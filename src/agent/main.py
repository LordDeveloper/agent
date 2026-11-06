import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agent import __version__
from agent.asyncutil import read_deadline, short_read_path
from agent.audit import AuditLog
from agent.auth import verify_auth
from agent.config import load_settings
from agent.db import Store
from agent.api.cores import router as cores_router
from agent.api.stats import router as stats_router
from agent.api.xray import router as xray_router
from agent.api.wireguard import router as wireguard_router
from agent.api.amnezia import router as amnezia_router
from agent.api.l2tp import router as l2tp_router
from agent.api.openvpn import router as openvpn_router
from agent.api.tls import router as tls_router
from agent.api.network import router as network_router
from agent.api.mullvad import router as mullvad_router
from agent.api.transfer import router as transfer_router
from agent.api.status import router as status_router
from agent.mullvad_worker import mullvad_worker_loop
from agent.errorlog import CoreErrorCaptureMiddleware, CoreErrorLog
from agent.logutil import get_logger, resolve_log_path, setup_logging
from agent.registry import CoreRegistry
from agent.api.lifecycle import health_payload
from agent.routing import ROUTE_SLUGS
from agent.core_supervisor import bootstrap_enabled_cores
from agent.errors import AgentError
from agent.quota_enforcer import quota_enforcer_loop
from agent.support.quota import configure_quota_settings
from agent.runtime import RuntimeTrace
from agent.traffic.service import TrafficService
from agent.traffic_worker import traffic_worker_loop

log = get_logger("http")


def _request_action(request: Request) -> str:
    endpoint = request.scope.get("endpoint")
    name = getattr(endpoint, "__name__", "") if callable(endpoint) else ""
    if name:
        return name
    route = request.scope.get("route")
    route_name = getattr(route, "name", "") if route is not None else ""
    if route_name:
        return str(route_name)
    return f"{request.method}.{request.url.path}"


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        RuntimeTrace.start()
        request_id = (request.headers.get("x-request-id") or "").strip() or uuid.uuid4().hex
        node_id = (request.headers.get("x-node-id") or request.headers.get("x-node-host") or "").strip()
        protocol_switch_trace = (request.headers.get("x-protocol-switch-trace") or "").strip()
        RuntimeTrace.set_request_id(request_id)
        if node_id:
            RuntimeTrace.set_node_id(node_id)
        started = time.perf_counter()
        client = request.client.host if request.client else "-"
        # Access log is written only after the handler returns. A client CRUD
        # stuck in Xray otherwise leaves the panel timeout with an empty log.
        watch = asyncio.create_task(self._warn_if_slow(request, client))
        deadline_token = None
        if short_read_path(request.method, request.url.path):
            settings = getattr(request.app.state, "settings", None)
            budget = float(getattr(settings, "read_budget_seconds", 12.0) or 12.0)
            deadline_token = read_deadline.set(max(1.0, budget))
        handler = asyncio.ensure_future(self._call_until_disconnect(request, call_next))
        _settings = getattr(request.app.state, "settings", None)
        slow_log_threshold_ms = (
            float(getattr(_settings, "slow_request_log_ms", 0) or 0) if _settings is not None else 0.0
        )
        try:
            with RuntimeTrace.span("handler"):
                response = await handler
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            if slow_log_threshold_ms > 0 and elapsed_ms >= slow_log_threshold_ms:
                log.warning(
                    "slow_request method=%s path=%s client=%s request_id=%s duration_ms=%.1f runtime=%s error=%s",
                    request.method,
                    request.url.path,
                    client,
                    RuntimeTrace.request_id() or "-",
                    elapsed_ms,
                    RuntimeTrace.header() or "-",
                    type(exc).__name__,
                )
            if isinstance(exc, HTTPException):
                raise
            log.exception(
                "request failed method=%s path=%s client=%s request_id=%s duration_ms=%.1f runtime=%s",
                request.method,
                request.url.path,
                client,
                RuntimeTrace.request_id() or "-",
                elapsed_ms,
                RuntimeTrace.header() or "-",
            )
            raise
        else:
            RuntimeTrace.set_action(_request_action(request))
            RuntimeTrace.apply(response)
            response.headers[RuntimeTrace.request_header] = request_id
            elapsed_ms = (time.perf_counter() - started) * 1000
            runtime_h = response.headers.get(RuntimeTrace.header_name, "-")
            level = log.warning if response.status_code >= 400 else log.info
            log_extra = {"protocol_switch_trace": protocol_switch_trace} if protocol_switch_trace else {}
            msg = "method=%s path=%s status=%s client=%s duration_ms=%.1f runtime=%s"
            args = (
                request.method,
                request.url.path,
                response.status_code,
                client,
                elapsed_ms,
                runtime_h,
            )
            if log_extra:
                level(msg, *args, extra=log_extra)
            else:
                level(msg, *args)
            if slow_log_threshold_ms > 0 and elapsed_ms >= slow_log_threshold_ms:
                dmsg = (
                    "slow_request_detail method=%s path=%s status=%s client=%s "
                    "request_id=%s duration_ms=%.1f runtime=%s"
                )
                dargs = (
                    request.method,
                    request.url.path,
                    response.status_code,
                    client,
                    RuntimeTrace.request_id() or "-",
                    elapsed_ms,
                    runtime_h,
                )
                if log_extra:
                    log.warning(dmsg, *dargs, extra=log_extra)
                else:
                    log.warning(dmsg, *dargs)
            return response
        finally:
            if not handler.done():
                handler.cancel()
            watch.cancel()
            if deadline_token is not None:
                read_deadline.reset(deadline_token)
            RuntimeTrace.reset()

    @staticmethod
    async def _call_until_disconnect(request: Request, call_next):
        """Cancel the handler when the panel closes the socket.

        The handler task is what awaits the core. Cancelling it aborts httpx
        and child processes instead of leaving them until the core's own budget.
        ``is_disconnected`` is only polled for GET/HEAD so a POST body is not
        pulled off the receive stream before the endpoint reads it.
        """
        handler = asyncio.ensure_future(call_next(request))
        if request.method not in {"GET", "HEAD"}:
            return await handler
        try:
            while not handler.done():
                probe = asyncio.ensure_future(request.is_disconnected())
                done, _pending = await asyncio.wait(
                    {handler, probe},
                    timeout=0.5,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if handler in done:
                    if not probe.done():
                        probe.cancel()
                    break
                disconnected = probe.done() and not probe.cancelled() and bool(probe.result())
                if not probe.done():
                    probe.cancel()
                if disconnected:
                    handler.cancel()
                    break
            return await handler
        except asyncio.CancelledError:
            if not handler.done():
                handler.cancel()
            raise

    @staticmethod
    async def _warn_if_slow(request: Request, client: str) -> None:
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            return
        log.warning(
            "request still running method=%s path=%s client=%s request_id=%s runtime=%s",
            request.method,
            request.url.path,
            client,
            RuntimeTrace.request_id() or "-",
            RuntimeTrace.header() or "-",
        )


def create_app(env_file: str | None = None) -> FastAPI:
    settings = load_settings(env_file or os.environ.get("ENV_FILE"))
    configure_quota_settings(settings)
    setup_logging(settings)
    app_log = get_logger("app")

    store = Store(settings.resolve_db_path(), slow_query_log_ms=float(settings.slow_query_log_ms or 0.0))
    audit = AuditLog(store)
    errors = CoreErrorLog(resolve_log_path(settings))
    registry = CoreRegistry(settings, audit, store)
    traffic = TrafficService(store)
    enabled = set(settings.cores())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await store.open()
        from agent.support.quota_identity_migration import migrate_client_quota_identity

        migrated = await migrate_client_quota_identity(store)
        if migrated:
            app_log.info("client quota identity migrated docs=%s", migrated)
        app_log.info(
            "agent started version=%s listen=%s cores=%s log=%s local_volume_quota=%s",
            __version__,
            settings.listen,
            ",".join(settings.cores()) or "-",
            resolve_log_path(settings),
            settings.enforce_local_volume_quota,
        )
        if not settings.enforce_local_volume_quota:
            app_log.warning(
                "local volume quota enforcement disabled; panel sync must disable on is_exceeded",
            )
        await bootstrap_enabled_cores(settings, registry, app_log)
        from agent.support.bandwidth import bandwidth_reconcile_loop, configure_runtime
        from agent.support.egress_tasks import configure_egress, egress_reconcile_loop

        configure_runtime(registry, settings.data_dir)
        configure_egress(registry, settings.data_dir)
        stop_bandwidth = asyncio.Event()
        bandwidth_task = asyncio.create_task(
            bandwidth_reconcile_loop(registry, settings, stop_bandwidth),
        )
        stop_egress = asyncio.Event()
        egress_task = asyncio.create_task(
            egress_reconcile_loop(registry, settings, stop_egress),
        )
        try:
            from agent.support.xray_exit_bind import reapply_saved_binds

            rebound = await reapply_saved_binds()
            if rebound.get("applied") or rebound.get("failed"):
                app_log.info(
                    "xray exit binds applied=%s failed=%s",
                    rebound.get("applied"),
                    rebound.get("failed"),
                )
        except Exception:
            app_log.exception("xray exit bind reapply failed")

        stop_quota = asyncio.Event()
        quota_task = None
        if float(settings.quota_enforce_interval) > 0:
            quota_task = asyncio.create_task(
                quota_enforcer_loop(registry, settings, stop_quota),
            )

        stop_traffic = asyncio.Event()
        traffic_task = None
        if float(settings.traffic_sample_interval) > 0:
            await traffic.sample_all(registry)
            traffic_task = asyncio.create_task(
                traffic_worker_loop(registry, traffic, settings, stop_traffic),
            )

        stop_mullvad = asyncio.Event()
        mullvad_task = None
        if float(getattr(settings, "mullvad_fallback_interval", 60.0) or 0) > 0:
            mullvad_task = asyncio.create_task(
                mullvad_worker_loop(store, settings, stop_mullvad),
            )

        yield

        stop_bandwidth.set()
        await bandwidth_task
        stop_egress.set()
        await egress_task
        stop_mullvad.set()
        if mullvad_task is not None:
            await mullvad_task
        stop_traffic.set()
        if traffic_task is not None:
            await traffic_task
        stop_quota.set()
        if quota_task is not None:
            await quota_task
        from agent.support.proxy_protocol_forwarder import stop_forwarders

        stop_forwarders(settings)
        app_log.info("agent stopping")
        await store.close()

    app = FastAPI(title="Agent", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.audit = audit
    app.state.errors = errors
    app.state.registry = registry
    app.state.traffic = traffic
    app.add_middleware(CoreErrorCaptureMiddleware)
    app.add_middleware(RequestLogMiddleware)

    auth = [Depends(verify_auth)]
    app.include_router(cores_router, prefix="/api/v1", dependencies=auth)
    app.include_router(stats_router, prefix="/api/v1", dependencies=auth)
    app.include_router(status_router, prefix="/api/v1", dependencies=auth)

    # Core APIs are always mounted; ENABLED_CORES only marks preferred cores in health.
    app.include_router(xray_router, prefix="/api/v1", dependencies=auth)
    app.include_router(wireguard_router, prefix="/api/v1", dependencies=auth)
    app.include_router(amnezia_router, prefix="/api/v1", dependencies=auth)
    app.include_router(l2tp_router, prefix="/api/v1", dependencies=auth)
    app.include_router(openvpn_router, prefix="/api/v1", dependencies=auth)
    app.include_router(tls_router, prefix="/api/v1", dependencies=auth)
    app.include_router(network_router, prefix="/api/v1", dependencies=auth)
    app.include_router(mullvad_router, prefix="/api/v1", dependencies=auth)
    app.include_router(transfer_router, prefix="/api/v1", dependencies=auth)

    @app.get("/health")
    async def root_health(request: Request):
        reg: CoreRegistry = request.app.state.registry
        return {
            "success": True,
            "service": "agent",
            "version": __version__,
            "db": str(settings.resolve_db_path()),
            "cores": [c.model_dump() for c in await reg.list_cores()],
        }

    def _register_public_core_health(core_key: str, slug: str) -> None:
        @app.get(f"/cores/{slug}/health", name=f"{slug}-public-health")
        async def public_core_health(request: Request):
            try:
                driver = request.app.state.registry.get(core_key)
            except AgentError:
                return JSONResponse(
                    status_code=404,
                    content={
                        "success": False,
                        "error": {"code": "CONFIG_NOT_FOUND", "message": f"Core [{core_key}] is not enabled"},
                    },
                )
            return await health_payload(driver)

    for core_key, slug in ROUTE_SLUGS.items():
        _register_public_core_health(core_key, slug)

    @app.exception_handler(AgentError)
    async def agent_error_handler(request: Request, exc: AgentError):
        from agent.errors import ERROR_MAP, error_body

        status = int(exc.status or ERROR_MAP.get(exc.code, 400) or 400)
        response = JSONResponse(
            status_code=status,
            content=error_body(exc.code, exc.message),
        )
        RuntimeTrace.set_action(_request_action(request))
        RuntimeTrace.apply(response)
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        if isinstance(exc, HTTPException):
            return await http_exception_handler(request, exc)

        get_logger("app").exception(
            "unhandled error method=%s path=%s: %s",
            request.method,
            request.url.path,
            exc,
        )
        message = f"{type(exc).__name__}: {exc}".strip()[:400] or "Internal Server Error"
        response = JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": message},
            },
        )
        RuntimeTrace.set_action(_request_action(request))
        RuntimeTrace.apply(response)
        return response

    return app


def run() -> None:
    from agent.cli import run as cli_run

    cli_run()
