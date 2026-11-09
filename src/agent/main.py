import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse

from agent import __version__
from agent.audit import AuditLog
from agent.auth import verify_auth
from agent.config import load_settings
from agent.db import Store
from agent.api.cores import router as cores_router
from agent.api.documents import router as documents_router
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
from agent.errorlog import CoreErrorLog
from agent.http import AgentHttpMiddleware
from agent.logutil import get_logger, resolve_log_path, setup_logging
from agent.registry import CoreRegistry
from agent.api.lifecycle import health_payload
from agent.routing import ROUTE_SLUGS
from agent.errors import AgentError
from agent.support.quota import configure_quota_settings
from agent.runtime import RuntimeTrace
from agent.traffic.service import TrafficService


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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await store.open()
        from agent.support.quota_identity_migration import migrate_client_quota_identity

        migrated = await migrate_client_quota_identity(store)
        if migrated:
            app_log.info("client quota identity migrated docs=%s", migrated)
        from agent.support.node_id_pk_migration import migrate_node_id_primary_key

        moved = await migrate_node_id_primary_key(store)
        if moved:
            app_log.info("client node_id primary key migrated docs=%s", moved)
        app_log.info(
            "agent started version=%s listen=%s cores=%s log=%s local_volume_quota=%s",
            __version__,
            settings.listen,
            ",".join(settings.cores()) or "-",
            resolve_log_path(settings),
            settings.enforce_local_volume_quota,
        )
        if not settings.enforce_local_volume_quota:
            app_log.info(
                "volume quota cutoff is owned by the panel (UpdateSubscribeStats); "
                "agent will not disable clients for quota",
            )
        # Request handlers enqueue routing and bandwidth. The worker process applies them.
        from agent.support.bandwidth import configure_runtime
        from agent.support.egress_tasks import configure_egress

        configure_runtime(registry, settings.data_dir)
        configure_egress(registry, settings.data_dir)
        app_log.info("http process ready; background loops run in `agent work`")

        yield

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
    app.add_middleware(AgentHttpMiddleware)

    auth = [Depends(verify_auth)]
    app.include_router(cores_router, prefix="/api/v1", dependencies=auth)
    app.include_router(documents_router, prefix="/api/v1", dependencies=auth)
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
