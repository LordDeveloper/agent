import asyncio
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agent import __version__
from agent.audit import AuditLog
from agent.auth import verify_auth
from agent.config import load_settings
from agent.db import Store
from agent.api.cores import router as cores_router
from agent.api.stats import router as stats_router
from agent.api.xray import router as xray_router
from agent.api.wireguard import router as wireguard_router
from agent.api.amnezia import router as amnezia_router
from agent.api.tls import router as tls_router
from agent.api.network import router as network_router
from agent.errorlog import CoreErrorCaptureMiddleware, CoreErrorLog
from agent.logutil import get_logger, resolve_log_path, setup_logging
from agent.registry import CoreRegistry
from agent.api.lifecycle import health_payload
from agent.routing import ROUTE_SLUGS
from agent.core_supervisor import bootstrap_enabled_cores
from agent.errors import AgentError
from agent.quota_enforcer import quota_enforcer_loop
from agent.traffic.service import TrafficService
from agent.traffic_worker import traffic_worker_loop

log = get_logger("http")


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        client = request.client.host if request.client else "-"
        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            if isinstance(exc, HTTPException):
                raise
            log.exception(
                "request failed method=%s path=%s client=%s duration_ms=%.1f",
                request.method,
                request.url.path,
                client,
                elapsed_ms,
            )
            raise

        elapsed_ms = (time.perf_counter() - started) * 1000
        level = log.warning if response.status_code >= 400 else log.info
        level(
            "method=%s path=%s status=%s client=%s duration_ms=%.1f",
            request.method,
            request.url.path,
            response.status_code,
            client,
            elapsed_ms,
        )
        return response


def create_app(env_file: str | None = None) -> FastAPI:
    settings = load_settings(env_file or os.environ.get("ENV_FILE"))
    setup_logging(settings)
    app_log = get_logger("app")

    store = Store(settings.resolve_db_path())
    audit = AuditLog(store)
    errors = CoreErrorLog(resolve_log_path(settings))
    registry = CoreRegistry(settings, audit, store)
    traffic = TrafficService(store)
    enabled = set(settings.cores())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app_log.info(
            "agent started version=%s listen=%s cores=%s log=%s",
            __version__,
            settings.listen,
            ",".join(settings.cores()) or "-",
            resolve_log_path(settings),
        )
        bootstrap_enabled_cores(settings, registry, app_log)

        stop_quota = asyncio.Event()
        quota_task = None
        if float(settings.quota_enforce_interval) > 0:
            quota_task = asyncio.create_task(
                quota_enforcer_loop(registry, settings, stop_quota),
            )

        stop_traffic = asyncio.Event()
        traffic_task = None
        if float(settings.traffic_sample_interval) > 0:
            traffic.sample_all(registry)
            traffic_task = asyncio.create_task(
                traffic_worker_loop(registry, traffic, settings, stop_traffic),
            )

        yield

        stop_traffic.set()
        if traffic_task is not None:
            await traffic_task
        stop_quota.set()
        if quota_task is not None:
            await quota_task
        app_log.info("agent stopping")
        store.close()

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

    # Core APIs are always mounted; ENABLED_CORES only marks preferred cores in health.
    app.include_router(xray_router, prefix="/api/v1", dependencies=auth)
    app.include_router(wireguard_router, prefix="/api/v1", dependencies=auth)
    app.include_router(amnezia_router, prefix="/api/v1", dependencies=auth)
    app.include_router(tls_router, prefix="/api/v1", dependencies=auth)
    app.include_router(network_router, prefix="/api/v1", dependencies=auth)

    @app.get("/health")
    def root_health(request: Request):
        reg: CoreRegistry = request.app.state.registry
        return {
            "success": True,
            "service": "agent",
            "version": __version__,
            "db": str(settings.resolve_db_path()),
            "cores": [c.model_dump() for c in reg.list_cores()],
        }

    def _register_public_core_health(core_key: str, slug: str) -> None:
        @app.get(f"/cores/{slug}/health", name=f"{slug}-public-health")
        def public_core_health(request: Request):
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
            return health_payload(driver)

    for core_key, slug in ROUTE_SLUGS.items():
        _register_public_core_health(core_key, slug)

    @app.exception_handler(AgentError)
    async def agent_error_handler(request: Request, exc: AgentError):
        from agent.errors import ERROR_MAP, error_body

        status = int(exc.status or ERROR_MAP.get(exc.code, 400) or 400)
        return JSONResponse(
            status_code=status,
            content=error_body(exc.code, exc.message),
        )

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
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": message},
            },
        )

    return app


def run() -> None:
    from agent.cli import run as cli_run

    cli_run()
