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
from agent.errorlog import CoreErrorCaptureMiddleware, CoreErrorLog
from agent.logutil import get_logger, resolve_log_path, setup_logging
from agent.registry import CoreRegistry
from agent.api.lifecycle import health_payload
from agent.routing import ROUTE_SLUGS
from agent.errors import AgentError

log = get_logger("http")


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        client = request.client.host if request.client else "-"
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1000
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
        yield
        app_log.info("agent stopping")
        store.close()

    app = FastAPI(title="Agent", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.audit = audit
    app.state.errors = errors
    app.state.registry = registry
    app.add_middleware(CoreErrorCaptureMiddleware)
    app.add_middleware(RequestLogMiddleware)

    auth = [Depends(verify_auth)]
    app.include_router(cores_router, prefix="/api/v1", dependencies=auth)
    app.include_router(stats_router, prefix="/api/v1", dependencies=auth)

    # Each core owns its own API surface; only mount what is enabled.
    if "xray" in enabled:
        app.include_router(xray_router, prefix="/api/v1", dependencies=auth)
    if "wireguard" in enabled:
        app.include_router(wireguard_router, prefix="/api/v1", dependencies=auth)
    if "amnezia" in enabled:
        app.include_router(amnezia_router, prefix="/api/v1", dependencies=auth)

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
        if core_key in enabled:
            _register_public_core_health(core_key, slug)

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
