import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request

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
from agent.registry import CoreRegistry


def create_app(env_file: str | None = None) -> FastAPI:
    settings = load_settings(env_file or os.environ.get("ENV_FILE"))
    store = Store(settings.resolve_db_path())
    audit = AuditLog(store)
    registry = CoreRegistry(settings, audit, store)
    enabled = set(settings.cores())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        store.close()

    app = FastAPI(title="Agent", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.audit = audit
    app.state.registry = registry

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

    return app


def run() -> None:
    from agent.cli import run as cli_run

    cli_run()
