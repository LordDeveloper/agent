from fastapi import APIRouter, Depends, Query, Request

from agent.auth import verify_auth
from agent.registry import CoreRegistry
from agent.routing import resolve_core_key

router = APIRouter(tags=["stats"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


@router.get("/stats/online")
def stats_online(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    users = registry.online_users(resolve_core_key(core))
    return {"success": True, "users": users}


@router.get("/stats/snapshot")
def stats_snapshot(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    snapshot = registry.usage_snapshot(resolve_core_key(core))
    return {"success": True, **snapshot.model_dump()}
