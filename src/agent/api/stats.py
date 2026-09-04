from fastapi import APIRouter, Depends, Query, Request

from agent.auth import verify_auth
from agent.errors import AgentError, raise_agent_error
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
    try:
        users = registry.online_users(resolve_core_key(core))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "users": users}


@router.get("/stats/online/traffic")
def stats_online_traffic(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    try:
        users = registry.online_traffic(resolve_core_key(core))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "users": users}


@router.get("/stats/snapshot")
def stats_snapshot(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    try:
        snapshot = registry.usage_snapshot(resolve_core_key(core))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **snapshot.model_dump()}


@router.get("/stats/clients/traffic")
def stats_clients_traffic(
    registry: CoreRegistry = Depends(get_registry),
):
    """
    Single-call traffic snapshot for billing sync: all enabled cores (Xray + WireGuard + Amnezia)
    with online byte counters and full cumulative client snapshot.
    """
    try:
        online = registry.online_traffic(None)
        online_users = registry.online_users(None)
        snapshot = registry.usage_snapshot(None)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {
        "success": True,
        "online": {"users": online},
        "online_users": online_users,
        "snapshot": snapshot.model_dump(),
    }
