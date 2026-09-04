from fastapi import APIRouter, Depends, Query, Request

from agent.auth import verify_auth
from agent.errors import AgentError, raise_agent_error
from agent.registry import CoreRegistry
from agent.routing import resolve_core_key
from agent.traffic.service import TrafficService

router = APIRouter(tags=["stats"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


def _parse_ack(value: bool | None, passed: bool | None) -> bool:
    if passed is not None:
        return passed
    return bool(value)


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


@router.get("/stats/clients/traffic/delta")
def stats_clients_traffic_delta(
    request: Request,
    ack: bool = Query(False),
    passed: bool | None = Query(None, description="Alias for ack — panel processed pending deltas"),
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Pending byte deltas since the last ack, sampled by the local traffic worker.

    Online status is not used. Only clients with new consumption since the last
    successful panel ack appear in ``users``. When ``ack=true`` (or ``passed=true``),
    returned clients are removed from the pending queue and their baselines advance.
    """
    registry: CoreRegistry = request.app.state.registry

    if _parse_ack(ack, passed):
        traffic.sample_all(registry)

    payload = traffic.pending_payload()
    users = dict(payload.get("users") or {})
    acked = 0

    if _parse_ack(ack, passed) and users:
        acked = traffic.ack_pending()

    return {
        "success": True,
        "ack": _parse_ack(ack, passed),
        "acked_clients": acked,
        "sampled_at": payload.get("sampled_at"),
        "worker_lag_ms": payload.get("worker_lag_ms"),
        "users": users,
    }
