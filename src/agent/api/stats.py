from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from agent.errors import AgentError, raise_agent_error
from agent.registry import CoreRegistry
from agent.routing import resolve_core_key
from agent.traffic.service import TrafficService

router = APIRouter(tags=["stats"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


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


@router.get("/stats/clients/traffic/pending")
def stats_clients_traffic_pending(
    request: Request,
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Pending byte deltas since the last panel ack.

    Keys in ``users`` are canonical client ids (panel ``node_id``). The traffic
    worker keeps updating pending rows until each client is acked via POST.
    """
    registry: CoreRegistry = request.app.state.registry
    traffic.sample_all(registry)
    payload = traffic.pending_payload()

    return {
        "success": True,
        "sampled_at": payload.get("sampled_at"),
        "worker_lag_ms": payload.get("worker_lag_ms"),
        "users": payload.get("users") or {},
    }


@router.post("/stats/clients/traffic/pending/ack")
def stats_clients_traffic_pending_ack(
    body: dict[str, Any],
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Ack clients whose pending volume was applied on the panel.

    Body: ``{"clients": ["node-id-1", "node-id-2"]}`` — canonical ids only.
    """
    raw = body.get("clients")
    if raw is None:
        raw = body.get("client_keys") or body.get("emails") or []

    if not isinstance(raw, list):
        raise_agent_error("INVALID_PAYLOAD", "clients must be a list of client ids", 400)

    client_keys = [str(item).strip() for item in raw if str(item or "").strip()]
    acked, not_found = traffic.ack_clients(client_keys)

    return {
        "success": True,
        "acked": acked,
        "not_found": not_found,
    }
