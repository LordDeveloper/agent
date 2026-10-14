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
    """Online users for every enabled core (live-stats shape).

    Always ``{"xray": [...], "wireguard": [...], ...}``. Optional ``core`` is
    ignored for response shape so panels never fan out per-core HTTP calls.
    """
    try:
        users = registry.online_users_by_core()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    # Keep query param for older clients; do not change the global payload shape.
    _ = resolve_core_key(core)
    return {"success": True, "users": users}


@router.get("/stats/online/ips")
def stats_online_ips(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Live client IPs for every enabled core: ``{"xray": {...}, "wireguard": {...}}``."""
    try:
        users = registry.online_ips_by_core()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    _ = resolve_core_key(core)
    return {"success": True, "users": users}


@router.get("/stats/online/traffic")
def stats_online_traffic(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Per-core when ``core`` is set; otherwise flat merge (panel traffic billing)."""
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


def _live_payload(registry: CoreRegistry) -> dict[str, Any]:
    return {"success": True, **registry.live_stats()}


@router.get("/stats/live")
def stats_live(registry: CoreRegistry = Depends(get_registry)):
    """Snapshot + online users + IPs + traffic for every enabled core, one HTTP call."""
    try:
        return _live_payload(registry)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)


@router.get("/stats/clients/traffic")
def stats_clients_traffic(registry: CoreRegistry = Depends(get_registry)):
    """Legacy alias of /stats/live (panel collectAllClientTraffic)."""
    try:
        return _live_payload(registry)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)


@router.get("/stats/clients/traffic/pending")
def stats_clients_traffic_pending(
    request: Request,
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Unacked traffic queue for all cores. Not gated on online/handshake.

    Contract with NetinjaBot ``UpdateSubscribeStats``:
      1. Worker keeps ``pending = current_cumulative - ack`` until POST ack.
      2. GET samples, returns the queue, and snapshots watermarks.
      3. Panel bills those bytes, then POST ``/pending/ack`` with node_id and/or
         email so only growth after the GET snapshot remains queued.
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
    Reset pending for clients the panel already persisted.

    Advances traffic_ack to the GET snapshot (not a later worker sample) so
    bytes that arrived between GET and ACK stay in the next queue cycle.

    Body: ``{"clients": ["node-id-or-email", ...]}``.
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
