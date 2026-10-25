from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from agent.asyncutil import maybe_await
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
async def stats_online(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Online users for every enabled core (live-stats shape).

    Always ``{"xray": [...], "wireguard": [...], ...}``. Optional ``core`` is
    ignored for response shape so panels never fan out per-core HTTP calls.
    """
    try:
        users = await registry.online_users_by_core()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    # Keep query param for older clients; do not change the global payload shape.
    _ = resolve_core_key(core)
    return {"success": True, "users": users}


@router.get("/stats/online/ips")
async def stats_online_ips(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Live client IPs for every enabled core: ``{"xray": {...}, "wireguard": {...}}``."""
    try:
        users = await registry.online_ips_by_core()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    _ = resolve_core_key(core)
    return {"success": True, "users": users}


@router.get("/stats/online/traffic")
async def stats_online_traffic(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Per-core when ``core`` is set; otherwise flat merge (panel traffic billing)."""
    try:
        users = await registry.online_traffic(resolve_core_key(core))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "users": users}


@router.get("/stats/client")
async def stats_client(
    key: str = Query(...),
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Cumulative counters for one client.

    Panel create/move used to download ``/stats/snapshot`` (every user) just to
    read one email. Cores without a targeted lookup return 404 so the panel can
    fall back to that snapshot.
    """
    label = str(key or "").strip()
    core_key = resolve_core_key(core)
    if label == "" or core_key is None:
        raise_agent_error("VALIDATION_ERROR", "core and key are required", 422)
    try:
        driver = registry.get(core_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    getter = getattr(driver, "client_traffic_counters", None)
    if not callable(getter):
        raise_agent_error("UNSUPPORTED", "per-client counters are not available for this core", 404)
    try:
        incoming, outgoing = await maybe_await(getter(label))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {
        "success": True,
        "incoming": int(incoming or 0),
        "outgoing": int(outgoing or 0),
    }


@router.get("/stats/snapshot")
async def stats_snapshot(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    try:
        snapshot = await registry.usage_snapshot(resolve_core_key(core))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **snapshot.model_dump()}


async def _live_payload(registry: CoreRegistry) -> dict[str, Any]:
    return {"success": True, **(await registry.live_stats())}


@router.get("/stats/live")
async def stats_live(registry: CoreRegistry = Depends(get_registry)):
    """Snapshot + online users + IPs + traffic for every enabled core, one HTTP call."""
    try:
        return await _live_payload(registry)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)


@router.get("/stats/clients/traffic")
async def stats_clients_traffic(registry: CoreRegistry = Depends(get_registry)):
    """Legacy alias of /stats/live (panel collectAllClientTraffic)."""
    try:
        return await _live_payload(registry)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)


@router.get("/stats/clients/traffic/pending")
async def stats_clients_traffic_pending(
    request: Request,
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Unacked traffic queue for all cores. Not gated on online/handshake.

    Contract with NetinjaBot ``UpdateSubscribeStats``:
      1. Worker keeps ``pending = current_cumulative - ack`` until POST ack.
      2. GET returns the queue. It re-samples only when the worker snapshot is stale.
      3. Panel bills those bytes, then POST ``/pending/ack`` with node_id and/or
         email so only growth after the GET snapshot remains queued.
    """
    registry: CoreRegistry = request.app.state.registry
    age = await traffic.last_sample_age_ms()
    interval_ms = int(float(getattr(request.app.state.settings, "traffic_sample_interval", 30.0) or 30.0) * 1000)
    fresh_ms = max(3000, interval_ms // 2)
    if age is None or age > fresh_ms:
        await traffic.sample_all(registry)
    payload = await traffic.pending_payload()

    return {
        "success": True,
        "sampled_at": payload.get("sampled_at"),
        "worker_lag_ms": payload.get("worker_lag_ms"),
        "users": payload.get("users") or {},
    }


@router.post("/stats/clients/traffic/pending/ack")
async def stats_clients_traffic_pending_ack(
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
    acked, not_found = await traffic.ack_clients(client_keys)

    return {
        "success": True,
        "acked": acked,
        "not_found": not_found,
    }
