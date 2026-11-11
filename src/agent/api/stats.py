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


def _read_body(payload: dict[str, Any], unavailable: list[str], *, key: str) -> dict[str, Any]:
    """Attach cores that did not answer. Never describe that as an empty collection."""
    if unavailable and not payload.get(key):
        raise_agent_error(
            "UPSTREAM_TIMEOUT",
            "cores unavailable: " + ", ".join(unavailable),
            503,
        )
    body = {"success": True, **payload}
    if unavailable:
        body["unavailable_cores"] = unavailable
    return body


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
        users, unavailable = await registry.online_users_report()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    # Keep query param for older clients; do not change the global payload shape.
    _ = resolve_core_key(core)
    return _read_body({"users": users}, unavailable, key="users")


@router.get("/stats/online/ips")
async def stats_online_ips(
    core: str | None = Query(None),
    registry: CoreRegistry = Depends(get_registry),
):
    """Live client IPs for every enabled core: ``{"xray": {...}, "wireguard": {...}}``."""
    try:
        users, unavailable = await registry.online_ips_report()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    _ = resolve_core_key(core)
    return _read_body({"users": users}, unavailable, key="users")


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
    payload, unavailable = await registry.live_stats_report()
    if unavailable and not payload.get("ips") and not payload.get("online_users") and not (
        (payload.get("snapshot") or {}).get("inbounds")
    ):
        raise_agent_error(
            "UPSTREAM_TIMEOUT",
            "cores unavailable: " + ", ".join(unavailable),
            503,
        )
    body = {"success": True, **payload}
    if unavailable:
        body["unavailable_cores"] = unavailable
    return body


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
    registry: CoreRegistry = Depends(get_registry),
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Unacked traffic queue for all cores. Not gated on online/handshake.

    Contract with NetinjaBot ``UpdateSubscribeStats``:
      1. ``agent work`` samples on an interval and appends one pending **chunk**
         per client when counters grow. Chunks are not held until panel ack.
      2. GET returns ``users[node_id]`` with summed ``downlink``/``uplink`` and
         ``chunks: [{id, incoming, outgoing, sampled_at}, ...]``.
      3. Panel bills the summed totals, then POST ``/pending/ack`` with
         ``chunk_ids`` (processed chunk rows) plus optional ``clients``/``billed``
         for baseline settlement. GET does not take a write lock.
    """
    payload = await traffic.pending_payload(persist_snapshot=False)

    settings = getattr(registry, "settings", None)
    interval_s = float(getattr(settings, "traffic_sample_interval", 5.0) or 5.0)
    max_sample_age_ms = max(1000, int(interval_s * 1000))
    sample_refresh_scheduled = await traffic.ensure_sample_fresh(
        registry,
        max_sample_age_ms=max_sample_age_ms,
    )

    return {
        "success": True,
        "sampled_at": payload.get("sampled_at"),
        "worker_lag_ms": payload.get("worker_lag_ms"),
        "users": payload.get("users") or {},
        "sample_refresh_scheduled": sample_refresh_scheduled,
    }


@router.get("/stats/clients/ack")
async def stats_clients_ack(
    node_id: str = Query(""),
    traffic: TrafficService = Depends(get_traffic),
):
    """Read the traffic_ack watermark for one panel node_id. Does not sample or write."""
    label = str(node_id or "").strip()
    if not label:
        raise_agent_error("INVALID_PAYLOAD", "node_id is required", 400)
    inspected = await traffic.store.inspect_traffic_ack(label)
    ack_rows = inspected["ack_rows"]
    return {
        "success": True,
        "node_id": label,
        "ack_found": bool(ack_rows),
        "ack_rows": ack_rows,
        "pending_rows": inspected["pending_rows"],
    }


@router.post("/stats/clients/traffic/pending/ack")
async def stats_clients_traffic_pending_ack(
    body: dict[str, Any],
    traffic: TrafficService = Depends(get_traffic),
):
    """
    Reset pending for clients the panel already persisted.

    Subtracts the GET snapshot from the live pending row. Bytes sampled onto
    the queue after that GET stay pending and are not cleared.

    Body: ``{"chunk_ids": ["<uuid>", ...], "clients": [...], "billed": {...}, "drop": [...]}``.
    ``chunk_ids`` delete the billed sample chunks (primary idempotent clear).
    ``clients``/``billed`` settle the ack watermark when needed; ``drop`` clears
    keys the panel will never bill.
    """
    raw = body.get("clients")
    if raw is None:
        raw = body.get("client_keys") or []

    if not isinstance(raw, list):
        raise_agent_error("INVALID_PAYLOAD", "clients must be a list of client ids", 400)

    drop_raw = body.get("drop") or []
    if not isinstance(drop_raw, list):
        raise_agent_error("INVALID_PAYLOAD", "drop must be a list of client ids", 400)

    client_keys = [str(item).strip() for item in raw if str(item or "").strip()]
    drop_keys = [str(item).strip() for item in drop_raw if str(item or "").strip()]
    chunk_raw = body.get("chunk_ids") or []
    chunk_ids = [
        str(item).strip()
        for item in (chunk_raw if isinstance(chunk_raw, list) else [])
        if str(item or "").strip()
    ]
    chunks_deleted = 0
    chunks_missing: list[str] = []
    if chunk_ids:
        chunks_deleted, chunks_missing = await traffic.ack_chunk_ids(chunk_ids)
    acked, not_found = await traffic.ack_clients(
        client_keys,
        _billed_amounts(body.get("billed")),
        drop_keys,
    )

    return {
        "success": True,
        "acked": acked,
        "not_found": not_found,
        "chunks_deleted": chunks_deleted,
        "chunks_missing": chunks_missing,
        # Lets the panel tell a settled miss from an older agent that reports
        # not_found while the billed bytes are still queued.
        "billed_ack": True,
    }


def _billed_amounts(raw: Any) -> dict[str, tuple[int, int]]:
    if not isinstance(raw, dict):
        return {}
    parsed: dict[str, tuple[int, int]] = {}
    for key, value in raw.items():
        label = str(key or "").strip()
        if not label or not isinstance(value, dict):
            continue
        try:
            incoming = max(0, int(value.get("incoming") or value.get("downlink") or 0))
            outgoing = max(0, int(value.get("outgoing") or value.get("uplink") or 0))
        except (TypeError, ValueError):
            continue
        if incoming or outgoing:
            parsed[label] = (incoming, outgoing)
    return parsed
