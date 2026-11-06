import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, Request

from agent.asyncutil import maybe_await
from agent.db import Store
from agent.errors import AgentError, raise_agent_error
from agent.logutil import get_logger
from agent.support.peer_egress import all_desired_rules_from_store, all_tunnel_interface_names, repair_peer_egress
from agent.support.host_interfaces import list_host_interfaces

log = get_logger("network")

router = APIRouter(prefix="/network", tags=["network"])

_probe_fallback_pending: set[str] = set()
_probe_fallback_running = False
_PROBE_JOB_LIMIT = 32
_probe_jobs: dict[str, dict[str, Any]] = {}
_probe_tasks: set[asyncio.Task[None]] = set()


@router.get("/interfaces")
async def network_interfaces():
    return {"success": True, "interfaces": await list_host_interfaces()}


@router.get("/ads-block")
async def ads_block_status():
    from agent.ads_block import ads_block_status as status_fn

    return {"success": True, **await status_fn()}


@router.post("/ads-block/ensure")
async def ads_block_ensure():
    from agent.ads_block import ads_block_ensure as ensure_fn

    try:
        result = await ensure_fn()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.post("/ads-block/disable")
async def ads_block_disable():
    from agent.ads_block import ads_block_disable as disable_fn

    try:
        result = await disable_fn()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


async def _run_probe_fallbacks(*, store: Store, settings: Any) -> None:
    """Coalesce concurrent probe failures into one fallback worker (avoid thrash)."""
    global _probe_fallback_running
    from agent.asyncutil import gather_independent
    from agent.support.mullvad import MullvadService

    service = MullvadService(store, config_dir=settings.wireguard_config_dir)
    try:
        if not await service.auto_fallback_enabled():
            log.debug("mullvad probe fallback skipped — auto_fallback disabled")
            _probe_fallback_pending.clear()
            _probe_fallback_running = False
            return
    except Exception:
        log.exception("mullvad auto_fallback flag read failed; continuing probe fallback")

    while True:
        batch = sorted(_probe_fallback_pending)
        _probe_fallback_pending.clear()
        if not batch:
            _probe_fallback_running = False
            return

        async def _one(iface: str) -> None:
            try:
                result = await maybe_await(service.fallback_iface(iface))
                if result and result.get("status") == "changed":
                    log.info("mullvad probe fallback iface=%s %s", iface, result.get("message"))
                elif result and result.get("status") == "failed":
                    log.warning("mullvad probe fallback iface=%s %s", iface, result.get("message"))
            except Exception:
                log.exception("mullvad probe fallback failed iface=%s", iface)

        await gather_independent(*(_one(iface) for iface in batch))


def _schedule_probe_fallbacks(ifaces: list[str], *, store: Store, settings: Any) -> None:
    global _probe_fallback_running

    cleaned = [str(name or "").strip() for name in ifaces if str(name or "").strip()]
    if not cleaned:
        return

    _probe_fallback_pending.update(cleaned)
    if _probe_fallback_running:
        return
    _probe_fallback_running = True

    import asyncio

    asyncio.create_task(_run_probe_fallbacks(store=store, settings=settings))


def _coerce_probe_fallback(value: Any, *, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _remember_probe_job(probe_id: str, record: dict[str, Any]) -> None:
    _probe_jobs[probe_id] = record
    while len(_probe_jobs) > _PROBE_JOB_LIMIT:
        oldest = next(iter(_probe_jobs))
        if oldest == probe_id:
            break
        _probe_jobs.pop(oldest, None)


def _probe_job(probe_id: str) -> dict[str, Any] | None:
    record = _probe_jobs.get(probe_id)
    return dict(record) if isinstance(record, dict) else None


async def _load_probe_outbounds(registry: Any) -> list[dict[str, Any]]:
    from agent.drivers.xray import XrayDriver

    try:
        driver = registry.get("xray")
    except Exception:
        return []
    if not isinstance(driver, XrayDriver):
        return []
    try:
        listed = await driver.list_outbounds()
    except Exception:
        return []
    if not isinstance(listed, list):
        return []
    return [row for row in listed if isinstance(row, dict)]


def _failed_probe_ifaces(nodes: list[Any], result: dict[str, Any]) -> list[str]:
    failed: list[str] = []
    by_id = {str(item.get("id")): item for item in nodes if isinstance(item, dict)}
    for row in result.get("nodes") or []:
        if not isinstance(row, dict) or row.get("ok"):
            continue
        raw = by_id.get(str(row.get("id")))
        iface = ""
        if isinstance(raw, dict):
            iface = str(raw.get("exit_interface") or "").strip()
        # Dead exits (incl. timeout / no handshake) should still trigger fallback.
        # Fixed relays remain pinned inside MullvadService.fallback_iface.
        if iface:
            failed.append(iface)
    return failed


async def _execute_probe_job(
    probe_id: str,
    nodes: list[Any],
    *,
    schedule_fallback: bool,
    registry: Any,
    store: Store,
    settings: Any,
) -> None:
    from agent.support.node_probe import probe_region_nodes as run_probe

    log.info("region probe started probe_id=%s", probe_id)
    try:
        outbounds = await _load_probe_outbounds(registry)
        result = await run_probe(nodes, outbounds)
        if schedule_fallback:
            failed = _failed_probe_ifaces(nodes, result)
            if failed:
                _schedule_probe_fallbacks(failed, store=store, settings=settings)
        _remember_probe_job(probe_id, {"success": True, "status": "done", "probe_id": probe_id, **result})
    except AgentError as exc:
        log.warning("region probe failed probe_id=%s code=%s %s", probe_id, exc.code, exc.message)
        _remember_probe_job(
            probe_id,
            {
                "success": False,
                "status": "error",
                "probe_id": probe_id,
                "error": {"code": exc.code, "message": exc.message},
            },
        )
    except Exception:
        log.exception("region probe failed probe_id=%s", probe_id)
        _remember_probe_job(
            probe_id,
            {
                "success": False,
                "status": "error",
                "probe_id": probe_id,
                "error": {"code": "INTERNAL_ERROR", "message": "region probe failed"},
            },
        )


def _schedule_probe_job(
    probe_id: str,
    nodes: list[Any],
    *,
    schedule_fallback: bool,
    registry: Any,
    store: Store,
    settings: Any,
) -> None:
    async def _kickoff() -> None:
        # Let the accept response flush before curl, ping, or route locks run.
        # This task is not the request task: a client disconnect must not cancel it.
        await asyncio.sleep(0)
        await _execute_probe_job(
            probe_id,
            nodes,
            schedule_fallback=schedule_fallback,
            registry=registry,
            store=store,
            settings=settings,
        )

    task = asyncio.create_task(_kickoff())
    _probe_tasks.add(task)
    task.add_done_callback(_probe_tasks.discard)


@router.post("/nodes/probe")
async def probe_region_nodes(body: dict[str, Any], request: Request):
    nodes = body.get("nodes") or []
    if not isinstance(nodes, list):
        raise_agent_error("VALIDATION_ERROR", "nodes must be an array", 422)
    if not any(isinstance(item, dict) and item.get("id") is not None for item in nodes):
        raise_agent_error("VALIDATION_ERROR", "nodes list is required", 422)

    # Admin panel traffic tests pass fallback=false so false timeouts do not thrash relays.
    # Region monitor / ops probes keep the default (true) so dead exits still recover.
    schedule_fallback = _coerce_probe_fallback(body.get("fallback"), default=True)
    probe_id = uuid.uuid4().hex
    _remember_probe_job(probe_id, {"success": True, "status": "running", "probe_id": probe_id})
    _schedule_probe_job(
        probe_id,
        nodes,
        schedule_fallback=schedule_fallback,
        registry=request.app.state.registry,
        store=request.app.state.store,
        settings=request.app.state.settings,
    )
    log.info("region probe accepted probe_id=%s", probe_id)
    return {"success": True, "status": "running", "probe_id": probe_id}


@router.get("/nodes/probe/{probe_id}")
async def probe_region_nodes_status(probe_id: str):
    record = _probe_job(probe_id)
    if record is None:
        raise_agent_error("NOT_FOUND", "probe not found", 404)
    return record


@router.post("/egress/repair")
async def egress_repair(request: Request):
    """
    Agent-owned firewall/routing repair for WireGuard/Amnezia peer egress.

    Rebuilds ip_forward, rp_filter, policy routing, NAT/MASQUERADE and FORWARD
    for exit + tunnel interfaces, then rewrites the PostUp/systemd apply script.
    """
    store: Store = request.app.state.store
    data_dir = getattr(request.app.state.settings, "data_dir", None)
    result = await repair_peer_egress(store, data_dir=data_dir)
    return {"success": bool(result.get("ok")), **result}


@router.get("/egress/status")
async def egress_status(request: Request):
    store: Store = request.app.state.store
    rules = await all_desired_rules_from_store(store)
    return {
        "success": True,
        "rules": rules,
        "tunnels": await all_tunnel_interface_names(store),
        "rule_count": len(rules),
    }
