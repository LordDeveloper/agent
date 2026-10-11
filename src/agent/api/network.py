from typing import Any
import threading

from fastapi import APIRouter, Request

from agent.db import Store
from agent.errors import AgentError, raise_agent_error
from agent.logutil import get_logger
from agent.support.peer_egress import all_desired_rules_from_store, all_tunnel_interface_names, repair_peer_egress
from agent.support.host_interfaces import list_host_interfaces

log = get_logger("network")

router = APIRouter(prefix="/network", tags=["network"])

_probe_fallback_lock = threading.Lock()
_probe_fallback_pending: set[str] = set()
_probe_fallback_running = False


@router.get("/interfaces")
def network_interfaces():
    return {"success": True, "interfaces": list_host_interfaces()}


@router.get("/ads-block")
def ads_block_status():
    from agent.ads_block import ads_block_status as status_fn

    return {"success": True, **status_fn()}


@router.post("/ads-block/ensure")
def ads_block_ensure():
    from agent.ads_block import ads_block_ensure as ensure_fn

    try:
        result = ensure_fn()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.post("/ads-block/disable")
def ads_block_disable():
    from agent.ads_block import ads_block_disable as disable_fn

    try:
        result = disable_fn()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


def _schedule_probe_fallbacks(ifaces: list[str], *, store: Store, settings: Any) -> None:
    """Coalesce concurrent probe failures into one fallback worker (avoid thrash)."""
    global _probe_fallback_running

    cleaned = [str(name or "").strip() for name in ifaces if str(name or "").strip()]
    if not cleaned:
        return

    with _probe_fallback_lock:
        _probe_fallback_pending.update(cleaned)
        if _probe_fallback_running:
            return
        _probe_fallback_running = True

    def _run_fallback() -> None:
        global _probe_fallback_running
        from agent.support.mullvad import MullvadService

        service = MullvadService(store, config_dir=settings.wireguard_config_dir)
        try:
            if not service.auto_fallback_enabled():
                log.debug("mullvad probe fallback skipped — auto_fallback disabled")
                with _probe_fallback_lock:
                    _probe_fallback_pending.clear()
                return
        except Exception:
            log.exception("mullvad auto_fallback flag read failed; continuing probe fallback")

        while True:
            with _probe_fallback_lock:
                batch = sorted(_probe_fallback_pending)
                _probe_fallback_pending.clear()
                if not batch:
                    _probe_fallback_running = False
                    return

            for iface in batch:
                try:
                    result = service.fallback_iface(iface)
                    if result and result.get("status") == "changed":
                        log.info("mullvad probe fallback iface=%s %s", iface, result.get("message"))
                    elif result and result.get("status") == "failed":
                        log.warning("mullvad probe fallback iface=%s %s", iface, result.get("message"))
                except Exception:
                    log.exception("mullvad probe fallback failed iface=%s", iface)

    threading.Thread(target=_run_fallback, daemon=True, name="mullvad-probe-fallback").start()


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


@router.post("/nodes/probe")
def probe_region_nodes(body: dict[str, Any], request: Request):
    from agent.drivers.xray import XrayDriver
    from agent.support.node_probe import probe_region_nodes as run_probe

    nodes = body.get("nodes") or []
    if not isinstance(nodes, list):
        raise_agent_error("VALIDATION_ERROR", "nodes must be an array", 422)

    # Admin panel traffic tests pass fallback=false so false timeouts do not thrash relays.
    # Region monitor / ops probes keep the default (true) so dead exits still recover.
    schedule_fallback = _coerce_probe_fallback(body.get("fallback"), default=True)

    outbounds: list[dict[str, Any]] = []
    registry = request.app.state.registry
    try:
        driver = registry.get("xray")
        if isinstance(driver, XrayDriver):
            listed = driver.list_outbounds()
            if isinstance(listed, list):
                outbounds = [row for row in listed if isinstance(row, dict)]
    except Exception:
        outbounds = []

    try:
        result = run_probe(nodes, outbounds)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)

    if schedule_fallback:
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

        if failed:
            _schedule_probe_fallbacks(
                failed,
                store=request.app.state.store,
                settings=request.app.state.settings,
            )

    return {"success": True, **result}


@router.post("/egress/repair")
def egress_repair(request: Request):
    """
    Agent-owned firewall/routing repair for WireGuard/Amnezia peer egress.

    Rebuilds ip_forward, rp_filter, policy routing, NAT/MASQUERADE and FORWARD
    for exit + tunnel interfaces, then rewrites the PostUp/systemd apply script.
    """
    store: Store = request.app.state.store
    data_dir = getattr(request.app.state.settings, "data_dir", None)
    result = repair_peer_egress(store, data_dir=data_dir)
    return {"success": bool(result.get("ok")), **result}


@router.get("/egress/status")
def egress_status(request: Request):
    store: Store = request.app.state.store
    return {
        "success": True,
        "rules": all_desired_rules_from_store(store),
        "tunnels": all_tunnel_interface_names(store),
        "rule_count": len(all_desired_rules_from_store(store)),
    }
