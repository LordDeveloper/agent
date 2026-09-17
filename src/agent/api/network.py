from typing import Any

from fastapi import APIRouter, Request

from agent.db import Store
from agent.errors import AgentError, raise_agent_error
from agent.logutil import get_logger
from agent.support.peer_egress import all_desired_rules_from_store, all_tunnel_interface_names, repair_peer_egress
from agent.support.host_interfaces import list_host_interfaces

log = get_logger("network")

router = APIRouter(prefix="/network", tags=["network"])


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


@router.post("/nodes/probe")
def probe_region_nodes(body: dict[str, Any], request: Request):
    from agent.drivers.xray import XrayDriver
    from agent.support.node_probe import probe_region_nodes as run_probe

    nodes = body.get("nodes") or []
    if not isinstance(nodes, list):
        raise_agent_error("VALIDATION_ERROR", "nodes must be an array", 422)

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

    failed: list[str] = []
    by_id = {str(item.get("id")): item for item in nodes if isinstance(item, dict)}
    for row in result.get("nodes") or []:
        if not isinstance(row, dict) or row.get("ok"):
            continue
        raw = by_id.get(str(row.get("id")))
        iface = ""
        if isinstance(raw, dict):
            iface = str(raw.get("exit_interface") or "").strip()
        if iface:
            failed.append(iface)

    if failed:
        import threading

        store = request.app.state.store
        settings = request.app.state.settings

        def _run_fallback() -> None:
            from agent.support.mullvad import MullvadService

            service = MullvadService(store, config_dir=settings.wireguard_config_dir)
            seen: set[str] = set()
            for iface in failed:
                if iface in seen:
                    continue
                seen.add(iface)
                try:
                    result = service.fallback_iface(iface)
                    if result and result.get("status") == "changed":
                        log.info("mullvad probe fallback iface=%s %s", iface, result.get("message"))
                    elif result and result.get("status") == "failed":
                        log.warning("mullvad probe fallback iface=%s %s", iface, result.get("message"))
                except Exception:
                    log.exception("mullvad probe fallback failed iface=%s", iface)

        threading.Thread(target=_run_fallback, daemon=True).start()

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
