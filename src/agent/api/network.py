from fastapi import APIRouter, Request

from agent.db import Store
from agent.support.peer_egress import all_desired_rules_from_store, all_tunnel_interface_names, repair_peer_egress
from agent.support.host_interfaces import list_host_interfaces

router = APIRouter(prefix="/network", tags=["network"])


@router.get("/interfaces")
def network_interfaces():
    return {"success": True, "interfaces": list_host_interfaces()}


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
