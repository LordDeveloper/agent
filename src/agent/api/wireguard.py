from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.wireguard import WireGuardDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import WgInterfacePayload, WgPeerPayload
from agent.registry import CoreRegistry

router = APIRouter(prefix="/cores/wireguard", tags=["wireguard"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_wg(registry: CoreRegistry = Depends(get_registry)) -> WireGuardDriver:
    try:
        driver = registry.get("wireguard")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not isinstance(driver, WireGuardDriver) or driver.key != "wireguard":
        raise_agent_error("UNSUPPORTED_CAPABILITY", "WireGuard core is not available")
    return driver


attach_lifecycle(router, core="wireguard", get_driver=get_wg)


@router.get("/status")
def status(wg: WireGuardDriver = Depends(get_wg)):
    return health_payload(wg)


@router.get("/interfaces")
def list_interfaces(wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "interfaces": wg.list_interfaces()}


@router.post("/interfaces")
def create_interface(payload: WgInterfacePayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = wg.create_interface(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.get("/interfaces/{interface_id}")
def get_interface(interface_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = wg.get_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.put("/interfaces/{interface_id}")
def update_interface(interface_id: str, payload: WgInterfacePayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = wg.update_interface(interface_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.delete("/interfaces/{interface_id}")
def delete_interface(interface_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        wg.delete_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers")
def add_peer(interface_id: str, payload: WgPeerPayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = wg.add_peer(interface_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.put("/interfaces/{interface_id}/peers/{peer_id}")
def update_peer(interface_id: str, peer_id: str, payload: WgPeerPayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = wg.update_peer(interface_id, peer_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.delete("/interfaces/{interface_id}/peers/{peer_id}")
def delete_peer(interface_id: str, peer_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        wg.delete_peer(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/reset-traffic")
def reset_peer_traffic(interface_id: str, peer_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = wg.reset_peer_traffic(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.get("/interfaces/{interface_id}/peers/{peer_id}/config")
def peer_config(
    interface_id: str,
    peer_id: str,
    endpoint: str | None = None,
    wg: WireGuardDriver = Depends(get_wg),
):
    try:
        config = wg.peer_config(interface_id, peer_id, endpoint_host=endpoint or "127.0.0.1")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "config": config}


@router.get("/peers/{email}/ips")
def peer_ips(email: str, wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "ips": wg.peer_ips(email)}


@router.get("/diagnose")
def diagnose_peer(address: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        report = wg.diagnose_address(address)
    except ValueError as exc:
        raise_agent_error("VALIDATION_ERROR", str(exc), 422)
    return report


@router.delete("/peers/{email}/ips")
def clear_peer_ips(email: str, wg: WireGuardDriver = Depends(get_wg)):
    wg.clear_peer_ips(email)
    return {"success": True}


@router.post("/backup")
def backup(wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "backup": wg.backup()}


@router.post("/restore")
def restore(body: dict[str, Any], wg: WireGuardDriver = Depends(get_wg)):
    payload = body.get("backup") if isinstance(body.get("backup"), dict) else body
    wg.restore(payload)
    return {"success": True}
