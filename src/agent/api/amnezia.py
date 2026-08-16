from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.drivers.amnezia import AmneziaDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import AmneziaInterfacePayload, AmneziaPeerPayload
from agent.registry import CoreRegistry

router = APIRouter(prefix="/cores/amnezia", tags=["amnezia"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_amnezia(registry: CoreRegistry = Depends(get_registry)) -> AmneziaDriver:
    driver = registry.get("amnezia")
    if not isinstance(driver, AmneziaDriver):
        raise_agent_error("UNSUPPORTED_CAPABILITY", "Amnezia core is not available")
    return driver


@router.get("/status")
def status(amnezia: AmneziaDriver = Depends(get_amnezia)):
    return {
        "success": True,
        "installed": amnezia.installed(),
        "running": amnezia.running(),
        "version": amnezia.version(),
    }


@router.get("/interfaces")
def list_interfaces(amnezia: AmneziaDriver = Depends(get_amnezia)):
    return {"success": True, "interfaces": amnezia.list_interfaces()}


@router.post("/interfaces")
def create_interface(payload: AmneziaInterfacePayload, amnezia: AmneziaDriver = Depends(get_amnezia)):
    body = payload.model_dump(exclude_none=True)
    if payload.obfuscation:
        body["obfuscation"] = payload.obfuscation.model_dump(exclude_none=True)
    try:
        iface = amnezia.create_interface(body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.get("/interfaces/{interface_id}")
def get_interface(interface_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        iface = amnezia.get_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.put("/interfaces/{interface_id}")
def update_interface(interface_id: str, payload: AmneziaInterfacePayload, amnezia: AmneziaDriver = Depends(get_amnezia)):
    body = payload.model_dump(exclude_none=True)
    if payload.obfuscation:
        body["obfuscation"] = payload.obfuscation.model_dump(exclude_none=True)
    try:
        iface = amnezia.update_interface(interface_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.delete("/interfaces/{interface_id}")
def delete_interface(interface_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        amnezia.delete_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers")
def add_peer(interface_id: str, payload: AmneziaPeerPayload, amnezia: AmneziaDriver = Depends(get_amnezia)):
    body = payload.model_dump(exclude_none=True)
    if payload.obfuscation:
        body["obfuscation"] = payload.obfuscation.model_dump(exclude_none=True)
    try:
        peer = amnezia.add_peer(interface_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.put("/interfaces/{interface_id}/peers/{peer_id}")
def update_peer(interface_id: str, peer_id: str, payload: AmneziaPeerPayload, amnezia: AmneziaDriver = Depends(get_amnezia)):
    body = payload.model_dump(exclude_none=True)
    if payload.obfuscation:
        body["obfuscation"] = payload.obfuscation.model_dump(exclude_none=True)
    try:
        peer = amnezia.update_peer(interface_id, peer_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.delete("/interfaces/{interface_id}/peers/{peer_id}")
def delete_peer(interface_id: str, peer_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        amnezia.delete_peer(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/reset-traffic")
def reset_peer_traffic(interface_id: str, peer_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        peer = amnezia.reset_peer_traffic(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.get("/interfaces/{interface_id}/peers/{peer_id}/config")
def peer_config(interface_id: str, peer_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        config = amnezia.peer_config(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "config": config}


@router.get("/peers/{email}/ips")
def peer_ips(email: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    return {"success": True, "ips": amnezia.peer_ips(email)}


@router.delete("/peers/{email}/ips")
def clear_peer_ips(email: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    amnezia.clear_peer_ips(email)
    return {"success": True}


@router.post("/backup")
def backup(amnezia: AmneziaDriver = Depends(get_amnezia)):
    return {"success": True, "backup": amnezia.backup()}


@router.post("/restore")
def restore(body: dict[str, Any], amnezia: AmneziaDriver = Depends(get_amnezia)):
    payload = body.get("backup") if isinstance(body.get("backup"), dict) else body
    amnezia.restore(payload)
    return {"success": True}
