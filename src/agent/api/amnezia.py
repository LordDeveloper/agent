from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.amnezia import AmneziaDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import AmneziaInterfacePayload, AmneziaPeerPayload
from agent.registry import CoreRegistry
from agent.traffic.service import TrafficService

router = APIRouter(prefix="/cores/amnezia", tags=["amnezia"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


def get_amnezia(registry: CoreRegistry = Depends(get_registry)) -> AmneziaDriver:
    try:
        driver = registry.get("amnezia")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not isinstance(driver, AmneziaDriver):
        raise_agent_error("UNSUPPORTED_CAPABILITY", "Amnezia core is not available")
    return driver


attach_lifecycle(router, core="amnezia", get_driver=get_amnezia)


@router.get("/status")
def status(amnezia: AmneziaDriver = Depends(get_amnezia)):
    return health_payload(amnezia)


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


@router.post("/interfaces/{interface_id}/peers/batch")
@router.post("/interfaces/{interface_id}/peers:batch")
def batch_peers(interface_id: str, body: dict[str, Any], amnezia: AmneziaDriver = Depends(get_amnezia)):
    peers = body.get("peers") or []
    if not isinstance(peers, list):
        raise_agent_error("VALIDATION_ERROR", "peers must be a list", 422)
    mode = str(body.get("mode") or "upsert")
    atomic = bool(body.get("atomic", False))
    try:
        result = amnezia.batch_peers(
            interface_id,
            [row for row in peers if isinstance(row, dict)],
            mode=mode,
            atomic=atomic,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.delete("/interfaces/{interface_id}/peers/batch")
@router.delete("/interfaces/{interface_id}/peers:batch")
def batch_remove_peers(interface_id: str, body: dict[str, Any], amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        result = amnezia.batch_remove_peers(
            interface_id,
            emails=list(body.get("emails") or []),
            ids=list(body.get("ids") or []),
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


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
def reset_peer_traffic(
    interface_id: str,
    peer_id: str,
    amnezia: AmneziaDriver = Depends(get_amnezia),
    traffic: TrafficService = Depends(get_traffic),
):
    try:
        peer = amnezia.reset_peer_traffic(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    traffic.reset_client_record("amnezia", peer, peer_id)
    return {"success": True, "peer": peer}


@router.get("/interfaces/{interface_id}/peers/{peer_id}/config")
def peer_config(
    interface_id: str,
    peer_id: str,
    endpoint: str | None = None,
    amnezia: AmneziaDriver = Depends(get_amnezia),
):
    try:
        bundle = amnezia.peer_config_bundle(interface_id, peer_id, endpoint_host=endpoint or "127.0.0.1")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **bundle}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/repair-keys")
def repair_peer_keys(
    interface_id: str,
    peer_id: str,
    payload: dict[str, Any],
    amnezia: AmneziaDriver = Depends(get_amnezia),
):
    try:
        peer = amnezia.repair_peer_private_key(interface_id, peer_id, str(payload.get("private_key") or ""))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/reset-keys")
def reset_peer_keys(interface_id: str, peer_id: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        peer = amnezia.reset_peer_keys(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.get("/peers/{email}/ips")
def peer_ips(email: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    return {"success": True, "ips": amnezia.peer_ips(email)}


@router.get("/diagnose")
def diagnose_peer(address: str, amnezia: AmneziaDriver = Depends(get_amnezia)):
    try:
        report = amnezia.diagnose_address(address)
    except ValueError as exc:
        raise_agent_error("VALIDATION_ERROR", str(exc), 422)
    return report


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
