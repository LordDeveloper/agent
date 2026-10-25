from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.wireguard import WireGuardDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import WgInterfacePayload, WgPeerPayload
from agent.registry import CoreRegistry
from agent.traffic.service import TrafficService

router = APIRouter(prefix="/cores/wireguard", tags=["wireguard"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


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
async def status(wg: WireGuardDriver = Depends(get_wg)):
    return await health_payload(wg)


@router.get("/interfaces")
async def list_interfaces(wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "interfaces": await wg.list_interfaces()}


@router.post("/interfaces")
async def create_interface(payload: WgInterfacePayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = await wg.create_interface(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.get("/interfaces/{interface_id}")
async def get_interface(interface_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = await wg.get_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.put("/interfaces/{interface_id}")
async def update_interface(interface_id: str, payload: WgInterfacePayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        iface = await wg.update_interface(interface_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "interface": iface}


@router.delete("/interfaces/{interface_id}")
async def delete_interface(interface_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        await wg.delete_interface(interface_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers")
async def add_peer(interface_id: str, payload: WgPeerPayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = await wg.add_peer(interface_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.post("/interfaces/{interface_id}/peers/batch")
@router.post("/interfaces/{interface_id}/peers:batch")
async def batch_peers(interface_id: str, body: dict[str, Any], wg: WireGuardDriver = Depends(get_wg)):
    peers = body.get("peers") or []
    if not isinstance(peers, list):
        raise_agent_error("VALIDATION_ERROR", "peers must be a list", 422)
    mode = str(body.get("mode") or "upsert")
    atomic = bool(body.get("atomic", False))
    try:
        result = await wg.batch_peers(
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
async def batch_remove_peers(interface_id: str, body: dict[str, Any], wg: WireGuardDriver = Depends(get_wg)):
    try:
        result = await wg.batch_remove_peers(
            interface_id,
            emails=list(body.get("emails") or []),
            ids=list(body.get("ids") or []),
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.put("/interfaces/{interface_id}/peers/{peer_id}")
async def update_peer(interface_id: str, peer_id: str, payload: WgPeerPayload, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = await wg.update_peer(interface_id, peer_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.delete("/interfaces/{interface_id}/peers/{peer_id}")
async def delete_peer(interface_id: str, peer_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        await wg.delete_peer(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/reset-traffic")
async def reset_peer_traffic(
    interface_id: str,
    peer_id: str,
    wg: WireGuardDriver = Depends(get_wg),
    traffic: TrafficService = Depends(get_traffic),
):
    try:
        peer = await wg.reset_peer_traffic(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    await traffic.reset_client_record("wireguard", peer, peer_id)
    return {"success": True, "peer": peer}


@router.get("/interfaces/{interface_id}/peers/{peer_id}/config")
async def peer_config(
    interface_id: str,
    peer_id: str,
    endpoint: str | None = None,
    wg: WireGuardDriver = Depends(get_wg),
):
    try:
        bundle = await wg.peer_config_bundle(interface_id, peer_id, endpoint_host=endpoint or "127.0.0.1")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **bundle}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/repair-keys")
async def repair_peer_keys(
    interface_id: str,
    peer_id: str,
    payload: dict[str, Any],
    wg: WireGuardDriver = Depends(get_wg),
):
    try:
        peer = await wg.repair_peer_private_key(interface_id, peer_id, str(payload.get("private_key") or ""))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.post("/interfaces/{interface_id}/peers/{peer_id}/reset-keys")
async def reset_peer_keys(interface_id: str, peer_id: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        peer = await wg.reset_peer_keys(interface_id, peer_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "peer": peer}


@router.get("/peers/{email}/ips")
async def peer_ips(email: str, wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "ips": await wg.peer_ips(email)}


@router.get("/diagnose")
async def diagnose_peer(address: str, wg: WireGuardDriver = Depends(get_wg)):
    try:
        report = await wg.diagnose_address(address)
    except ValueError as exc:
        raise_agent_error("VALIDATION_ERROR", str(exc), 422)
    return report


@router.delete("/peers/{email}/ips")
async def clear_peer_ips(email: str, wg: WireGuardDriver = Depends(get_wg)):
    await wg.clear_peer_ips(email)
    return {"success": True}


@router.post("/backup")
async def backup(wg: WireGuardDriver = Depends(get_wg)):
    return {"success": True, "backup": await wg.backup()}


@router.post("/restore")
async def restore(body: dict[str, Any], wg: WireGuardDriver = Depends(get_wg)):
    payload = body.get("backup") if isinstance(body.get("backup"), dict) else body
    await wg.restore(payload)
    return {"success": True}
