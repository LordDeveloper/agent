from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.drivers.xray import XrayDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import ClientPayload, InboundPayload
from agent.registry import CoreRegistry

router = APIRouter(prefix="/cores/xray", tags=["xray"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_xray(registry: CoreRegistry = Depends(get_registry)) -> XrayDriver:
    driver = registry.get("xray")
    if not isinstance(driver, XrayDriver):
        raise_agent_error("UNSUPPORTED_CAPABILITY", "Xray core is not available")
    return driver


@router.get("/status")
def xray_status(xray: XrayDriver = Depends(get_xray)):
    return {
        "success": True,
        "installed": xray.installed(),
        "running": xray.running(),
        "version": xray.version(),
        # Bot-compatible shape used by AdminServerManage / ServerService checks.
        "obj": {"xray": {"state": "running" if xray.running() else "stop", "errorMsg": ""}},
    }


@router.post("/restart")
def xray_restart(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "result": xray.restart()}


@router.get("/inbounds")
def list_inbounds(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "inbounds": xray.list_inbounds()}


@router.get("/inbounds/{inbound_id}")
def get_inbound(inbound_id: str, xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = xray.get_inbound(inbound_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.post("/inbounds")
def create_inbound(payload: InboundPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = xray.create_inbound(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.put("/inbounds/{inbound_id}")
def update_inbound(inbound_id: str, payload: InboundPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = xray.update_inbound(inbound_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.post("/inbounds/{inbound_id}/refresh")
def refresh_inbound(inbound_id: str, body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    if not body.get("protocol") and not body.get("streamSettings"):
        raise_agent_error(
            "VALIDATION_ERROR",
            "full inbound config is required (protocol/streamSettings); formats are client-side",
        )
    try:
        inbound = xray.refresh_inbound(inbound_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.delete("/inbounds/{inbound_id}")
def delete_inbound(inbound_id: str, xray: XrayDriver = Depends(get_xray)):
    try:
        xray.delete_inbound(inbound_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/inbounds/{inbound_id}/clients")
def add_client(inbound_id: str, payload: ClientPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        client = xray.add_client(inbound_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "client": client}


@router.put("/inbounds/{inbound_id}/clients/{client_key}")
def update_client(inbound_id: str, client_key: str, payload: ClientPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        client = xray.update_client(inbound_id, client_key, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "client": client}


@router.delete("/inbounds/{inbound_id}/clients/{client_key}")
def delete_client(inbound_id: str, client_key: str, xray: XrayDriver = Depends(get_xray)):
    try:
        xray.delete_client(inbound_id, client_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/inbounds/{inbound_id}/clients/{client_key}/reset-traffic")
def reset_traffic(inbound_id: str, client_key: str, xray: XrayDriver = Depends(get_xray)):
    try:
        client = xray.reset_client_traffic(inbound_id, client_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "client": client}


@router.get("/clients/{email}/ips")
def client_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "ips": xray.client_ips(email)}


@router.delete("/clients/{email}/ips")
def clear_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    xray.clear_client_ips(email)
    return {"success": True}


@router.get("/outbounds")
def list_outbounds(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "outbounds": xray.list_outbounds()}


@router.post("/outbounds")
def add_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rows = body.get("outbounds") or ([body] if body else [])
    return {"success": True, "result": xray.add_outbounds(list(rows))}


@router.delete("/outbounds")
def remove_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    tags = list(body.get("tags") or [])
    return {"success": True, "result": xray.remove_outbounds(tags)}


@router.get("/rules")
def list_rules(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "rules": xray.list_rules()}


@router.post("/rules")
def add_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or body.get("routing", {}).get("rules") or []
    return {"success": True, "result": xray.add_rules(list(rules))}


@router.delete("/rules")
def remove_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    tags = list(body.get("tags") or [])
    return {"success": True, "result": xray.remove_rules(tags)}


@router.post("/sourceip/block")
def block_source_ips(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    ips = list(body.get("source_ips") or body.get("ips") or [])
    try:
        result = xray.block_source_ips(
            ips,
            outbound=body.get("outbound", "blocked"),
            inbound=body.get("inbound"),
            rule_tag=body.get("rule_tag", "sourceIpBlock"),
            reset=bool(body.get("reset", False)),
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/config/import")
def import_config(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    config = body.get("config") or body
    try:
        result = xray.import_config(config, path=body.get("path"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/backup")
def backup(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "backup": xray.backup()}


@router.post("/restore")
def restore(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    payload = body.get("backup") if isinstance(body.get("backup"), dict) else body
    xray.restore(payload)
    return {"success": True}


@router.post("/x25519")
def x25519(xray: XrayDriver = Depends(get_xray)):
    try:
        keys = xray.x25519()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "keys": keys}
