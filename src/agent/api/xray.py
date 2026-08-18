from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import ClientPayload, InboundPayload
from agent.registry import CoreRegistry

router = APIRouter(prefix="/cores/xray", tags=["xray"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_xray(registry: CoreRegistry = Depends(get_registry)) -> XrayDriver:
    try:
        driver = registry.get("xray")
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not isinstance(driver, XrayDriver):
        raise_agent_error("UNSUPPORTED_CAPABILITY", "Xray core is not available")
    return driver


attach_lifecycle(router, core="xray", get_driver=get_xray)


@router.get("/status")
def xray_status(xray: XrayDriver = Depends(get_xray)):
    payload = health_payload(xray)
    payload["obj"] = {
        "xray": {
            "state": "running" if payload["running"] else "stop",
            "errorMsg": "",
        },
    }
    return payload


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
    except Exception as exc:
        raise_agent_error("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", 500)
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
    except Exception as exc:
        raise_agent_error("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", 500)
    return {"success": True, "client": client}


@router.get("/clients/{email}/ips")
def client_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "ips": xray.client_ips(email)}


@router.delete("/clients/{email}/ips")
def clear_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    xray.clear_client_ips(email)
    return {"success": True}


def _as_rows(body: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = body.get(key) or ([body] if body else [])
    return [row for row in rows if isinstance(row, dict)]


def _as_tags(body: dict[str, Any]) -> list[str]:
    tags = body.get("tags") or ([body.get("tag")] if body.get("tag") else [])
    return [str(tag).strip() for tag in tags if str(tag).strip()]


@router.get("/console")
def xray_console(xray: XrayDriver = Depends(get_xray)):
    try:
        payload = xray.console()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.get("/config")
def get_config(xray: XrayDriver = Depends(get_xray)):
    try:
        config = xray.dumped_config()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "config": config, "config_path": xray.settings.xray.config}


@router.put("/config")
def put_config(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        if body.get("section"):
            result = xray.replace_section(str(body.get("section")), body.get("value"))
        else:
            config = body.get("config") if isinstance(body.get("config"), dict) else body
            result = xray.apply_config(dict(config or {}))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.get("/logs")
def xray_logs(kind: str = "error", lines: int = 200, xray: XrayDriver = Depends(get_xray)):
    try:
        payload = xray.tail_logs(kind=kind, lines=lines)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/logger/restart")
def restart_logger(xray: XrayDriver = Depends(get_xray)):
    try:
        result = xray.restart_logger()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.get("/outbounds")
def list_outbounds(xray: XrayDriver = Depends(get_xray)):
    try:
        rows = xray.list_outbounds()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "outbounds": rows}


@router.post("/outbounds")
def add_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = xray.add_outbounds(_as_rows(body, "outbounds"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.put("/outbounds")
def edit_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = xray.edit_outbounds(_as_rows(body, "outbounds"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.delete("/outbounds")
def remove_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = xray.remove_outbounds(_as_tags(body))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.get("/rules")
def list_rules(xray: XrayDriver = Depends(get_xray)):
    try:
        rows = xray.list_rules()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "rules": rows}


@router.post("/rules")
def add_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or body.get("routing", {}).get("rules") or []
    try:
        result = xray.add_rules([row for row in rules if isinstance(row, dict)])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.put("/rules")
def edit_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or ([body] if body else [])
    try:
        result = xray.edit_rules([row for row in rules if isinstance(row, dict)])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.delete("/rules")
def remove_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = xray.remove_rules(_as_tags(body))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


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
