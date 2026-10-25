from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import ClientPayload, InboundPayload
from agent.registry import CoreRegistry
from agent.traffic.service import TrafficService

router = APIRouter(prefix="/cores/xray", tags=["xray"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


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
async def xray_status(xray: XrayDriver = Depends(get_xray)):
    payload = await health_payload(xray)
    payload["obj"] = {
        "xray": {
            "state": "running" if payload["running"] else "stop",
            "errorMsg": "",
        },
    }
    return payload


@router.get("/inbounds")
async def list_inbounds(xray: XrayDriver = Depends(get_xray)):
    try:
        inbounds = await xray.present_inbounds(await xray.list_inbounds())
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbounds": inbounds}


@router.get("/inbounds/{inbound_id}")
async def get_inbound(
    inbound_id: str,
    include_clients: bool = True,
    xray: XrayDriver = Depends(get_xray),
):
    try:
        inbound = await xray.get_inbound(inbound_id, include_clients=include_clients)
        if include_clients:
            presented = await xray.present_inbounds([inbound])
            inbound = presented[0]
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.post("/inbounds")
async def create_inbound(payload: InboundPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = await xray.create_inbound(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.put("/inbounds/{inbound_id}")
async def update_inbound(inbound_id: str, payload: InboundPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = await xray.update_inbound(inbound_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.patch("/inbounds/{inbound_id}")
@router.put("/inbounds/{inbound_id}/settings")
async def patch_inbound_settings(inbound_id: str, body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        inbound = await xray.patch_inbound_settings(inbound_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "ok": True, "inbound": inbound}


@router.post("/inbounds/{inbound_id}/refresh")
async def refresh_inbound(inbound_id: str, body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    if not body.get("protocol") and not body.get("streamSettings"):
        raise_agent_error(
            "VALIDATION_ERROR",
            "full inbound config is required (protocol/streamSettings); formats are client-side",
        )
    try:
        inbound = await xray.refresh_inbound(inbound_id, body)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "inbound": inbound}


@router.delete("/inbounds/{inbound_id}")
async def delete_inbound(inbound_id: str, xray: XrayDriver = Depends(get_xray)):
    try:
        await xray.delete_inbound(inbound_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/inbounds/{inbound_id}/clients")
async def add_client(inbound_id: str, payload: ClientPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        client = await xray.add_client(inbound_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "client": client}


@router.post("/inbounds/{inbound_id}/clients/batch")
@router.post("/inbounds/{inbound_id}/clients:batch")
async def batch_clients(inbound_id: str, body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    clients = body.get("clients") or []
    if not isinstance(clients, list):
        raise_agent_error("VALIDATION_ERROR", "clients must be a list", 422)
    mode = str(body.get("mode") or "upsert")
    atomic = bool(body.get("atomic", False))
    try:
        result = await xray.batch_clients(inbound_id,
            [row for row in clients if isinstance(row, dict)],
            mode=mode,
            atomic=atomic,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.delete("/inbounds/{inbound_id}/clients/batch")
@router.delete("/inbounds/{inbound_id}/clients:batch")
async def batch_remove_clients(inbound_id: str, body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.batch_remove_clients(inbound_id,
            emails=list(body.get("emails") or []),
            ids=list(body.get("ids") or []),
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.get("/inbounds/{inbound_id}/clients/{client_key}")
async def get_client_record(inbound_id: str, client_key: str, xray: XrayDriver = Depends(get_xray)):
    try:
        client = await xray.get_client_record(inbound_id, client_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "client": client}


@router.put("/inbounds/{inbound_id}/clients/{client_key}")
async def update_client(inbound_id: str, client_key: str, payload: ClientPayload, xray: XrayDriver = Depends(get_xray)):
    try:
        client = await xray.update_client(inbound_id, client_key, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    except Exception as exc:
        raise_agent_error("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", 500)
    return {"success": True, "client": client}


@router.delete("/inbounds/{inbound_id}/clients/{client_key}")
async def delete_client(inbound_id: str, client_key: str, xray: XrayDriver = Depends(get_xray)):
    try:
        await xray.delete_client(inbound_id, client_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True}


@router.post("/inbounds/{inbound_id}/clients/{client_key}/reset-traffic")
async def reset_traffic(
    inbound_id: str,
    client_key: str,
    xray: XrayDriver = Depends(get_xray),
    traffic: TrafficService = Depends(get_traffic),
):
    try:
        client = await xray.reset_client_traffic(inbound_id, client_key)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    except Exception as exc:
        raise_agent_error("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", 500)
    await traffic.reset_client_record("xray", client, client_key)
    return {"success": True, "client": client}


@router.get("/diagnose")
async def diagnose_client(
    key: str | None = None,
    email: str | None = None,
    client_id: str | None = None,
    inbound_id: str | None = None,
    xray: XrayDriver = Depends(get_xray),
):
    client_key = str(key or email or client_id or "").strip()
    if not client_key:
        raise_agent_error("VALIDATION_ERROR", "key, email, or client_id is required", 422)
    try:
        report = await xray.diagnose_client(client_key, inbound_id=inbound_id)
    except ValueError as exc:
        raise_agent_error("VALIDATION_ERROR", str(exc), 422)
    return report


@router.get("/clients/{email}/ips")
async def client_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    try:
        ips = await xray.client_ip_last_seen(email)
    except AgentError as exc:
        # Offline users are reported as 404 by Xray online/iplist — treat as [].
        message = str(exc.message or "").lower()
        if exc.status == 404 or exc.code == "USER_OFFLINE" or "online not found" in message:
            return {"success": True, "ips": []}
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "ips": ips}


@router.delete("/clients/{email}/ips")
async def clear_ips(email: str, xray: XrayDriver = Depends(get_xray)):
    xray.clear_client_ips(email)
    return {"success": True}


def _as_rows(body: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = body.get(key) or ([body] if body else [])
    return [row for row in rows if isinstance(row, dict)]


def _as_tags(body: dict[str, Any]) -> list[str]:
    tags = body.get("tags") or ([body.get("tag")] if body.get("tag") else [])
    return [str(tag).strip() for tag in tags if str(tag).strip()]


@router.get("/console")
async def xray_console(xray: XrayDriver = Depends(get_xray)):
    try:
        payload = await xray.console()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.get("/geodata")
async def export_geodata_route(xray: XrayDriver = Depends(get_xray)):
    from agent.xray_release import export_geodata

    del xray
    try:
        payload = export_geodata()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/geodata")
async def import_geodata_route(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    from agent.xray_release import import_geodata

    del xray
    files = body.get("files")
    if not isinstance(files, list):
        raise_agent_error("VALIDATION_ERROR", "files must be a list", 422)
    try:
        result = import_geodata(files)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.get("/config/raw")
async def get_raw_config(xray: XrayDriver = Depends(get_xray)):
    """Full on-disk config, including secrets. Used to move a server onto a new agent."""
    try:
        config = await xray._read_config()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "config": config, "config_path": xray.settings.xray.config}


@router.get("/config")
async def get_config(xray: XrayDriver = Depends(get_xray)):
    try:
        config = await xray.dumped_config()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "config": config, "config_path": xray.settings.xray.config}


@router.put("/config")
async def put_config(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        if body.get("section"):
            result = await xray.replace_section(str(body.get("section")), body.get("value"))
        else:
            config = body.get("config") if isinstance(body.get("config"), dict) else body
            result = await xray.apply_config(dict(config or {}))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/ensure-traffic-stats")
async def ensure_traffic_stats(xray: XrayDriver = Depends(get_xray)):
    """Enable stats/policy/StatsService on disk without a full config round-trip."""
    try:
        from pathlib import Path

        from agent.xray_service import ensure_xray_traffic_stats_config

        path = Path(xray.settings.xray.config)
        changed = ensure_xray_traffic_stats_config(path)
        config = await xray._read_config()
        # Hot-reload into running core when possible (keeps connections if import works).
        try:
            api = await xray._api()
            reload_result = await api.import_config(config, path=str(path))
        except AgentError as exc:
            reload_result = {"ok": False, "error": exc.message}
        return {
            "success": True,
            "changed": changed,
            "config_path": str(path),
            "stats": config.get("stats") if isinstance(config.get("stats"), dict) else {},
            "policy": config.get("policy") if isinstance(config.get("policy"), dict) else {},
            "api": config.get("api") if isinstance(config.get("api"), dict) else {},
            "reload": reload_result if isinstance(reload_result, dict) else {"ok": True, "result": reload_result},
        }
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)



@router.get("/logs")
async def xray_logs(kind: str = "error", lines: int = 200, xray: XrayDriver = Depends(get_xray)):
    try:
        payload = await xray.tail_logs(kind=kind, lines=lines)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/logger/restart")
async def restart_logger(xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.restart_logger()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.get("/outbounds")
async def list_outbounds(xray: XrayDriver = Depends(get_xray)):
    try:
        rows = await xray.list_outbounds()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "outbounds": rows}


@router.post("/outbounds")
async def add_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.add_outbounds(_as_rows(body, "outbounds"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.put("/outbounds")
async def edit_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.edit_outbounds(_as_rows(body, "outbounds"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.delete("/outbounds")
async def remove_outbounds(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.remove_outbounds(_as_tags(body))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.get("/rules")
async def list_rules(xray: XrayDriver = Depends(get_xray)):
    try:
        rows = await xray.list_rules()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "rules": rows}


@router.post("/rules")
async def add_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or body.get("routing", {}).get("rules") or []
    try:
        result = await xray.add_rules([row for row in rules if isinstance(row, dict)])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.put("/rules")
async def edit_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or ([body] if body else [])
    try:
        result = await xray.edit_rules([row for row in rules if isinstance(row, dict)])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.delete("/rules")
async def remove_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    try:
        result = await xray.remove_rules(_as_tags(body))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.put("/routing/rules")
async def replace_routing_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or body.get("routing", {}).get("rules") or []
    extras = {k: v for k, v in body.items() if k not in {"rules", "routing"} and v is not None}
    if isinstance(body.get("routing"), dict):
        for key, value in body["routing"].items():
            if key != "rules" and key not in extras:
                extras[key] = value
    try:
        result = await xray.replace_rules([row for row in rules if isinstance(row, dict)], routing_extras=extras)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.get("/httpapi/guard")
async def httpapi_guard(xray: XrayDriver = Depends(get_xray)):
    try:
        guard = await xray.httpapi_guard()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **guard}


@router.post("/httpapi/ensure-auth")
async def ensure_httpapi_auth(xray: XrayDriver = Depends(get_xray)):
    try:
        guard = await xray.ensure_httpapi_auth()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **guard}


@router.post("/routing/rules/append")
async def append_routing_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    rules = body.get("rules") or []
    try:
        result = await xray.append_rules([row for row in rules if isinstance(row, dict)])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/routing/rules/upsert")
@router.post("/routing/rules:upsert")
async def upsert_routing_rules(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    remove_tags = body.get("remove_tags") or body.get("tags") or []
    add = body.get("add") or body.get("rules") or []
    try:
        result = await xray.upsert_rules(remove_tags=[str(tag) for tag in remove_tags if str(tag).strip()],
            add=[row for row in add if isinstance(row, dict)],
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.post("/routing/test")
async def test_routing(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    attrs = {
        "domain": body.get("domain"),
        "ip": body.get("ip"),
        "user": body.get("user") or body.get("email"),
        "inboundTag": body.get("inboundTag") or body.get("inbound"),
        "protocol": body.get("protocol"),
        "port": body.get("port"),
        "network": body.get("network"),
        "source": body.get("source"),
    }
    try:
        result = await xray.test_routing(attrs)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **result}


@router.post("/sourceip/block")
async def block_source_ips(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    ips = list(body.get("source_ips") or body.get("ips") or [])
    try:
        result = await xray.block_source_ips(ips,
            outbound=body.get("outbound", "blocked"),
            inbound=body.get("inbound"),
            rule_tag=body.get("rule_tag", "sourceIpBlock"),
            reset=bool(body.get("reset", False)),
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/config/import")
async def import_config(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    config = body.get("config") or body
    try:
        result = await xray.import_config(config, path=body.get("path"))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/backup")
async def backup(xray: XrayDriver = Depends(get_xray)):
    return {"success": True, "backup": await xray.backup()}


@router.post("/restore")
async def restore(body: dict[str, Any], xray: XrayDriver = Depends(get_xray)):
    payload = body.get("backup") if isinstance(body.get("backup"), dict) else body
    await xray.restore(payload)
    return {"success": True}


@router.post("/x25519")
async def x25519(xray: XrayDriver = Depends(get_xray)):
    try:
        keys = await xray.x25519()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "keys": keys}
