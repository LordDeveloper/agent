from typing import Any

from fastapi import APIRouter, Request

from agent.errors import AgentError, raise_agent_error
from agent.support.mullvad import MullvadService, service_from_app

router = APIRouter(prefix="/mullvad", tags=["mullvad"])


def _service(request: Request) -> MullvadService:
    return service_from_app(request)


@router.get("/locations")
def mullvad_locations(request: Request, force: bool = False, ping: bool = False):
    try:
        payload = _service(request).locations(force=force, ping=ping)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.get("/locations/{country_code}/relays")
def mullvad_country_relays(country_code: str, request: Request, ping: bool = True):
    try:
        payload = _service(request).country_relays(country_code, ping=ping)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.get("/status")
def mullvad_status(request: Request, probe: bool = False):
    try:
        payload = _service(request).status(probe=bool(probe))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/settings")
def mullvad_settings(body: dict[str, Any], request: Request):
    try:
        kwargs: dict[str, Any] = {}
        if "private_key" in body and body.get("private_key") is not None:
            kwargs["private_key"] = str(body.get("private_key") or "")
        if "address" in body:
            kwargs["address"] = (
                str(body["address"]).strip()
                if body.get("address") is not None
                else None
            )
        if "relay_metric" in body and body.get("relay_metric") is not None:
            kwargs["relay_metric"] = str(body.get("relay_metric") or "")
        if "relay_mode" in body and body.get("relay_mode") is not None:
            kwargs["relay_mode"] = str(body.get("relay_mode") or "")
        elif "selection_mode" in body and body.get("selection_mode") is not None:
            kwargs["selection_mode"] = str(body.get("selection_mode") or "")
        if "auto_fallback" in body and body.get("auto_fallback") is not None:
            raw = body.get("auto_fallback")
            if isinstance(raw, bool):
                kwargs["auto_fallback"] = raw
            else:
                text = str(raw).strip().lower()
                if text in {"1", "true", "yes", "on", "enable", "enabled"}:
                    kwargs["auto_fallback"] = True
                elif text in {"0", "false", "no", "off", "disable", "disabled"}:
                    kwargs["auto_fallback"] = False
                else:
                    raise AgentError("VALIDATION_ERROR", "auto_fallback must be true/false", 422)
        if not kwargs:
            raise AgentError("VALIDATION_ERROR", "No settings provided", 422)
        payload = _service(request).save_settings(**kwargs)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    propagated = payload.pop("propagated", None) if isinstance(payload, dict) else None
    public = {k: v for k, v in payload.items() if k != "private_key"}
    response: dict[str, Any] = {"success": True, "settings": public}
    if isinstance(propagated, dict):
        response["propagated"] = propagated
    return response


@router.post("/tunnels/{iface}/service")
def mullvad_tunnel_service(iface: str, body: dict[str, Any], request: Request):
    try:
        payload = _service(request).control_tunnel(iface, str(body.get("action") or ""))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/service")
def mullvad_service_bulk(body: dict[str, Any], request: Request):
    try:
        raw_ifaces = body.get("ifaces") or body.get("interfaces") or []
        ifaces = [str(item) for item in raw_ifaces] if isinstance(raw_ifaces, list) else None
        payload = _service(request).control_tunnels(
            str(body.get("action") or ""),
            ifaces=ifaces,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/ensure")
def mullvad_ensure(country_code: str, request: Request):
    try:
        payload = _service(request).ensure(country_code)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/relay")
def mullvad_switch_relay(country_code: str, body: dict[str, Any], request: Request):
    try:
        fixed = bool(body.get("fixed") or body.get("pin") or body.get("pinned"))
        payload = _service(request).switch_relay(
            country_code,
            str(body.get("hostname") or ""),
            fixed=fixed,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/fixed")
def mullvad_set_relay_fixed(country_code: str, body: dict[str, Any], request: Request):
    try:
        fixed = bool(body.get("fixed") if "fixed" in body else (body.get("pin") or body.get("pinned")))
        payload = _service(request).set_relay_fixed(country_code, fixed)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/fallback")
def mullvad_fallback_one(country_code: str, request: Request, optimize: bool = False):
    try:
        payload = _service(request).fallback(country_code, optimize=optimize)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/fallback")
def mullvad_fallback_all(request: Request, optimize: bool = False):
    try:
        payload = _service(request).fallback(optimize=optimize)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/bindings/refresh")
def mullvad_refresh_bindings(request: Request):
    try:
        rows = _service(request).refresh_bindings()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "bindings": rows}
