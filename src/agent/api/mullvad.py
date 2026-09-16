from typing import Any

from fastapi import APIRouter, Request

from agent.errors import AgentError, raise_agent_error
from agent.support.mullvad import MullvadService, service_from_app

router = APIRouter(prefix="/mullvad", tags=["mullvad"])


def _service(request: Request) -> MullvadService:
    return service_from_app(request)


@router.get("/locations")
def mullvad_locations(request: Request, force: bool = False):
    try:
        payload = _service(request).locations(force=force)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.get("/status")
def mullvad_status(request: Request):
    try:
        payload = _service(request).status()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/settings")
def mullvad_settings(body: dict[str, Any], request: Request):
    try:
        payload = _service(request).save_settings(
            private_key=str(body.get("private_key") or ""),
            address=str(body["address"]).strip() if "address" in body and body.get("address") is not None else None,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    public = {k: v for k, v in payload.items() if k != "private_key"}
    return {"success": True, "settings": public}


@router.post("/locations/{country_code}/ensure")
def mullvad_ensure(country_code: str, request: Request):
    try:
        payload = _service(request).ensure(country_code)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/fallback")
def mullvad_fallback_one(country_code: str, request: Request):
    try:
        payload = _service(request).fallback(country_code)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/fallback")
def mullvad_fallback_all(request: Request):
    try:
        payload = _service(request).fallback()
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
