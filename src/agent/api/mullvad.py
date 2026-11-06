import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, Request

from agent.errors import AgentError, raise_agent_error
from agent.logutil import get_logger
from agent.support.mullvad import MullvadService, service_from_app

log = get_logger("mullvad")

router = APIRouter(prefix="/mullvad", tags=["mullvad"])

_RELAY_PING_LIMIT = 32
_relay_ping_jobs: dict[str, dict[str, Any]] = {}
_relay_ping_tasks: set[asyncio.Task[None]] = set()
_location_ping_jobs: dict[str, dict[str, Any]] = {}
_location_ping_tasks: set[asyncio.Task[None]] = set()


def _remember_location_ping(ping_id: str, record: dict[str, Any]) -> None:
    _location_ping_jobs[ping_id] = record
    while len(_location_ping_jobs) > _RELAY_PING_LIMIT:
        oldest = next(iter(_location_ping_jobs))
        _location_ping_jobs.pop(oldest, None)


async def _execute_location_ping(ping_id: str, service: MullvadService) -> None:
    rows: list[dict[str, Any]] = []
    try:
        payload = await service.locations(ping=False, cached=True)
        rows = [dict(row) for row in (payload.get("locations") or []) if isinstance(row, dict)]
        relays, _fresh = await service.load_catalog()

        def publish(status: str) -> None:
            _remember_location_ping(
                ping_id,
                {
                    "success": status != "error",
                    "status": status,
                    "ping_id": ping_id,
                    "locations": [dict(row) for row in rows],
                },
            )

        publish("running")
        await service._attach_pings(rows, relays, on_progress=lambda: publish("running"))
        publish("done")
    except AgentError as exc:
        log.warning("mullvad location ping failed ping_id=%s code=%s %s", ping_id, exc.code, exc.message)
        _remember_location_ping(
            ping_id,
            {
                "success": False,
                "status": "error",
                "ping_id": ping_id,
                "locations": [dict(row) for row in rows],
                "error": {"code": exc.code, "message": exc.message},
            },
        )
    except Exception as exc:
        log.exception("mullvad location ping failed ping_id=%s", ping_id)
        _remember_location_ping(
            ping_id,
            {
                "success": False,
                "status": "error",
                "ping_id": ping_id,
                "locations": [dict(row) for row in rows],
                "error": {"code": "INTERNAL_ERROR", "message": type(exc).__name__},
            },
        )


def _remember_relay_ping(ping_id: str, record: dict[str, Any]) -> None:
    _relay_ping_jobs[ping_id] = record
    while len(_relay_ping_jobs) > _RELAY_PING_LIMIT:
        oldest = next(iter(_relay_ping_jobs))
        _relay_ping_jobs.pop(oldest, None)


async def _execute_relay_ping(
    ping_id: str,
    service: MullvadService,
    country_code: str,
    base_rows: list[dict[str, Any]],
) -> None:
    by_host = {
        str(row.get("hostname") or "").strip().lower(): dict(row)
        for row in base_rows
        if str(row.get("hostname") or "").strip()
    }

    def publish(presented: dict[str, Any]) -> None:
        host = str(presented.get("hostname") or "").strip().lower()
        if not host:
            return
        current = by_host.get(host, {})
        current.update(presented)
        by_host[host] = current
        _remember_relay_ping(
            ping_id,
            {
                "success": True,
                "status": "running",
                "ping_id": ping_id,
                "country_code": country_code,
                "relays": list(by_host.values()),
            },
        )

    try:
        result = await service.country_relays(country_code, ping=True, on_row=publish)
        _remember_relay_ping(
            ping_id,
            {"success": True, "status": "done", "ping_id": ping_id, **result},
        )
    except AgentError as exc:
        log.warning("mullvad relay ping failed ping_id=%s code=%s %s", ping_id, exc.code, exc.message)
        _remember_relay_ping(
            ping_id,
            {
                "success": False,
                "status": "error",
                "ping_id": ping_id,
                "country_code": country_code,
                "relays": list(by_host.values()),
                "error": {"code": exc.code, "message": exc.message},
            },
        )
    except Exception as exc:
        log.exception("mullvad relay ping failed ping_id=%s", ping_id)
        _remember_relay_ping(
            ping_id,
            {
                "success": False,
                "status": "error",
                "ping_id": ping_id,
                "country_code": country_code,
                "relays": list(by_host.values()),
                "error": {"code": "INTERNAL_ERROR", "message": type(exc).__name__},
            },
        )


def _service(request: Request) -> MullvadService:
    return service_from_app(request)


@router.get("/locations/ping/{ping_id}")
async def mullvad_location_ping(ping_id: str):
    record = _location_ping_jobs.get(ping_id)
    if not isinstance(record, dict):
        raise_agent_error("NOT_FOUND", "Location ping was not found", 404)
    return record


@router.get("/locations")
async def mullvad_locations(request: Request, force: bool = False, ping: bool = False):
    try:
        # Catalog refresh belongs to `agent work`. force is accepted so older
        # panels keep working, and still does not call Mullvad from this request.
        _ = force
        service = _service(request)
        payload = await service.locations(ping=False, cached=True)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not ping:
        return {"success": True, "ping_status": "idle", **payload}

    ping_id = uuid.uuid4().hex
    rows = [row for row in (payload.get("locations") or []) if isinstance(row, dict)]
    _remember_location_ping(
        ping_id,
        {
            "success": True,
            "status": "running",
            "ping_id": ping_id,
            "locations": rows,
        },
    )
    task = asyncio.create_task(_execute_location_ping(ping_id, service))
    _location_ping_tasks.add(task)
    task.add_done_callback(_location_ping_tasks.discard)
    return {"success": True, "ping_status": "running", "ping_id": ping_id, **payload}


@router.get("/locations/{country_code}/relays/ping/{ping_id}")
async def mullvad_country_relay_ping(country_code: str, ping_id: str):
    record = _relay_ping_jobs.get(ping_id)
    code = str(country_code or "").strip().lower()
    if not isinstance(record, dict) or str(record.get("country_code") or "").strip().lower() != code:
        raise_agent_error("NOT_FOUND", "Relay ping was not found", 404)
    return record


@router.get("/locations/{country_code}/relays")
async def mullvad_country_relays(country_code: str, request: Request, ping: bool = True):
    service = _service(request)
    try:
        # The list itself never waits on probes. ping=1 only starts a bulk job.
        payload = await service.country_relays(country_code, ping=False)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not ping:
        return {"success": True, "ping_status": "idle", **payload}

    ping_id = uuid.uuid4().hex
    rows = [row for row in (payload.get("relays") or []) if isinstance(row, dict)]
    code = str(payload.get("country_code") or country_code).strip().lower()
    _remember_relay_ping(
        ping_id,
        {
            "success": True,
            "status": "running",
            "ping_id": ping_id,
            "country_code": code,
            "relays": rows,
        },
    )
    task = asyncio.create_task(_execute_relay_ping(ping_id, service, code, rows))
    _relay_ping_tasks.add(task)
    task.add_done_callback(_relay_ping_tasks.discard)
    return {"success": True, "ping_status": "running", "ping_id": ping_id, **payload}


@router.get("/status")
async def mullvad_status(request: Request, probe: bool = False):
    try:
        payload = await _service(request).status(probe=bool(probe))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/settings")
async def mullvad_settings(body: dict[str, Any], request: Request):
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
        payload = await _service(request).save_settings(**kwargs)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    propagated = payload.pop("propagated", None) if isinstance(payload, dict) else None
    public = {k: v for k, v in payload.items() if k != "private_key"}
    response: dict[str, Any] = {"success": True, "settings": public}
    if isinstance(propagated, dict):
        response["propagated"] = propagated
    return response


@router.post("/tunnels/{iface}/service")
async def mullvad_tunnel_service(iface: str, body: dict[str, Any], request: Request):
    try:
        payload = await _service(request).control_tunnel(iface, str(body.get("action") or ""))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/service")
async def mullvad_service_bulk(body: dict[str, Any], request: Request):
    try:
        raw_ifaces = body.get("ifaces") or body.get("interfaces") or []
        ifaces = [str(item) for item in raw_ifaces] if isinstance(raw_ifaces, list) else None
        payload = await _service(request).control_tunnels(
            str(body.get("action") or ""),
            ifaces=ifaces,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/ensure")
async def mullvad_ensure(country_code: str, request: Request):
    try:
        payload = await _service(request).ensure(country_code)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/relay")
async def mullvad_switch_relay(country_code: str, body: dict[str, Any], request: Request):
    try:
        fixed = bool(body.get("fixed") or body.get("pin") or body.get("pinned"))
        payload = await _service(request).switch_relay(
            country_code,
            str(body.get("hostname") or ""),
            fixed=fixed,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/fixed")
async def mullvad_set_relay_fixed(country_code: str, body: dict[str, Any], request: Request):
    try:
        fixed = bool(body.get("fixed") if "fixed" in body else (body.get("pin") or body.get("pinned")))
        payload = await _service(request).set_relay_fixed(country_code, fixed)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/locations/{country_code}/fallback")
async def mullvad_fallback_one(country_code: str, request: Request, optimize: bool = False):
    try:
        payload = await _service(request).fallback(country_code, optimize=optimize)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/fallback")
async def mullvad_fallback_all(request: Request, optimize: bool = False):
    try:
        payload = await _service(request).fallback(optimize=optimize)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, **payload}


@router.post("/bindings/refresh")
async def mullvad_refresh_bindings(request: Request):
    try:
        rows = await _service(request).refresh_bindings()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "bindings": rows}
