from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from agent.errorlog import CoreErrorLog
from agent.errors import AgentError, raise_agent_error
from agent.ops import install_core as run_install
from agent.routing import slug_for

from typing import Any, Callable


def health_payload(driver: Any) -> dict[str, Any]:
    return {
        "success": True,
        "service": "agent",
        "core": driver.key,
        "key": driver.key,
        "slug": slug_for(driver.key),
        "label": driver.label,
        "installed": driver.installed(),
        "running": driver.running(),
        "version": driver.version(),
        "capabilities": list(driver.capabilities()),
    }


def get_errors(request: Request) -> CoreErrorLog:
    return request.app.state.errors


def attach_lifecycle(router: APIRouter, *, core: str, get_driver: Callable) -> None:
    @router.get("/health")
    def core_health(driver=Depends(get_driver)):
        return health_payload(driver)

    @router.post("/install")
    def core_install():
        try:
            result = run_install(core)
        except AgentError as exc:
            raise_agent_error(exc.code, exc.message, exc.status)
        return {"success": True, "result": result}

    @router.post("/enable")
    def core_enable(driver=Depends(get_driver)):
        try:
            return {"success": True, "result": driver.enable()}
        except AgentError as exc:
            raise_agent_error(exc.code, exc.message, exc.status)

    @router.post("/disable")
    def core_disable(driver=Depends(get_driver)):
        try:
            return {"success": True, "result": driver.disable()}
        except AgentError as exc:
            raise_agent_error(exc.code, exc.message, exc.status)

    @router.post("/restart")
    def core_restart(driver=Depends(get_driver)):
        try:
            return {"success": True, "result": driver.restart()}
        except AgentError as exc:
            raise_agent_error(exc.code, exc.message, exc.status)

    @router.get("/errors")
    def core_errors(
        limit: int = Query(40, ge=1, le=200),
        level: str | None = Query(None),
        errors: CoreErrorLog = Depends(get_errors),
    ):
        return {"success": True, "core": core, "errors": errors.list(core, limit, level)}
