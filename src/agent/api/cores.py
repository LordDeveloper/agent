from fastapi import APIRouter, Depends, Request

from agent.auth import verify_auth
from agent.errors import AgentError, raise_agent_error
from agent.registry import CoreRegistry

router = APIRouter(tags=["meta"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


@router.get("/health")
def health(registry: CoreRegistry = Depends(get_registry)):
    return {
        "success": True,
        "service": "agent",
        "cores": [c.model_dump() for c in registry.list_cores()],
    }


@router.get("/cores")
def list_cores(registry: CoreRegistry = Depends(get_registry)):
    return {"success": True, "cores": [c.model_dump() for c in registry.list_cores()]}


@router.get("/cores/{core}")
def get_core(core: str, registry: CoreRegistry = Depends(get_registry)):
    try:
        driver = registry.get(core)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    info = registry._info(driver)
    return {"success": True, "core": info.model_dump()}


@router.post("/cores/{core}/install")
def install_core(core: str, registry: CoreRegistry = Depends(get_registry)):
    try:
        result = registry.get(core).install()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}


@router.post("/cores/{core}/enable")
def enable_core(core: str, registry: CoreRegistry = Depends(get_registry)):
    result = registry.get(core).enable()
    return {"success": True, "result": result}


@router.post("/cores/{core}/disable")
def disable_core(core: str, registry: CoreRegistry = Depends(get_registry)):
    result = registry.get(core).disable()
    return {"success": True, "result": result}


@router.post("/cores/{core}/restart")
def restart_core(core: str, registry: CoreRegistry = Depends(get_registry)):
    result = registry.get(core).restart()
    return {"success": True, "result": result}
