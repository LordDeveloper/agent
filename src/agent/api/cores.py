from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, Field

from agent.auth import verify_auth
from agent.errors import AgentError, raise_agent_error
from agent.registry import CoreRegistry

router = APIRouter(tags=["meta"])


class CoreInstallBody(BaseModel):
    github_token: str | None = Field(
        default=None,
        description="GitHub PAT for private release download (falls back to GITHUB_TOKEN env)",
    )


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
def install_core(
    core: str,
    body: CoreInstallBody | None = Body(default=None),
    registry: CoreRegistry = Depends(get_registry),
):
    try:
        registry.get(core)
        from agent.ops import install_core as run_install

        token = body.github_token if body else None
        result = run_install(core, github_token=token)
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
