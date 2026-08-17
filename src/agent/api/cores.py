from fastapi import APIRouter, Depends, Request

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
