from fastapi import APIRouter, Depends, Query, Request

from agent.registry import CoreRegistry

router = APIRouter(tags=["meta"])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


@router.get("/health")
async def health(registry: CoreRegistry = Depends(get_registry)):
    return {
        "success": True,
        "service": "agent",
        "cores": [c.model_dump() for c in await registry.list_cores()],
    }


@router.get("/activity")
async def live_activity(after: int = Query(0, ge=0), follow: int = Query(0)):
    from agent.logutil import activity_log

    payload = activity_log.cursor() if follow and after <= 0 else activity_log.since(after)
    return {"success": True, **payload}


@router.get("/cores")
async def list_cores(registry: CoreRegistry = Depends(get_registry)):
    return {"success": True, "cores": [c.model_dump() for c in await registry.list_cores()]}
