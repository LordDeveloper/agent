from fastapi import APIRouter

from agent.support.host_interfaces import list_host_interfaces

router = APIRouter(prefix="/network", tags=["network"])


@router.get("/interfaces")
def network_interfaces():
    return {"success": True, "interfaces": list_host_interfaces()}
