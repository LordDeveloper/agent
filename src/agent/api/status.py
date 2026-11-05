from fastapi import APIRouter, Request

from agent.support.bandwidth import read_status
from agent.support.sysstatus import collect_system_status

router = APIRouter(tags=["status"])


@router.get("/status/sys")
async def status_sys():
    """Current host CPU, memory, disk, bandwidth, and agent process metrics.

    Mounted at ``/api/v1/status/sys`` behind the same bearer/basic auth as the
    rest of the agent API. Rates are counter deltas; the first sample leaves
    them null.
    """
    payload = await collect_system_status()
    return {"success": True, **payload}


@router.get("/status/bandwidth-limits")
async def status_bandwidth_limits(request: Request):
    """Configured subscription rates and the last kernel reconcile result."""
    data_dir = request.app.state.settings.data_dir
    return {"success": True, **read_status(data_dir)}
