"""One-shot server transfer: export this agent, or apply a snapshot and reload."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from agent.errors import AgentError, raise_agent_error
from agent.transfer_snapshot import apply_snapshot, export_snapshot

router = APIRouter(prefix="/transfer", tags=["transfer"])


@router.post("/snapshot")
async def export_transfer_snapshot(request: Request):
    try:
        snapshot = await export_snapshot(request.app.state.settings, request.app.state.store)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "snapshot": snapshot}


@router.post("/apply")
async def apply_transfer_snapshot(body: dict[str, Any], request: Request):
    snapshot = body.get("snapshot") if isinstance(body.get("snapshot"), dict) else body
    try:
        result = await apply_snapshot(
            request.app.state.settings,
            request.app.state.store,
            request.app.state.registry,
            snapshot,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {"success": True, "result": result}
