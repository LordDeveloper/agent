"""Read-only document primary-key lookup. Does not create or change clients."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from agent.errors import raise_agent_error

router = APIRouter(prefix="/documents", tags=["documents"])

# Stay under SQLite's host parameter limit. The panel chunks below this.
LOOKUP_MAX_IDS = 1000


@router.post("/lookup")
async def lookup_document_keys(body: dict[str, Any], request: Request):
    ids = body.get("ids")
    if not isinstance(ids, list):
        raise_agent_error("VALIDATION_ERROR", "ids must be a list of document primary keys", 422)
    if len(ids) > LOOKUP_MAX_IDS:
        raise_agent_error(
            "VALIDATION_ERROR",
            f"ids exceeds {LOOKUP_MAX_IDS}; query a smaller chunk",
            422,
        )
    documents = await request.app.state.store.lookup_document_keys([str(item) for item in ids])
    return {"success": True, "documents": documents}
