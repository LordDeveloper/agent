from __future__ import annotations

import uuid
from typing import Any, Literal

StoreKind = Literal["xray", "agent"]


def _trim(value: Any) -> str:
    return str(value or "").strip()


def apply_panel_identity(
    client: dict[str, Any],
    *,
    store_kind: StoreKind = "xray",
) -> dict[str, Any]:
    """Split panel upsert fields into agent route id vs protocol/global id.

    Panel contract:
      - ``node_id``: immutable link / panel global id (VLESS uuid when applicable)
      - ``id``: agent-scoped route primary key (optional on first create)
    """
    row = dict(client)
    panel_node_id = _trim(row.pop("node_id", None))
    incoming_id = _trim(row.get("id") or "")

    if panel_node_id and incoming_id and panel_node_id != incoming_id:
        agent_id = incoming_id
        protocol_id = panel_node_id
        panel_global = panel_node_id
    elif panel_node_id:
        protocol_id = panel_node_id
        panel_global = panel_node_id
        agent_id = incoming_id or str(uuid.uuid4())
    elif incoming_id:
        agent_id = incoming_id
        protocol_id = incoming_id
        panel_global = incoming_id
    else:
        agent_id = str(uuid.uuid4())
        protocol_id = agent_id
        panel_global = agent_id

    row["agent_id"] = agent_id
    row["node_id"] = panel_global
    row["id"] = agent_id if store_kind == "agent" else protocol_id
    return row


def panel_client_response(client: dict[str, Any]) -> dict[str, Any]:
    """Batch upsert response row for the Laravel panel."""
    agent_id = _trim(client.get("agent_id") or "")
    panel_node_id = _trim(client.get("node_id") or "")
    protocol_id = _trim(client.get("id") or "")
    email = _trim(client.get("email") or "")

    if not agent_id:
        agent_id = protocol_id
    if not panel_node_id:
        panel_node_id = protocol_id

    out: dict[str, Any] = {
        "id": agent_id,
        "node_id": panel_node_id,
    }
    if email:
        out["email"] = email
    return out


def identity_lookup_keys(client: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for value in (
        client.get("agent_id"),
        client.get("node_id"),
        client.get("id"),
        client.get("email"),
        client.get("password"),
    ):
        text = _trim(value)
        if text:
            keys.add(text)
    return keys


def billing_client_id(meta: dict[str, Any] | None, *, protocol_id: str, email: str) -> str:
    """Panel ``subscribes.node_id`` (agent route id) for traffic rows."""
    if isinstance(meta, dict):
        agent_id = _trim(meta.get("agent_id") or "")
        if agent_id:
            return agent_id
    return protocol_id or email
