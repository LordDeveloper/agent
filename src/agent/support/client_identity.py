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
    """Split panel upsert fields into agent route id vs core/link id.

    Panel contract:
      - ``client_link_uuid``: identifier stored in the core (VLESS/VMess UUID)
      - ``id``: Agent database primary key when it differs from the core id
      - ``node_id``: legacy alias of the core id (still sent by the panel)

    The Agent primary key is never written into the core when a distinct
    ``client_link_uuid`` or legacy ``node_id`` is present.
    """
    row = dict(client)
    prior_agent = _trim(row.get("agent_id"))
    explicit_core = _trim(row.pop("client_link_uuid", None))
    panel_node_id = _trim(row.pop("node_id", None))
    incoming_id = _trim(row.get("id") or "")

    if explicit_core:
        protocol_id = explicit_core
        panel_global = explicit_core
        agent_hint = prior_agent
        if incoming_id and incoming_id != explicit_core:
            agent_hint = agent_hint or incoming_id
        elif panel_node_id and panel_node_id != explicit_core:
            agent_hint = agent_hint or panel_node_id
        if agent_hint and agent_hint != explicit_core:
            agent_id = agent_hint
        elif incoming_id and incoming_id != explicit_core:
            agent_id = incoming_id
        else:
            agent_id = str(uuid.uuid4())
    elif panel_node_id and incoming_id and panel_node_id != incoming_id:
        agent_id = prior_agent or incoming_id
        protocol_id = panel_node_id
        panel_global = panel_node_id
    elif panel_node_id:
        protocol_id = panel_node_id
        panel_global = panel_node_id
        if prior_agent and prior_agent != panel_node_id:
            agent_id = prior_agent
        elif incoming_id and incoming_id != panel_node_id:
            agent_id = incoming_id
        else:
            agent_id = str(uuid.uuid4())
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
    if store_kind == "xray":
        row["client_link_uuid"] = protocol_id
    return row


def panel_client_response(client: dict[str, Any]) -> dict[str, Any]:
    """Batch upsert response row for the Laravel panel.

    ``id`` and, when a core id exists, ``node_id`` are the Agent primary key.
    ``client_link_uuid`` is the identifier configured in the core.
    Cores without that split keep ``node_id`` as the legacy panel global id.
    """
    agent_id = _trim(client.get("agent_id") or "")
    panel_node_id = _trim(client.get("node_id") or "")
    protocol_id = _trim(client.get("id") or "")
    core_id = _trim(client.get("client_link_uuid") or "")
    email = _trim(client.get("email") or "")

    if core_id:
        if not agent_id:
            agent_id = protocol_id or panel_node_id
        if agent_id == core_id and panel_node_id and panel_node_id != core_id:
            agent_id = panel_node_id
        out: dict[str, Any] = {
            "id": agent_id,
            "node_id": agent_id,
            "client_link_uuid": core_id,
        }
    else:
        if not agent_id:
            agent_id = protocol_id
        if not panel_node_id:
            panel_node_id = protocol_id
        out = {
            "id": agent_id,
            "node_id": panel_node_id,
        }
    if email:
        out["email"] = email
    core = _trim(client.get("core") or "")
    if core:
        out["core"] = core
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
        link = _trim(meta.get("node_id") or "")
        legacy = _trim(meta.get("agent_id") or meta.get("primary_key") or "")
        stored_id = _trim(meta.get("id") or "")
        if legacy and legacy != link:
            return legacy
        if stored_id and link and stored_id != link:
            return stored_id
        if stored_id:
            return stored_id
    return protocol_id or email
