from __future__ import annotations

from typing import Any

from agent.database.models.client import PARENT_INTERFACE, PARENT_SERVER


def client_row_to_member(row: Any) -> dict[str, Any]:
    """Rebuild a driver-facing peer/user dict from ORM ``Client`` + ``meta``."""
    payload: dict[str, Any] = dict(row.meta or {})
    payload["id"] = str(row.id)
    payload["node_id"] = str(row.id)
    if row.email:
        payload["email"] = row.email
    if row.name:
        payload["name"] = row.name
    payload["is_enabled"] = bool(row.is_enabled)
    if row.disabled_reason:
        payload["disabled_reason"] = row.disabled_reason
    if row.disabled_at:
        payload["disabled_at"] = row.disabled_at
    return payload


def assemble_interface(config: dict[str, Any], peers: list[dict[str, Any]]) -> dict[str, Any]:
    doc = dict(config)
    if peers:
        doc["peers"] = list(peers)
    return doc


def assemble_server(config: dict[str, Any], users: list[dict[str, Any]]) -> dict[str, Any]:
    doc = dict(config)
    if users:
        doc["users"] = list(users)
    return doc


def split_interface_document(data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = dict(data)
    peers_raw = payload.pop("peers", None)
    peers = [dict(item) for item in peers_raw if isinstance(item, dict)] if isinstance(peers_raw, list) else []
    return payload, peers


def split_server_document(data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = dict(data)
    users_raw = payload.pop("users", None)
    users = [dict(item) for item in users_raw if isinstance(item, dict)] if isinstance(users_raw, list) else []
    return payload, users


def parent_type_for_kind(kind: str) -> str:
    if kind == "interface":
        return PARENT_INTERFACE
    if kind == "server":
        return PARENT_SERVER
    return ""


def quota_row_to_document(row: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": row.client_id,
        "node_id": row.client_id,
        "client_link_uuid": row.protocol_id or row.client_id,
        "email": row.email or "",
        "volume": row.volume,
        "_incoming": int(row.baseline_incoming or 0),
        "_outgoing": int(row.baseline_outgoing or 0),
    }
    if row.expires_at is not None:
        data["expires_at"] = row.expires_at
    if row.max_connection is not None:
        data["max_connection"] = row.max_connection
    if row.inbound_id:
        data["inbound_id"] = row.inbound_id
    if row.inbound_tag:
        data["inbound_tag"] = row.inbound_tag
    if row.is_enabled is not None:
        data["is_enabled"] = bool(row.is_enabled)
    return data
