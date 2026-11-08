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
    """Keep the panel ``node_id`` as the only client primary key.

    ``client_link_uuid`` is the protocol id (VLESS/VMess UUID) and is the value
    written into Xray. It is not a second client identity. A new primary key is
    created only when the caller supplied none.
    """
    row = dict(client)
    prior_agent = _trim(row.get("agent_id"))
    explicit_core = _trim(row.pop("client_link_uuid", None))
    supplied_node = _trim(row.pop("node_id", None))
    incoming_id = _trim(row.get("id") or "")

    # Older panels sent the protocol UUID as ``node_id`` and the stored primary
    # key as ``id``. Keep that primary key. Do not mint another one.
    legacy_split = bool(
        explicit_core
        and supplied_node
        and incoming_id
        and supplied_node == explicit_core
        and incoming_id != explicit_core
    )
    if legacy_split:
        primary_key = incoming_id
        protocol_id = explicit_core
    elif supplied_node:
        primary_key = supplied_node
        protocol_id = explicit_core or (incoming_id if incoming_id and incoming_id != supplied_node else supplied_node)
    elif incoming_id:
        primary_key = incoming_id
        protocol_id = explicit_core or incoming_id
    elif prior_agent:
        primary_key = prior_agent
        protocol_id = explicit_core or prior_agent
    else:
        primary_key = str(uuid.uuid4())
        protocol_id = explicit_core or primary_key

    row["node_id"] = primary_key
    row["agent_id"] = primary_key
    if store_kind == "xray":
        row["client_link_uuid"] = protocol_id
        row["id"] = protocol_id
    else:
        row["id"] = primary_key
        if explicit_core:
            row["client_link_uuid"] = explicit_core
    return row


def existing_quota_for_push(index: dict[str, Any] | None, client: dict[str, Any]) -> dict[str, Any] | None:
    """Quota document already stored for this push.

    Lookup uses the protocol UUID and email. A ``node_id`` that is only the
    protocol UUID must not hide a document whose primary key is different.
    """
    if not isinstance(index, dict):
        return None

    protocol = _trim(client.get("client_link_uuid") or "")
    node_id = _trim(client.get("node_id") or "")
    incoming = _trim(client.get("id") or "")
    email = _trim(client.get("email") or "")
    protocol_id = protocol
    if not protocol_id and incoming and incoming != node_id:
        protocol_id = incoming
    elif not protocol_id and incoming and incoming == node_id:
        protocol_id = incoming

    meta = select_quota_meta(index, protocol_id=protocol_id, email=email)
    if meta is None and node_id and node_id != protocol_id:
        found = index.get(f"n:{node_id}")
        meta = found if isinstance(found, dict) else None
    return meta if isinstance(meta, dict) else None


def preserve_pushed_identity(client: dict[str, Any], index: dict[str, Any] | None) -> dict[str, Any]:
    """Keep the stored document primary key when the panel repeats the protocol UUID.

    Older panels sent that protocol UUID as ``node_id`` and the document primary
    key as ``id``. That ``id`` stays the primary key. This does not mint one.
    """
    row = dict(client)
    protocol = _trim(row.get("client_link_uuid") or "")
    node_id = _trim(row.get("node_id") or "")
    incoming = _trim(row.get("id") or "")
    meta = existing_quota_for_push(index, row)
    stored = ""
    stored_link = ""
    if meta is not None:
        email = _trim(row.get("email") or "")
        stored = billing_client_id(meta, protocol_id=protocol or incoming, email=email)
        stored_link = _trim(meta.get("client_link_uuid") or "")

    if stored and protocol and stored_link == protocol and stored != protocol:
        row["node_id"] = stored
        row["agent_id"] = stored
        row["client_link_uuid"] = stored_link
        return row

    if protocol and node_id == protocol and incoming and incoming != protocol:
        row["node_id"] = incoming
        row["agent_id"] = incoming
        return row

    if stored and stored != protocol and (not node_id or node_id == protocol):
        row["node_id"] = stored
        row["agent_id"] = stored
        if stored_link and stored_link != stored:
            row["client_link_uuid"] = stored_link
    return row


def publish_document_identity(
    client: dict[str, Any],
    meta: dict[str, Any],
    *,
    protocol_id: str,
    email: str,
) -> None:
    """Expose the document primary key as ``node_id`` without replacing the core id.

    Xray ``id`` stays the protocol UUID. ``node_id`` is the document primary key.
    """
    primary_key = billing_client_id(meta, protocol_id=protocol_id, email=email)
    link = _trim(meta.get("client_link_uuid") or "")
    if not link and protocol_id and protocol_id != primary_key:
        link = protocol_id
    if primary_key:
        client["node_id"] = primary_key
        client["agent_id"] = primary_key
    if link:
        client["client_link_uuid"] = link


def keep_stored_identity_fields(merged: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
    """An update keeps the stored primary key and protocol id."""
    for key in ("id", "node_id", "agent_id"):
        current = _trim(before.get(key))
        if current:
            merged[key] = before.get(key)
    if not _trim(merged.get("node_id")) and _trim(merged.get("id")):
        merged["node_id"] = merged.get("id")
        merged["agent_id"] = merged.get("id")
    link = _trim(before.get("client_link_uuid"))
    if link:
        merged["client_link_uuid"] = before.get("client_link_uuid")
    return merged


def panel_client_response(client: dict[str, Any]) -> dict[str, Any]:
    """Return the panel primary key as both ``id`` and ``node_id``.

    ``client_link_uuid`` is included only so the core can keep its own protocol
    id. It is not an alternate client key.
    """
    primary_key = _trim(client.get("node_id") or client.get("agent_id") or "")
    protocol_id = _trim(client.get("id") or "")
    core_id = _trim(client.get("client_link_uuid") or "")
    email = _trim(client.get("email") or "")

    if not primary_key and not (core_id and protocol_id and protocol_id == core_id):
        primary_key = protocol_id
    if not core_id and protocol_id and protocol_id != primary_key:
        core_id = protocol_id

    out: dict[str, Any] = {
        "id": primary_key,
        "node_id": primary_key,
    }
    if core_id:
        out["client_link_uuid"] = core_id
    if email:
        out["email"] = email
    core = _trim(client.get("core") or "")
    if core:
        out["core"] = core
    if "core_persisted" in client:
        out["core_persisted"] = bool(client.get("core_persisted"))
    return out


def identity_lookup_keys(client: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for value in (
        client.get("agent_id"),
        client.get("node_id"),
        client.get("id"),
        client.get("client_link_uuid"),
        client.get("email"),
        client.get("password"),
    ):
        text = _trim(value)
        if text:
            keys.add(text)
    return keys


def billing_client_id(meta: dict[str, Any] | None, *, protocol_id: str, email: str) -> str:
    """Traffic rows are keyed only by the panel ``node_id`` primary key.

    Email and the Xray UUID are never returned. Pre-migration quota documents
    stored that primary key in ``id`` and the protocol UUID in ``node_id``.
    """
    del email
    if not isinstance(meta, dict):
        return ""

    node_id = _trim(meta.get("node_id") or "")
    stored_id = _trim(meta.get("id") or "")
    link = _trim(meta.get("client_link_uuid") or "")
    legacy = _trim(meta.get("agent_id") or meta.get("primary_key") or "")

    if legacy and legacy not in {node_id, link, ""}:
        return legacy
    if link and stored_id and stored_id != link and (not node_id or node_id == link):
        return stored_id
    # Quota rows written before node_id was the primary key: ``id`` is the key
    # and ``node_id`` still holds the protocol UUID.
    if not link and stored_id and node_id and stored_id != node_id:
        return stored_id
    if node_id and link and node_id != link:
        return node_id
    if node_id:
        return node_id
    if stored_id and stored_id != _trim(protocol_id):
        return stored_id
    # A legacy row whose only stored key is the protocol UUID keeps that key.
    # Callers must not invent a replacement, and must not prefer this row when
    # another document has a distinct node_id for the same Xray user.
    if stored_id:
        return stored_id
    return ""


def select_quota_meta(
    index: dict[str, Any] | None,
    *,
    protocol_id: str,
    email: str,
) -> dict[str, Any] | None:
    """Quota document for an Xray user.

    ``l:`` is the protocol UUID and ``e:`` is the email. ``n:`` / ``i:`` are
    primary keys. A hit on ``n:{protocol uuid}`` is only a legacy row whose
    stored key still equals that UUID, or a pre-migration row that kept the
    protocol UUID in ``node_id``. A document with a different ``node_id`` wins.
    This does not create or rewrite identifiers.
    """
    if not isinstance(index, dict):
        return None

    protocol_id = _trim(protocol_id)
    email = _trim(email)
    ordered: list[dict[str, Any]] = []

    def add(row: Any) -> None:
        if isinstance(row, dict) and row not in ordered:
            ordered.append(row)

    if protocol_id:
        add(index.get(f"l:{protocol_id}"))
    if email:
        add(index.get(f"e:{email}"))
    if protocol_id:
        add(index.get(f"i:{protocol_id}"))
        add(index.get(f"n:{protocol_id}"))

    distinct: dict[str, Any] | None = None
    fallback: dict[str, Any] | None = None
    for row in ordered:
        key = billing_client_id(row, protocol_id=protocol_id, email=email)
        if not key:
            continue
        if fallback is None:
            fallback = row
        if key != protocol_id and distinct is None:
            distinct = row
    return distinct or fallback
