"""Point quota documents and traffic rows at the existing panel node_id.

The previous quota migration stored the protocol UUID in ``node_id`` and the
primary key in ``id``. This step swaps that naming without inventing ids:
``node_id`` becomes the primary key, ``client_link_uuid`` keeps the protocol
UUID, and traffic watermarks move with the row.

No table is dropped. A backup is taken before the first rewrite and is never
overwritten. If that backup cannot be created, the database is left unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.db import Store
from agent.logutil import get_logger

_QUOTA_KIND = "client_quota"
_log = get_logger("quota.node_id")


def _trim(value: Any) -> str:
    return str(value or "").strip()


def _counter(data: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(data.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _identity(doc_id: str, data: dict[str, Any]) -> tuple[str, str]:
    """Return ``(primary_key, protocol_id)`` using only values already stored."""
    stored = _trim(data.get("id"))
    node_id = _trim(data.get("node_id"))
    link = _trim(data.get("client_link_uuid"))
    legacy = _trim(data.get("agent_id") or data.get("primary_key"))
    doc_id = _trim(doc_id)

    if legacy and legacy not in {node_id, link, ""}:
        primary = legacy
        protocol = link or (node_id if node_id and node_id != primary else stored)
    elif link and stored and stored != link and (not node_id or node_id == link):
        primary = stored
        protocol = link
    elif not link and stored and node_id and stored != node_id:
        primary = stored
        protocol = node_id
    elif node_id:
        primary = node_id
        protocol = link or (stored if stored and stored != node_id else node_id)
    elif stored:
        primary = stored
        protocol = link or stored
    else:
        primary = doc_id
        protocol = link or doc_id

    if not protocol:
        protocol = primary
    return primary, protocol


def _document_needs_rewrite(doc_id: str, data: dict[str, Any], primary: str, protocol: str) -> bool:
    if _trim(doc_id) != primary:
        return True
    if _trim(data.get("id")) != primary or _trim(data.get("node_id")) != primary:
        return True
    if "agent_id" in data or "primary_key" in data:
        return True
    if protocol and protocol != primary and _trim(data.get("client_link_uuid")) != protocol:
        return True
    return False


def _merge_payload(rows: list[dict[str, Any]], primary: str, protocol: str) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: (0 if _trim(row.get("doc_id")) == primary else 1, -len(row["data"])))
    merged: dict[str, Any] = {}
    for row in ordered:
        for key, value in row["data"].items():
            if key not in merged or merged[key] in (None, ""):
                merged[key] = value
    for key in ("_incoming", "_outgoing"):
        if any(key in row["data"] for row in rows):
            merged[key] = max(_counter(row["data"], key) for row in rows)
    volumes = []
    for row in rows:
        if "volume" not in row["data"] or row["data"].get("volume") in (None, ""):
            continue
        volumes.append(_counter(row["data"], "volume"))
    if volumes:
        merged["volume"] = max(volumes)
    merged.pop("agent_id", None)
    merged.pop("primary_key", None)
    merged["id"] = primary
    merged["node_id"] = primary
    if protocol:
        merged["client_link_uuid"] = protocol
    return merged


def plan_node_id_primary_key(
    documents: list[dict[str, Any]],
    acks: dict[tuple[str, str], tuple[int, int]],
    pending: dict[tuple[str, str], dict[str, int]],
) -> dict[str, list[Any]]:
    """Pure rewrite plan. Traffic deltas are not summed."""
    quota_rows = [
        row
        for row in documents
        if str(row.get("kind") or "") == _QUOTA_KIND and isinstance(row.get("data"), dict)
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    protocol_of: dict[tuple[str, str], str] = {}
    for row in quota_rows:
        core = str(row.get("core") or "")
        primary, protocol = _identity(str(row.get("doc_id") or ""), row["data"])
        if not primary:
            continue
        key = (core, primary)
        grouped.setdefault(key, []).append(row)
        if protocol and protocol != primary:
            protocol_of[key] = protocol
        elif key not in protocol_of:
            protocol_of[key] = protocol

    primaries_by_core: dict[str, set[str]] = {}
    for core, primary in grouped:
        primaries_by_core.setdefault(core, set()).add(primary)

    puts: list[tuple[str, str, dict[str, Any]]] = []
    deletes: list[tuple[str, str]] = []
    aliases: dict[tuple[str, str], set[str]] = {}

    for key, rows in grouped.items():
        core, primary = key
        protocol = protocol_of.get(key) or primary
        payload = _merge_payload(rows, primary, protocol)
        doc_ids = {_trim(row.get("doc_id")) for row in rows}
        doc_ids.discard("")
        rewrite = any(_document_needs_rewrite(str(row.get("doc_id") or ""), row["data"], primary, protocol) for row in rows)
        current = next((row["data"] for row in rows if _trim(row.get("doc_id")) == primary), None)
        if rewrite and current != payload:
            puts.append((core, primary, payload))
        for doc_id in sorted(doc_ids - {primary}):
            if doc_id not in primaries_by_core.get(core, set()):
                deletes.append((core, doc_id))
        alias_values = set(doc_ids)
        alias_values.add(protocol)
        for row in rows:
            for field in ("id", "node_id", "client_link_uuid", "email", "agent_id", "primary_key"):
                alias_values.add(_trim(row["data"].get(field)))
        alias_values.discard("")
        alias_values.discard(primary)
        alias_values -= primaries_by_core.get(core, set())
        if alias_values:
            aliases[key] = alias_values

    ack_upserts: list[tuple[str, str, int, int]] = []
    ack_deletes: list[tuple[str, str]] = []
    pending_upserts: list[tuple[str, str, int, int, int, int]] = []
    pending_deletes: list[tuple[str, str]] = []

    for (core, primary), names in aliases.items():
        best_ack = acks.get((core, primary))
        ack_changed = False
        for name in sorted(names):
            alias_ack = acks.get((core, name))
            if alias_ack is None:
                continue
            if best_ack is None:
                best_ack = alias_ack
                ack_changed = True
            else:
                merged_ack = (max(best_ack[0], alias_ack[0]), max(best_ack[1], alias_ack[1]))
                ack_changed = ack_changed or merged_ack != best_ack
                best_ack = merged_ack
            ack_deletes.append((core, name))
        if ack_changed and best_ack is not None:
            ack_upserts.append((core, primary, best_ack[0], best_ack[1]))

        best_pending = pending.get((core, primary))
        pending_changed = False
        for name in sorted(names):
            alias_pending = pending.get((core, name))
            if alias_pending is None:
                continue
            alias_total = int(alias_pending["delta_incoming"]) + int(alias_pending["delta_outgoing"])
            best_total = -1
            if best_pending is not None:
                best_total = int(best_pending["delta_incoming"]) + int(best_pending["delta_outgoing"])
            if best_pending is None or alias_total > best_total:
                best_pending = alias_pending
                pending_changed = True
            pending_deletes.append((core, name))
        if pending_changed and best_pending is not None:
            pending_upserts.append((
                core,
                primary,
                int(best_pending["delta_incoming"]),
                int(best_pending["delta_outgoing"]),
                int(best_pending["current_incoming"]),
                int(best_pending["current_outgoing"]),
            ))

    return {
        "puts": puts,
        "deletes": deletes,
        "ack_upserts": ack_upserts,
        "ack_deletes": ack_deletes,
        "pending_upserts": pending_upserts,
        "pending_deletes": pending_deletes,
    }


def _backup_path(db_path: Path) -> Path:
    return db_path.with_name(db_path.name + ".bak-node-id-pk")


async def migrate_node_id_primary_key(store: Store) -> int:
    """Rewrite stored rows. Returns how many quota documents were written.

    Returns 0 without changing anything when the backup cannot be created.
    """
    documents = await store.list_doc_records(kind=_QUOTA_KIND)
    acks, pending = await store._traffic_books()
    plan = plan_node_id_primary_key(documents, acks, pending)
    changed = any(plan[key] for key in plan)
    if not changed:
        return 0

    backup = _backup_path(Path(store.path))
    try:
        await store.backup_database(backup)
    except Exception:
        _log.exception("node_id primary-key migration skipped; backup failed path=%s", backup)
        return 0
    if not backup.exists() or backup.stat().st_size <= 0:
        _log.error("node_id primary-key migration skipped; backup missing path=%s", backup)
        return 0

    await store.apply_node_id_rewrite(
        puts=plan["puts"],
        deletes=plan["deletes"],
        ack_upserts=plan["ack_upserts"],
        ack_deletes=plan["ack_deletes"],
        pending_upserts=plan["pending_upserts"],
        pending_deletes=plan["pending_deletes"],
    )
    _log.info(
        "node_id primary key applied docs=%s removed=%s backup=%s",
        len(plan["puts"]),
        len(plan["deletes"]),
        backup,
    )
    return len(plan["puts"]) or 1
