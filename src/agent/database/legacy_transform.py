from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from agent.database.models.core import DEFAULT_CORE_KEYS
from agent.logutil import get_logger

_log = get_logger("migrate.legacy")

ARTIFACT_KINDS = frozenset({"settings", "catalog", "location", "egress_state"})

META_PEER_KEYS = frozenset({
    "public_key",
    "allowed_ips",
    "persistent_keepalive",
    "obfuscation",
    "client_link_uuid",
    "flow",
    "password",
    "username",
    "address",
    "linked_peer_id",
    "linked_core",
    "linked_interface_id",
    "exit_interface",
    "volume",
    "incoming",
    "outgoing",
    "max_connection",
    "expires_at",
    "handshake_at",
    "primary_key",
    "agent_id",
})

CLIENT_TOP_KEYS = frozenset({
    "id",
    "node_id",
    "email",
    "name",
    "is_enabled",
    "disabled_reason",
    "disabled_at",
    "inbound_id",
    "inbound_tag",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _ensure_core(conn: Connection, core: str) -> None:
    if not core:
        return
    conn.execute(text("INSERT OR IGNORE INTO cores (id) VALUES (:id)"), {"id": core})


def _split_member_meta(member: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    top = {k: member[k] for k in CLIENT_TOP_KEYS if k in member}
    meta = {k: member[k] for k in member if k not in CLIENT_TOP_KEYS}
    for key in list(meta.keys()):
        if key in CLIENT_TOP_KEYS:
            meta.pop(key, None)
    return top, meta


def _client_id(member: dict[str, Any], *, fallback: str = "") -> str:
    return str(
        member.get("node_id") or member.get("id") or fallback or ""
    ).strip()


def _upsert_client(
    conn: Connection,
    *,
    core: str,
    client_id: str,
    parent_type: str,
    parent_core: str | None,
    parent_id: str | None,
    role: str,
    top: dict[str, Any],
    meta: dict[str, Any],
) -> None:
    if not client_id:
        return
    email = str(top.get("email") or meta.get("email") or "").strip() or None
    name = str(top.get("name") or "").strip() or None
    is_enabled = bool(top.get("is_enabled", True))
    disabled_reason = str(top.get("disabled_reason") or "").strip() or None
    disabled_at = str(top.get("disabled_at") or "").strip() or None
    parent_interface_core_id = parent_core if parent_type == "interface" else None
    parent_interface_id = parent_id if parent_type == "interface" else None
    parent_server_core_id = parent_core if parent_type == "server" else None
    parent_server_id = parent_id if parent_type == "server" else None
    conn.execute(
        text(
            """
            INSERT INTO clients (
                core_id, id, parent_type,
                parent_interface_core_id, parent_interface_id,
                parent_server_core_id, parent_server_id,
                email, name, is_enabled, disabled_reason, disabled_at,
                role, meta, updated_at
            ) VALUES (
                :core_id, :id, :parent_type,
                :p_iface_core, :p_iface_id,
                :p_srv_core, :p_srv_id,
                :email, :name, :is_enabled, :disabled_reason, :disabled_at,
                :role, :meta, :updated_at
            )
            ON CONFLICT(core_id, id) DO UPDATE SET
                parent_type = excluded.parent_type,
                parent_interface_core_id = excluded.parent_interface_core_id,
                parent_interface_id = excluded.parent_interface_id,
                parent_server_core_id = excluded.parent_server_core_id,
                parent_server_id = excluded.parent_server_id,
                email = excluded.email,
                name = excluded.name,
                is_enabled = excluded.is_enabled,
                disabled_reason = excluded.disabled_reason,
                disabled_at = excluded.disabled_at,
                role = excluded.role,
                meta = excluded.meta,
                updated_at = excluded.updated_at
            """
        ),
        {
            "core_id": core,
            "id": client_id,
            "parent_type": parent_type or "",
            "p_iface_core": parent_interface_core_id,
            "p_iface_id": parent_interface_id,
            "p_srv_core": parent_server_core_id,
            "p_srv_id": parent_server_id,
            "email": email,
            "name": name,
            "is_enabled": is_enabled,
            "disabled_reason": disabled_reason,
            "disabled_at": disabled_at,
            "role": role,
            "meta": json.dumps(meta, ensure_ascii=False),
            "updated_at": _now(),
        },
    )


def _upsert_quota(conn: Connection, core: str, data: dict[str, Any], doc_id: str) -> None:
    client_id = _client_id(data, fallback=doc_id)
    if not client_id:
        return
    _ensure_core(conn, core)
    top, meta = _split_member_meta(data)
    _upsert_client(
        conn,
        core=core,
        client_id=client_id,
        parent_type="",
        parent_core=None,
        parent_id=None,
        role="quota",
        top=top,
        meta=meta,
    )
    volume = data.get("volume")
    try:
        volume = int(volume) if volume is not None else None
    except (TypeError, ValueError):
        volume = None
    if volume is not None and volume <= 0:
        volume = None
    baseline_in = int(data.get("_incoming") or 0)
    baseline_out = int(data.get("_outgoing") or 0)
    email = str(data.get("email") or "").strip() or None
    protocol_id = str(data.get("client_link_uuid") or data.get("id") or "").strip() or None
    conn.execute(
        text(
            """
            INSERT INTO quotas (
                core_id, client_id, volume, baseline_incoming, baseline_outgoing,
                expires_at, max_connection, inbound_id, inbound_tag,
                email, protocol_id, is_enabled, updated_at
            ) VALUES (
                :core_id, :client_id, :volume, :bi, :bo,
                :expires_at, :max_connection, :inbound_id, :inbound_tag,
                :email, :protocol_id, :is_enabled, :updated_at
            )
            ON CONFLICT(core_id, client_id) DO UPDATE SET
                volume = excluded.volume,
                baseline_incoming = excluded.baseline_incoming,
                baseline_outgoing = excluded.baseline_outgoing,
                expires_at = excluded.expires_at,
                max_connection = excluded.max_connection,
                inbound_id = excluded.inbound_id,
                inbound_tag = excluded.inbound_tag,
                email = excluded.email,
                protocol_id = excluded.protocol_id,
                is_enabled = excluded.is_enabled,
                updated_at = excluded.updated_at
            """
        ),
        {
            "core_id": core,
            "client_id": client_id,
            "volume": volume,
            "bi": baseline_in,
            "bo": baseline_out,
            "expires_at": data.get("expires_at"),
            "max_connection": data.get("max_connection"),
            "inbound_id": str(data.get("inbound_id") or "").strip() or None,
            "inbound_tag": str(data.get("inbound_tag") or "").strip() or None,
            "email": email,
            "protocol_id": protocol_id,
            "is_enabled": 1 if data.get("is_enabled", True) else 0,
            "updated_at": _now(),
        },
    )


def migrate_documents_to_relational(conn: Connection) -> int:
    """Transform legacy ``documents`` rows into relational tables. Returns rows processed."""
    inspector_query = conn.execute(
        text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='documents'"
        )
    )
    if inspector_query.fetchone() is None:
        return 0

    for core in DEFAULT_CORE_KEYS:
        conn.execute(text("INSERT OR IGNORE INTO cores (id) VALUES (:id)"), {"id": core})

    rows = conn.execute(
        text("SELECT core, kind, doc_id, data FROM documents ORDER BY core, kind, doc_id")
    ).fetchall()
    total = len(rows)
    if total:
        _log.info("legacy documents migration starting rows=%s", total)
    count = 0
    for row in rows:
        core = str(row[0] or "")
        kind = str(row[1] or "")
        doc_id = str(row[2] or "")
        data = _loads(str(row[3] or ""))
        if not core or not kind or not doc_id:
            continue
        _ensure_core(conn, core)
        count += 1
        if count == 1 or count % 500 == 0 or count == total:
            _log.info("legacy documents migration progress=%s/%s", count, total)

        if kind == "interface":
            peers = data.pop("peers", None)
            config = dict(data)
            config.pop("users", None)
            conn.execute(
                text(
                    """
                    INSERT INTO interfaces (core_id, id, config, updated_at)
                    VALUES (:core_id, :id, :config, :updated_at)
                    ON CONFLICT(core_id, id) DO UPDATE SET
                        config = excluded.config,
                        updated_at = excluded.updated_at
                    """
                ),
                {
                    "core_id": core,
                    "id": doc_id,
                    "config": json.dumps(config, ensure_ascii=False),
                    "updated_at": _now(),
                },
            )
            if isinstance(peers, list):
                for peer in peers:
                    if not isinstance(peer, dict):
                        continue
                    top, meta = _split_member_meta(peer)
                    cid = _client_id(peer)
                    _upsert_client(
                        conn,
                        core=core,
                        client_id=cid,
                        parent_type="interface",
                        parent_core=core,
                        parent_id=doc_id,
                        role="peer",
                        top=top,
                        meta=meta,
                    )
        elif kind == "server":
            users = data.pop("users", None)
            config = dict(data)
            conn.execute(
                text(
                    """
                    INSERT INTO servers (core_id, id, config, updated_at)
                    VALUES (:core_id, :id, :config, :updated_at)
                    ON CONFLICT(core_id, id) DO UPDATE SET
                        config = excluded.config,
                        updated_at = excluded.updated_at
                    """
                ),
                {
                    "core_id": core,
                    "id": doc_id,
                    "config": json.dumps(config, ensure_ascii=False),
                    "updated_at": _now(),
                },
            )
            if isinstance(users, list):
                for user in users:
                    if not isinstance(user, dict):
                        continue
                    top, meta = _split_member_meta(user)
                    cid = _client_id(user)
                    _upsert_client(
                        conn,
                        core=core,
                        client_id=cid,
                        parent_type="server",
                        parent_core=core,
                        parent_id=doc_id,
                        role="user",
                        top=top,
                        meta=meta,
                    )
        elif kind == "client_quota":
            _upsert_quota(conn, core, data, doc_id)
        elif kind == "xray_disabled_client":
            top, meta = _split_member_meta(data)
            cid = _client_id(data, fallback=doc_id)
            top["is_enabled"] = False
            if "inbound_id" in data:
                top["inbound_id"] = data.get("inbound_id")
            if "inbound_tag" in data:
                top["inbound_tag"] = data.get("inbound_tag")
            _upsert_client(
                conn,
                core=core,
                client_id=cid,
                parent_type="",
                parent_core=None,
                parent_id=None,
                role="xray_disabled",
                top=top,
                meta=meta,
            )
        elif kind in ARTIFACT_KINDS or kind == "egress_state":
            conn.execute(
                text(
                    """
                    INSERT INTO core_artifacts (core_id, kind, artifact_id, data, updated_at)
                    VALUES (:core_id, :kind, :artifact_id, :data, :updated_at)
                    ON CONFLICT(core_id, kind, artifact_id) DO UPDATE SET
                        data = excluded.data,
                        updated_at = excluded.updated_at
                    """
                ),
                {
                    "core_id": core,
                    "kind": kind,
                    "artifact_id": doc_id,
                    "data": json.dumps(data, ensure_ascii=False),
                    "updated_at": _now(),
                },
            )
        else:
            conn.execute(
                text(
                    """
                    INSERT INTO core_artifacts (core_id, kind, artifact_id, data, updated_at)
                    VALUES (:core_id, :kind, :artifact_id, :data, :updated_at)
                    ON CONFLICT(core_id, kind, artifact_id) DO UPDATE SET
                        data = excluded.data,
                        updated_at = excluded.updated_at
                    """
                ),
                {
                    "core_id": core,
                    "kind": kind,
                    "artifact_id": doc_id,
                    "data": json.dumps(data, ensure_ascii=False),
                    "updated_at": _now(),
                },
            )

    conn.execute(text("DROP TABLE IF EXISTS documents"))
    conn.execute(text("DROP INDEX IF EXISTS documents_by_kind"))
    if total:
        _log.info("legacy documents migration complete rows=%s", count)
    return count
