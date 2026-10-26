from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiosqlite


class Store:
    """Single SQLite database for agent state (inbounds, peers, audit, meta)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = asyncio.Lock()
        self._conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA busy_timeout=2000")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._migrate()

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None

    def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Store is not open; await store.open() first")
        return self._conn

    async def _migrate(self) -> None:
        conn = self._connection()
        async with self._lock:
            await conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    core TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, kind, doc_id)
                );

                CREATE TABLE IF NOT EXISTS meta (
                    core TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (core, key)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS traffic_ack (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    incoming INTEGER NOT NULL DEFAULT 0,
                    outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                );

                CREATE TABLE IF NOT EXISTS traffic_pending (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    delta_incoming INTEGER NOT NULL DEFAULT 0,
                    delta_outgoing INTEGER NOT NULL DEFAULT 0,
                    current_incoming INTEGER NOT NULL DEFAULT 0,
                    current_outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                );

                DROP TABLE IF EXISTS core_errors;
                """
            )
            await conn.commit()

    async def list_docs(self, core: str, kind: str) -> list[dict[str, Any]]:
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT data FROM documents WHERE core = ? AND kind = ? ORDER BY doc_id",
                (core, kind),
            )
            rows = await cursor.fetchall()
        return [json.loads(row["data"]) for row in rows]

    async def get_doc(self, core: str, kind: str, doc_id: str) -> dict[str, Any] | None:
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT data FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                (core, kind, str(doc_id)),
            )
            row = await cursor.fetchone()
        return json.loads(row["data"]) if row else None

    async def put_doc(self, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        async with self._lock:
            await self._connection().execute(
                """
                INSERT INTO documents (core, kind, doc_id, data, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, kind, doc_id) DO UPDATE SET
                    data = excluded.data,
                    updated_at = datetime('now')
                """,
                (core, kind, str(doc_id), payload),
            )
            await self._connection().commit()

    async def delete_doc(self, core: str, kind: str, doc_id: str) -> bool:
        async with self._lock:
            cursor = await self._connection().execute(
                "DELETE FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                (core, kind, str(doc_id)),
            )
            await self._connection().commit()
            return cursor.rowcount > 0

    async def write_docs(
        self,
        core: str,
        kind: str,
        puts: list[tuple[str, dict[str, Any]]],
        deletes: list[str] | None = None,
    ) -> None:
        async with self._lock:
            conn = self._connection()
            for doc_id, data in puts:
                payload = json.dumps(data, ensure_ascii=False)
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(core, kind, doc_id) DO UPDATE SET
                        data = excluded.data,
                        updated_at = datetime('now')
                    """,
                    (core, kind, str(doc_id), payload),
                )
            for doc_id in deletes or []:
                if not str(doc_id).strip():
                    continue
                await conn.execute(
                    "DELETE FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                    (core, kind, str(doc_id)),
                )
            await conn.commit()

    async def replace_docs(
        self,
        core: str,
        kind: str,
        docs: list[dict[str, Any]],
        id_key: str = "id",
    ) -> None:
        async with self._lock:
            conn = self._connection()
            await conn.execute(
                "DELETE FROM documents WHERE core = ? AND kind = ?",
                (core, kind),
            )
            for doc in docs:
                doc_id = str(doc.get(id_key, ""))
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    """,
                    (core, kind, doc_id, json.dumps(doc, ensure_ascii=False)),
                )
            await conn.commit()

    async def get_meta(self, core: str, key: str, default: Any = None) -> Any:
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT value FROM meta WHERE core = ? AND key = ?",
                (core, key),
            )
            row = await cursor.fetchone()
        if row is None:
            return default
        return json.loads(row["value"])

    async def set_meta(self, core: str, key: str, value: Any) -> None:
        async with self._lock:
            await self._connection().execute(
                """
                INSERT INTO meta (core, key, value) VALUES (?, ?, ?)
                ON CONFLICT(core, key) DO UPDATE SET value = excluded.value
                """,
                (core, key, json.dumps(value, ensure_ascii=False)),
            )
            await self._connection().commit()

    async def dump_documents(self) -> list[dict[str, Any]]:
        """Every stored document. Traffic and audit tables are not included."""
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT core, kind, doc_id, data FROM documents ORDER BY core, kind, doc_id"
            )
            rows = await cursor.fetchall()
        dumped: list[dict[str, Any]] = []
        for row in rows:
            try:
                data = json.loads(row["data"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            dumped.append({
                "core": str(row["core"]),
                "kind": str(row["kind"]),
                "doc_id": str(row["doc_id"]),
                "data": data,
            })
        return dumped

    async def replace_all_documents(self, rows: list[dict[str, Any]]) -> int:
        """Replace the document table with a transferred snapshot."""
        async with self._lock:
            conn = self._connection()
            await conn.execute("DELETE FROM documents")
            count = 0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                core = str(row.get("core") or "").strip()
                kind = str(row.get("kind") or "").strip()
                doc_id = str(row.get("doc_id") or "").strip()
                data = row.get("data")
                if (
                    not core
                    or not kind
                    or not doc_id
                    or not isinstance(data, dict)
                    or len(core) > 64
                    or len(kind) > 64
                    or len(doc_id) > 512
                ):
                    continue
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    """,
                    (core, kind, doc_id, json.dumps(data, ensure_ascii=False)),
                )
                count += 1
            await conn.commit()
            return count

    async def dump_meta(self) -> list[dict[str, Any]]:
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT core, key, value FROM meta ORDER BY core, key"
            )
            rows = await cursor.fetchall()
        dumped: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(row["value"])
            except (TypeError, json.JSONDecodeError):
                continue
            dumped.append({
                "core": str(row["core"]),
                "key": str(row["key"]),
                "value": value,
            })
        return dumped

    async def replace_all_meta(self, rows: list[dict[str, Any]]) -> int:
        async with self._lock:
            conn = self._connection()
            await conn.execute("DELETE FROM meta")
            count = 0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                core = str(row.get("core") or "").strip()
                key = str(row.get("key") or "").strip()
                if not core or not key or len(core) > 64 or len(key) > 128 or "value" not in row:
                    continue
                await conn.execute(
                    "INSERT INTO meta (core, key, value) VALUES (?, ?, ?)",
                    (core, key, json.dumps(row.get("value"), ensure_ascii=False)),
                )
                count += 1
            await conn.commit()
            return count

    async def get_traffic_ack(self, core: str, client_key: str) -> dict[str, int] | None:
        async with self._lock:
            cursor = await self._connection().execute(
                """
                SELECT incoming, outgoing FROM traffic_ack
                WHERE core = ? AND client_key = ?
                """,
                (core, client_key),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return {"incoming": int(row["incoming"]), "outgoing": int(row["outgoing"])}

    async def set_traffic_ack(
        self,
        core: str,
        client_key: str,
        incoming: int,
        outgoing: int,
    ) -> None:
        async with self._lock:
            await self._connection().execute(
                """
                INSERT INTO traffic_ack (core, client_key, incoming, outgoing, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    incoming = excluded.incoming,
                    outgoing = excluded.outgoing,
                    updated_at = datetime('now')
                """,
                (core, client_key, incoming, outgoing),
            )
            await self._connection().commit()

    async def delete_traffic_ack(self, core: str, client_key: str) -> None:
        async with self._lock:
            await self._connection().execute(
                "DELETE FROM traffic_ack WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            await self._connection().commit()

    async def upsert_traffic_pending(
        self,
        core: str,
        client_key: str,
        delta_incoming: int,
        delta_outgoing: int,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        async with self._lock:
            await self._connection().execute(
                """
                INSERT INTO traffic_pending (
                    core, client_key,
                    delta_incoming, delta_outgoing,
                    current_incoming, current_outgoing,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    delta_incoming = excluded.delta_incoming,
                    delta_outgoing = excluded.delta_outgoing,
                    current_incoming = excluded.current_incoming,
                    current_outgoing = excluded.current_outgoing,
                    updated_at = datetime('now')
                """,
                (
                    core,
                    client_key,
                    delta_incoming,
                    delta_outgoing,
                    current_incoming,
                    current_outgoing,
                ),
            )
            await self._connection().commit()

    async def delete_traffic_pending(self, core: str, client_key: str) -> None:
        async with self._lock:
            await self._connection().execute(
                "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            await self._connection().commit()

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        async with self._lock:
            cursor = await self._connection().execute(
                """
                SELECT core, client_key, delta_incoming, delta_outgoing,
                       current_incoming, current_outgoing, updated_at
                FROM traffic_pending
                WHERE core = ? AND client_key = ?
                """,
                (core, client_key),
            )
            row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_traffic_pending(self) -> list[dict[str, Any]]:
        async with self._lock:
            cursor = await self._connection().execute(
                """
                SELECT core, client_key, delta_incoming, delta_outgoing,
                       current_incoming, current_outgoing, updated_at
                FROM traffic_pending
                ORDER BY core, client_key
                """,
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def count_traffic_pending(self) -> int:
        async with self._lock:
            cursor = await self._connection().execute(
                "SELECT COUNT(*) AS c FROM traffic_pending",
            )
            row = await cursor.fetchone()
        return int(row["c"]) if row else 0

    async def apply_traffic_sample(self, plan) -> dict[str, int]:
        async with self._lock:
            conn = self._connection()
            acks: dict[tuple[str, str], tuple[int, int]] = {}
            cursor = await conn.execute(
                "SELECT core, client_key, incoming, outgoing FROM traffic_ack",
            )
            async for row in cursor:
                acks[(str(row["core"]), str(row["client_key"]))] = (
                    int(row["incoming"]),
                    int(row["outgoing"]),
                )
            pending: dict[tuple[str, str], dict[str, int]] = {}
            cursor = await conn.execute(
                """
                SELECT core, client_key, delta_incoming, delta_outgoing,
                       current_incoming, current_outgoing
                FROM traffic_pending
                """,
            )
            async for row in cursor:
                pending[(str(row["core"]), str(row["client_key"]))] = {
                    "delta_incoming": int(row["delta_incoming"]),
                    "delta_outgoing": int(row["delta_outgoing"]),
                    "current_incoming": int(row["current_incoming"]),
                    "current_outgoing": int(row["current_outgoing"]),
                }
            try:
                writes = plan(acks, pending)
                await self._write_traffic_plan(conn, writes)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
            stats = dict(writes.get("stats") or {})
            counted = await conn.execute("SELECT COUNT(*) AS c FROM traffic_pending")
            row = await counted.fetchone()
            stats["pending"] = int(row["c"]) if row else 0
            return stats

    async def _write_traffic_plan(self, conn: aiosqlite.Connection, writes: dict[str, Any]) -> None:
        for core, client_key, incoming, outgoing in writes.get("ack_upserts") or []:
            await conn.execute(
                """
                INSERT INTO traffic_ack (core, client_key, incoming, outgoing, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    incoming = excluded.incoming,
                    outgoing = excluded.outgoing,
                    updated_at = datetime('now')
                """,
                (core, client_key, int(incoming), int(outgoing)),
            )
        for core, client_key in writes.get("ack_deletes") or []:
            await conn.execute(
                "DELETE FROM traffic_ack WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
        for item in writes.get("pending_upserts") or []:
            await conn.execute(
                """
                INSERT INTO traffic_pending (
                    core, client_key,
                    delta_incoming, delta_outgoing,
                    current_incoming, current_outgoing,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    delta_incoming = excluded.delta_incoming,
                    delta_outgoing = excluded.delta_outgoing,
                    current_incoming = excluded.current_incoming,
                    current_outgoing = excluded.current_outgoing,
                    updated_at = datetime('now')
                """,
                (
                    item["core"],
                    item["client_key"],
                    int(item["delta_incoming"]),
                    int(item["delta_outgoing"]),
                    int(item["current_incoming"]),
                    int(item["current_outgoing"]),
                ),
            )
        for core, client_key in writes.get("pending_deletes") or []:
            await conn.execute(
                "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
        meta = writes.get("meta")
        if isinstance(meta, tuple) and len(meta) == 3:
            core, key, value = meta
            await conn.execute(
                """
                INSERT INTO meta (core, key, value) VALUES (?, ?, ?)
                ON CONFLICT(core, key) DO UPDATE SET value = excluded.value
                """,
                (core, key, json.dumps(value, ensure_ascii=False)),
            )

    async def ack_traffic_rows(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        async with self._lock:
            conn = self._connection()
            seen: set[tuple[str, str]] = set()
            for row in rows:
                key = (str(row["core"]), str(row["client_key"]))
                if key in seen:
                    continue
                seen.add(key)
                await conn.execute(
                    """
                    INSERT INTO traffic_ack (core, client_key, incoming, outgoing, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(core, client_key) DO UPDATE SET
                        incoming = excluded.incoming,
                        outgoing = excluded.outgoing,
                        updated_at = datetime('now')
                    """,
                    (
                        key[0],
                        key[1],
                        int(row["current_incoming"]),
                        int(row["current_outgoing"]),
                    ),
                )
                await conn.execute(
                    "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                    key,
                )
            await conn.commit()

    async def audit(self, action: str, resource: str, detail: str = "") -> None:
        from datetime import datetime, timezone

        async with self._lock:
            await self._connection().execute(
                "INSERT INTO audit_log (ts, action, resource, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), action, resource, detail),
            )
            await self._connection().commit()
