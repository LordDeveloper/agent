from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from agent.logutil import get_logger
from agent.runtime import RuntimeTrace

_sql_log = get_logger("sql")

# A few dozen peers already produce a document large enough to stall the loop
# if it is parsed inline. Smaller rows stay on the loop to avoid thread hops.
_JSON_OFFLOAD_BYTES = 64 * 1024


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _loads(raw: str) -> Any:
    return json.loads(raw)


def _json_is_large(value: Any) -> bool:
    if isinstance(value, str):
        return len(value) >= _JSON_OFFLOAD_BYTES
    if isinstance(value, list):
        return len(value) >= 32
    if isinstance(value, dict):
        for item in value.values():
            if isinstance(item, str) and len(item) >= _JSON_OFFLOAD_BYTES:
                return True
            if isinstance(item, list) and len(item) >= 32:
                return True
            if isinstance(item, dict):
                for nested in item.values():
                    if isinstance(nested, list) and len(nested) >= 32:
                        return True
                    if isinstance(nested, str) and len(nested) >= _JSON_OFFLOAD_BYTES:
                        return True
    return False


async def _encode_json(value: Any) -> str:
    if _json_is_large(value):
        return await asyncio.to_thread(_dumps, value)
    return _dumps(value)


async def _decode_json(raw: str) -> Any:
    if len(raw) >= _JSON_OFFLOAD_BYTES:
        return await asyncio.to_thread(_loads, raw)
    return _loads(raw)


class Store:
    """SQLite state for the agent.

    Writes use one connection and the write lock. Reads use a second connection
    and do not take that lock, so a large document commit cannot stall health
    and stats reads. WAL is enabled in ``open``.
    """

    def __init__(self, path: str | Path, *, slow_query_log_ms: float = 0.0):
        self.path = Path(path)
        self._slow_query_log_ms = max(0.0, float(slow_query_log_ms))
        self._lock = asyncio.Lock()
        self._conn: aiosqlite.Connection | None = None
        self._read: aiosqlite.Connection | None = None

    def _maybe_log_slow(self, phase: str, elapsed_ms: float, extra: str = "") -> None:
        if self._slow_query_log_ms <= 0 or elapsed_ms < self._slow_query_log_ms:
            return
        suffix = f" {extra}" if extra else ""
        _sql_log.warning("slow_sql phase=%s duration_ms=%.1f%s", phase, elapsed_ms, suffix)

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA busy_timeout=2000")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._migrate()
        self._read = await aiosqlite.connect(str(self.path), isolation_level=None)
        self._read.row_factory = aiosqlite.Row
        await self._read.execute("PRAGMA query_only=ON")
        await self._read.execute("PRAGMA busy_timeout=2000")
        await self._read.execute("PRAGMA foreign_keys=ON")

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None
        if self._read is not None:
            await self._read.close()
            self._read = None

    def _writer(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Store is not open; await store.open() first")
        return self._conn

    def _reader(self) -> aiosqlite.Connection:
        if self._read is None:
            raise RuntimeError("Store is not open; await store.open() first")
        return self._read

    @asynccontextmanager
    async def _writing(self) -> AsyncIterator[aiosqlite.Connection]:
        wait_started = time.perf_counter()
        with RuntimeTrace.span("db.wait"):
            await self._lock.acquire()
        self._maybe_log_slow("db.wait_lock", (time.perf_counter() - wait_started) * 1000)
        try:
            q_started = time.perf_counter()
            with RuntimeTrace.span("db.query"):
                yield self._writer()
            self._maybe_log_slow("db.write", (time.perf_counter() - q_started) * 1000)
        finally:
            self._lock.release()

    async def _fetch(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        q_started = time.perf_counter()
        with RuntimeTrace.span("db.query"):
            cursor = await self._reader().execute(sql, params)
            rows = await cursor.fetchall()
        self._maybe_log_slow(
            "db.read",
            (time.perf_counter() - q_started) * 1000,
            extra=f"sql={sql[:120]}",
        )
        return rows

    async def _migrate(self) -> None:
        async with self._writing() as conn:
            await conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    core TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, kind, doc_id)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS meta (
                    core TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (core, key)
                ) WITHOUT ROWID;

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
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS traffic_pending (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    delta_incoming INTEGER NOT NULL DEFAULT 0,
                    delta_outgoing INTEGER NOT NULL DEFAULT 0,
                    current_incoming INTEGER NOT NULL DEFAULT 0,
                    current_outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS traffic_identity (
                    core TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    canonical_key TEXT NOT NULL,
                    PRIMARY KEY (core, alias)
                ) WITHOUT ROWID;

                DROP TABLE IF EXISTS core_errors;
                """
            )
            await self._cluster_existing_tables(conn)
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS documents_by_kind ON documents (kind, core, doc_id)"
            )
            await conn.execute("ANALYZE documents")
            await conn.commit()

    async def _cluster_existing_tables(self, conn: aiosqlite.Connection) -> None:
        """Move composite-key tables off the rowid heap.

        A rowid table keeps the primary key in a separate index, so
        ``ORDER BY core, kind, doc_id`` and ``WHERE core = ? AND kind = ?``
        look up every JSON body by rowid. ``WITHOUT ROWID`` stores the row in
        primary-key order. ``CREATE TABLE IF NOT EXISTS`` does not change a
        table that was created by an older agent.
        """
        tables = {
            "documents": (
                """
                CREATE TABLE documents__clustered (
                    core TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, kind, doc_id)
                ) WITHOUT ROWID
                """,
                "core, kind, doc_id, data, updated_at",
            ),
            "meta": (
                """
                CREATE TABLE meta__clustered (
                    core TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (core, key)
                ) WITHOUT ROWID
                """,
                "core, key, value",
            ),
            "traffic_ack": (
                """
                CREATE TABLE traffic_ack__clustered (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    incoming INTEGER NOT NULL DEFAULT 0,
                    outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                ) WITHOUT ROWID
                """,
                "core, client_key, incoming, outgoing, updated_at",
            ),
            "traffic_pending": (
                """
                CREATE TABLE traffic_pending__clustered (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    delta_incoming INTEGER NOT NULL DEFAULT 0,
                    delta_outgoing INTEGER NOT NULL DEFAULT 0,
                    current_incoming INTEGER NOT NULL DEFAULT 0,
                    current_outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                ) WITHOUT ROWID
                """,
                "core, client_key, delta_incoming, delta_outgoing, current_incoming, current_outgoing, updated_at",
            ),
        }
        for name, (create_sql, columns) in tables.items():
            cursor = await conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            )
            row = await cursor.fetchone()
            if row is None or "WITHOUT ROWID" in str(row[0] or "").upper():
                continue
            clustered = f"{name}__clustered"
            await conn.execute(f"DROP TABLE IF EXISTS {clustered}")
            await conn.execute(create_sql)
            await conn.execute(
                f"INSERT INTO {clustered} ({columns}) SELECT {columns} FROM {name}"
            )
            await conn.execute(f"DROP TABLE {name}")
            await conn.execute(f"ALTER TABLE {clustered} RENAME TO {name}")

    async def list_docs(self, core: str, kind: str) -> list[dict[str, Any]]:
        rows = await self._fetch(
            "SELECT data FROM documents WHERE core = ? AND kind = ? ORDER BY doc_id",
            (core, kind),
        )
        return [await _decode_json(row["data"]) for row in rows]

    async def get_doc(self, core: str, kind: str, doc_id: str) -> dict[str, Any] | None:
        rows = await self._fetch(
            "SELECT data FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
            (core, kind, str(doc_id)),
        )
        if not rows:
            return None
        return await _decode_json(rows[0]["data"])

    async def put_doc(self, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        payload = await _encode_json(data)
        async with self._writing() as conn:
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
            await conn.commit()

    async def delete_doc(self, core: str, kind: str, doc_id: str) -> bool:
        async with self._writing() as conn:
            cursor = await conn.execute(
                "DELETE FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                (core, kind, str(doc_id)),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def write_docs(
        self,
        core: str,
        kind: str,
        puts: list[tuple[str, dict[str, Any]]],
        deletes: list[str] | None = None,
    ) -> None:
        encoded = [(str(doc_id), await _encode_json(data)) for doc_id, data in puts]
        async with self._writing() as conn:
            for doc_id, payload in encoded:
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(core, kind, doc_id) DO UPDATE SET
                        data = excluded.data,
                        updated_at = datetime('now')
                    """,
                    (core, kind, doc_id, payload),
                )
            for doc_id in deletes or []:
                if not str(doc_id).strip():
                    continue
                await conn.execute(
                    "DELETE FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                    (core, kind, str(doc_id)),
                )
            await conn.commit()

    async def backup_database(self, dest: Path) -> None:
        """Copy the open database. An existing destination is left untouched."""
        import sqlite3

        if dest.exists() and dest.stat().st_size > 0:
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".partial")
        if partial.exists():
            partial.unlink()

        def _copy() -> None:
            source = sqlite3.connect(str(self.path))
            try:
                target = sqlite3.connect(str(partial))
                try:
                    source.backup(target)
                finally:
                    target.close()
            finally:
                source.close()

        try:
            async with self._writing():
                await asyncio.to_thread(_copy)
            partial.replace(dest)
        except Exception:
            partial.unlink(missing_ok=True)
            raise

    async def apply_node_id_rewrite(
        self,
        *,
        puts: list[tuple[str, str, dict[str, Any]]],
        deletes: list[tuple[str, str]],
        ack_upserts: list[tuple[str, str, int, int]],
        ack_deletes: list[tuple[str, str]],
        pending_upserts: list[tuple[str, str, int, int, int, int]],
        pending_deletes: list[tuple[str, str]],
    ) -> None:
        """Rewrite quota documents and traffic keys in one transaction."""
        encoded = [
            (core, doc_id, await _encode_json(data))
            for core, doc_id, data in puts
        ]
        async with self._writing() as conn:
            try:
                for core, doc_id, payload in encoded:
                    await conn.execute(
                        """
                        INSERT INTO documents (core, kind, doc_id, data, updated_at)
                        VALUES (?, 'client_quota', ?, ?, datetime('now'))
                        ON CONFLICT(core, kind, doc_id) DO UPDATE SET
                            data = excluded.data,
                            updated_at = datetime('now')
                        """,
                        (core, doc_id, payload),
                    )
                for core, doc_id in deletes:
                    await conn.execute(
                        """
                        DELETE FROM documents
                        WHERE core = ? AND kind = 'client_quota' AND doc_id = ?
                        """,
                        (core, doc_id),
                    )
                for core, key, incoming, outgoing in ack_upserts:
                    await conn.execute(
                        """
                        INSERT INTO traffic_ack (core, client_key, incoming, outgoing, updated_at)
                        VALUES (?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(core, client_key) DO UPDATE SET
                            incoming = excluded.incoming,
                            outgoing = excluded.outgoing,
                            updated_at = datetime('now')
                        """,
                        (core, key, incoming, outgoing),
                    )
                for core, key in ack_deletes:
                    await conn.execute(
                        "DELETE FROM traffic_ack WHERE core = ? AND client_key = ?",
                        (core, key),
                    )
                for core, key, delta_in, delta_out, current_in, current_out in pending_upserts:
                    await conn.execute(
                        """
                        INSERT INTO traffic_pending (
                            core, client_key, delta_incoming, delta_outgoing,
                            current_incoming, current_outgoing, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(core, client_key) DO UPDATE SET
                            delta_incoming = excluded.delta_incoming,
                            delta_outgoing = excluded.delta_outgoing,
                            current_incoming = excluded.current_incoming,
                            current_outgoing = excluded.current_outgoing,
                            updated_at = datetime('now')
                        """,
                        (core, key, delta_in, delta_out, current_in, current_out),
                    )
                for core, key in pending_deletes:
                    await conn.execute(
                        "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                        (core, key),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def replace_docs(
        self,
        core: str,
        kind: str,
        docs: list[dict[str, Any]],
        id_key: str = "id",
    ) -> None:
        encoded = [(str(doc.get(id_key, "")), await _encode_json(doc)) for doc in docs]
        async with self._writing() as conn:
            await conn.execute(
                "DELETE FROM documents WHERE core = ? AND kind = ?",
                (core, kind),
            )
            for doc_id, payload in encoded:
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    """,
                    (core, kind, doc_id, payload),
                )
            await conn.commit()

    async def get_meta(self, core: str, key: str, default: Any = None) -> Any:
        rows = await self._fetch(
            "SELECT value FROM meta WHERE core = ? AND key = ?",
            (core, key),
        )
        if not rows:
            return default
        return await _decode_json(rows[0]["value"])

    async def set_meta(self, core: str, key: str, value: Any) -> None:
        payload = await _encode_json(value)
        async with self._writing() as conn:
            await conn.execute(
                """
                INSERT INTO meta (core, key, value) VALUES (?, ?, ?)
                ON CONFLICT(core, key) DO UPDATE SET value = excluded.value
                """,
                (core, key, payload),
            )
            await conn.commit()

    async def list_doc_records(
        self,
        *,
        core: str | None = None,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Document rows. Pass ``core`` and ``kind`` so the primary key can range-scan.

        Filtering only by ``kind`` uses ``documents_by_kind``. An unfiltered
        read walks the clustered primary key; callers that need one kind must
        not use that.
        """
        if core is not None and kind is not None:
            sql = (
                "SELECT core, kind, doc_id, data FROM documents "
                "WHERE core = ? AND kind = ? ORDER BY doc_id"
            )
            params: tuple[Any, ...] = (core, kind)
        elif kind is not None:
            sql = (
                "SELECT core, kind, doc_id, data FROM documents "
                "WHERE kind = ? ORDER BY core, doc_id"
            )
            params = (kind,)
        elif core is not None:
            sql = (
                "SELECT core, kind, doc_id, data FROM documents "
                "WHERE core = ? ORDER BY kind, doc_id"
            )
            params = (core,)
        else:
            sql = "SELECT core, kind, doc_id, data FROM documents ORDER BY core, kind, doc_id"
            params = ()
        rows = await self._fetch(sql, params)
        dumped: list[dict[str, Any]] = []
        for row in rows:
            try:
                data = await _decode_json(row["data"])
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

    async def dump_documents(self) -> list[dict[str, Any]]:
        """Every stored document. Traffic and audit tables are not included."""
        return await self.list_doc_records()

    async def replace_all_documents(self, rows: list[dict[str, Any]]) -> int:
        """Replace the document table with a transferred snapshot."""
        prepared: list[tuple[str, str, str, str]] = []
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
            prepared.append((core, kind, doc_id, await _encode_json(data)))
        async with self._writing() as conn:
            await conn.execute("DELETE FROM documents")
            for core, kind, doc_id, payload in prepared:
                await conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    """,
                    (core, kind, doc_id, payload),
                )
            await conn.commit()
            return len(prepared)

    async def dump_meta(self) -> list[dict[str, Any]]:
        rows = await self._fetch("SELECT core, key, value FROM meta ORDER BY core, key")
        dumped: list[dict[str, Any]] = []
        for row in rows:
            try:
                value = await _decode_json(row["value"])
            except (TypeError, json.JSONDecodeError):
                continue
            dumped.append({
                "core": str(row["core"]),
                "key": str(row["key"]),
                "value": value,
            })
        return dumped

    async def replace_all_meta(self, rows: list[dict[str, Any]]) -> int:
        prepared: list[tuple[str, str, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            core = str(row.get("core") or "").strip()
            key = str(row.get("key") or "").strip()
            if not core or not key or len(core) > 64 or len(key) > 128 or "value" not in row:
                continue
            prepared.append((core, key, await _encode_json(row.get("value"))))
        async with self._writing() as conn:
            await conn.execute("DELETE FROM meta")
            for core, key, payload in prepared:
                await conn.execute(
                    "INSERT INTO meta (core, key, value) VALUES (?, ?, ?)",
                    (core, key, payload),
                )
            await conn.commit()
            return len(prepared)

    async def inspect_traffic_ack(self, client_key: str) -> dict[str, Any]:
        """Read ack and pending rows for one client key. Does not write."""
        key = str(client_key or "").strip()
        if not key:
            return {"ack_rows": [], "pending_rows": []}
        ack_rows = await self._fetch(
            """
            SELECT core, client_key, incoming, outgoing, updated_at
            FROM traffic_ack
            WHERE client_key = ?
            ORDER BY core
            """,
            (key,),
        )
        pending_rows = await self._fetch(
            """
            SELECT core, client_key, delta_incoming, delta_outgoing,
                   current_incoming, current_outgoing, updated_at
            FROM traffic_pending
            WHERE client_key = ?
            ORDER BY core
            """,
            (key,),
        )
        return {
            "ack_rows": [dict(row) for row in ack_rows],
            "pending_rows": [dict(row) for row in pending_rows],
        }

    async def get_traffic_ack(self, core: str, client_key: str) -> dict[str, int] | None:
        rows = await self._fetch(
            """
            SELECT incoming, outgoing FROM traffic_ack
            WHERE core = ? AND client_key = ?
            """,
            (core, client_key),
        )
        if not rows:
            return None
        row = rows[0]
        return {"incoming": int(row["incoming"]), "outgoing": int(row["outgoing"])}

    async def set_traffic_ack(
        self,
        core: str,
        client_key: str,
        incoming: int,
        outgoing: int,
    ) -> None:
        async with self._writing() as conn:
            await conn.execute(
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
            await conn.commit()

    async def delete_traffic_ack(self, core: str, client_key: str) -> None:
        async with self._writing() as conn:
            await conn.execute(
                "DELETE FROM traffic_ack WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            await conn.commit()

    async def upsert_traffic_pending(
        self,
        core: str,
        client_key: str,
        delta_incoming: int,
        delta_outgoing: int,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        async with self._writing() as conn:
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
                    core,
                    client_key,
                    delta_incoming,
                    delta_outgoing,
                    current_incoming,
                    current_outgoing,
                ),
            )
            await conn.commit()

    async def delete_traffic_pending(self, core: str, client_key: str) -> None:
        async with self._writing() as conn:
            await conn.execute(
                "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            await conn.commit()

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        rows = await self._fetch(
            """
            SELECT core, client_key, delta_incoming, delta_outgoing,
                   current_incoming, current_outgoing, updated_at
            FROM traffic_pending
            WHERE core = ? AND client_key = ?
            """,
            (core, client_key),
        )
        return dict(rows[0]) if rows else None

    async def list_traffic_pending(self) -> list[dict[str, Any]]:
        rows = await self._fetch(
            """
            SELECT core, client_key, delta_incoming, delta_outgoing,
                   current_incoming, current_outgoing, updated_at
            FROM traffic_pending
            ORDER BY core, client_key
            """
        )
        return [dict(row) for row in rows]

    async def count_traffic_pending(self) -> int:
        rows = await self._fetch("SELECT COUNT(*) AS c FROM traffic_pending")
        return int(rows[0]["c"]) if rows else 0

    async def list_traffic_identity(self) -> list[dict[str, Any]]:
        rows = await self._fetch(
            """
            SELECT core, alias, canonical_key
            FROM traffic_identity
            ORDER BY core, alias
            """
        )
        return [dict(row) for row in rows]

    async def _traffic_books(self) -> tuple[
        dict[tuple[str, str], tuple[int, int]],
        dict[tuple[str, str], dict[str, int]],
    ]:
        """Read ack and pending on the read connection, outside the write lock."""
        ack_rows = await self._fetch(
            "SELECT core, client_key, incoming, outgoing FROM traffic_ack",
        )
        acks = {
            (str(row["core"]), str(row["client_key"])): (
                int(row["incoming"]),
                int(row["outgoing"]),
            )
            for row in ack_rows
        }
        pending_rows = await self._fetch(
            """
            SELECT core, client_key, delta_incoming, delta_outgoing,
                   current_incoming, current_outgoing
            FROM traffic_pending
            """
        )
        pending = {
            (str(row["core"]), str(row["client_key"])): {
                "delta_incoming": int(row["delta_incoming"]),
                "delta_outgoing": int(row["delta_outgoing"]),
                "current_incoming": int(row["current_incoming"]),
                "current_outgoing": int(row["current_outgoing"]),
            }
            for row in pending_rows
        }
        return acks, pending

    async def apply_traffic_sample(self, plan) -> dict[str, int]:
        # Planning walks every client. Do it before the write lock so a large
        # sample cannot stall other writers, and never on the HTTP process.
        acks, pending = await self._traffic_books()
        writes = plan(acks, pending)
        async with self._writing() as conn:
            try:
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
        for core, alias, canonical_key in writes.get("identity_upserts") or []:
            await conn.execute(
                """
                INSERT INTO traffic_identity (core, alias, canonical_key)
                VALUES (?, ?, ?)
                ON CONFLICT(core, alias) DO UPDATE SET
                    canonical_key = excluded.canonical_key
                """,
                (core, alias, canonical_key),
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
        async with self._writing() as conn:
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

        async with self._writing() as conn:
            await conn.execute(
                "INSERT INTO audit_log (ts, action, resource, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), action, resource, detail),
            )
            await conn.commit()
