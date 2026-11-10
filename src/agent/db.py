from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

from agent.database.events.listeners import register_listeners
from agent.database.json_codec import JSON_OFFLOAD_BYTES, decode_json, encode_json, loads as _loads
from agent.database.config import DatabaseConfig, database_config_from_path
from agent.database.migrate import upgrade_head
from agent.database.session import DatabaseRuntime
from agent.services.document_store import DocumentStore
from agent.services.meta_service import MetaService
from agent.services.traffic_store_service import TrafficStoreService

_JSON_OFFLOAD_BYTES = JSON_OFFLOAD_BYTES
_BUSY_TIMEOUT_SECONDS = 15.0
_BUSY_TIMEOUT_MS = 15_000
_LOCK_ATTEMPTS = 4
_STATEMENTS_PER_COMMIT = 100


def _dumps(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)


async def _encode_json(value: Any) -> str:
    return await encode_json(value)


async def _decode_json(raw: str) -> Any:
    return await decode_json(raw)


def _is_db_locked(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower()


class Store:
    """SQLite state for the agent (async SQLAlchemy backend)."""

    def __init__(
        self,
        config: DatabaseConfig | str | Path,
        *,
        slow_query_log_ms: float = 0.0,
    ):
        if isinstance(config, (str, Path)):
            db_config = database_config_from_path(config)
        else:
            db_config = config
        self._db_config = db_config
        self.path = db_config.sqlite_path or Path(db_config.database)
        self._slow_query_log_ms = max(0.0, float(slow_query_log_ms))
        self._runtime = DatabaseRuntime(db_config, slow_query_log_ms=slow_query_log_ms)
        self._documents = DocumentStore(self._runtime)
        self._meta = MetaService(self._runtime)
        self._traffic = TrafficStoreService(self._runtime)

    @property
    def _lock(self) -> asyncio.Lock:
        return self._runtime._lock

    async def _fetch(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        from sqlalchemy import text

        bind: dict[str, Any] = {}
        query = sql
        if "?" in sql and params:
            parts = sql.split("?")
            query = parts[0]
            for index, part in enumerate(parts[1:]):
                key = f"p{index}"
                bind[key] = params[index]
                query += f":{key}" + part
        async with self._runtime.reading() as session:
            result = await session.execute(text(query), bind)
            return [tuple(row) for row in result.fetchall()]

    async def open(self, *, migrate: bool = True) -> None:
        if self._db_config.is_sqlite and self._db_config.sqlite_path is not None:
            self._db_config.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        register_listeners()
        if migrate:
            await asyncio.to_thread(upgrade_head, self._db_config)
        await self._runtime.open()

    async def close(self) -> None:
        await self._runtime.close()

    async def list_docs(self, core: str, kind: str) -> list[dict[str, Any]]:
        return await self._documents.list_docs(core, kind)

    async def lookup_document_keys(self, doc_ids: list[str]) -> list[dict[str, Any]]:
        return await self._documents.lookup_document_keys(doc_ids)

    async def get_doc(self, core: str, kind: str, doc_id: str) -> dict[str, Any] | None:
        return await self._documents.get_doc(core, kind, doc_id)

    async def put_doc(self, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        await self._documents.put_doc(core, kind, doc_id, data)

    async def delete_doc(self, core: str, kind: str, doc_id: str) -> bool:
        return await self._documents.delete_doc(core, kind, doc_id)

    async def write_docs(
        self,
        core: str,
        kind: str,
        puts: list[tuple[str, dict[str, Any]]],
        deletes: list[str] | None = None,
    ) -> None:
        await self._documents.write_docs(core, kind, puts, deletes)

    async def backup_database(self, dest: Path) -> None:
        import sqlite3

        from agent.database.engine import BUSY_TIMEOUT_MS

        if dest.exists() and dest.stat().st_size > 0:
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".partial")
        if partial.exists():
            partial.unlink()

        def _copy() -> None:
            source = sqlite3.connect(str(self.path), timeout=_BUSY_TIMEOUT_SECONDS)
            try:
                source.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
                target = sqlite3.connect(str(partial))
                try:
                    source.backup(target)
                finally:
                    target.close()
            finally:
                source.close()

        async with self._runtime.writing():
            await asyncio.to_thread(_copy)
        partial.replace(dest)

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
        await self._traffic.apply_node_id_rewrite(
            puts=puts,
            deletes=deletes,
            ack_upserts=ack_upserts,
            ack_deletes=ack_deletes,
            pending_upserts=pending_upserts,
            pending_deletes=pending_deletes,
        )

    async def replace_docs(
        self,
        core: str,
        kind: str,
        docs: list[dict[str, Any]],
        id_key: str = "id",
    ) -> None:
        await self._documents.replace_docs(core, kind, docs, id_key=id_key)

    async def get_meta(self, core: str, key: str, default: Any = None) -> Any:
        return await self._meta.get_meta(core, key, default)

    async def set_meta(self, core: str, key: str, value: Any) -> None:
        await self._meta.set_meta(core, key, value)

    async def list_doc_records(
        self,
        *,
        core: str | None = None,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        return await self._documents.list_doc_records(core=core, kind=kind)

    async def dump_documents(self) -> list[dict[str, Any]]:
        return await self._documents.dump_documents()

    async def replace_all_documents(self, rows: list[dict[str, Any]]) -> int:
        return await self._documents.replace_all_documents(rows)

    async def dump_meta(self) -> list[dict[str, Any]]:
        return await self._meta.dump_meta()

    async def replace_all_meta(self, rows: list[dict[str, Any]]) -> int:
        return await self._meta.replace_all_meta(rows)

    async def inspect_traffic_ack(self, client_key: str) -> dict[str, Any]:
        return await self._traffic.inspect_traffic_ack(client_key)

    async def get_traffic_ack(self, core: str, client_key: str) -> dict[str, int] | None:
        return await self._traffic.get_traffic_ack(core, client_key)

    async def set_traffic_ack(self, core: str, client_key: str, incoming: int, outgoing: int) -> None:
        await self._traffic.set_traffic_ack(core, client_key, incoming, outgoing)

    async def delete_traffic_ack(self, core: str, client_key: str) -> None:
        await self._traffic.delete_traffic_ack(core, client_key)

    async def upsert_traffic_pending(
        self,
        core: str,
        client_key: str,
        delta_incoming: int,
        delta_outgoing: int,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        await self._traffic.upsert_traffic_pending(
            core,
            client_key,
            delta_incoming,
            delta_outgoing,
            current_incoming,
            current_outgoing,
        )

    async def delete_traffic_pending(self, core: str, client_key: str) -> None:
        await self._traffic.delete_traffic_pending(core, client_key)

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        return await self._traffic.get_traffic_pending(core, client_key)

    async def list_traffic_pending(self) -> list[dict[str, Any]]:
        return await self._traffic.list_traffic_pending()

    async def count_traffic_pending(self) -> int:
        return await self._traffic.count_traffic_pending()

    async def list_traffic_identity(self) -> list[dict[str, Any]]:
        return await self._traffic.list_traffic_identity()

    async def _traffic_books(self) -> tuple[
        dict[tuple[str, str], tuple[int, int]],
        dict[tuple[str, str], dict[str, int]],
    ]:
        return await self._traffic._traffic_books()

    async def apply_traffic_sample(self, plan) -> dict[str, int]:
        return await self._traffic.apply_traffic_sample(plan)

    async def ack_billed_snapshots(self, rows: list[dict[str, Any]]) -> None:
        await self._traffic.ack_billed_snapshots(rows)

    async def ack_traffic_rows(self, rows: list[dict[str, Any]]) -> None:
        await self._traffic.ack_traffic_rows(rows)

    async def audit(self, action: str, resource: str, detail: str = "") -> None:
        from datetime import datetime, timezone

        from sqlalchemy import insert

        from agent.database.models.audit import AuditLogEntry

        async with self._runtime.writing() as session:
            await session.execute(
                insert(AuditLogEntry).values(
                    ts=datetime.now(timezone.utc).isoformat(),
                    action=action,
                    resource=resource,
                    detail=detail,
                )
            )
            await session.commit()
