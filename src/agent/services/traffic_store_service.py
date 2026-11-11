from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from agent.auth_scope import current_scope
from agent.database.models.client import Client
from agent.database.models.traffic import TrafficAck, TrafficIdentity, TrafficPending, TrafficPendingChunk
from agent.database.session import DatabaseRuntime


class TrafficStoreService:
    def __init__(self, runtime: DatabaseRuntime):
        self._runtime = runtime

    async def inspect_traffic_ack(self, client_key: str) -> dict[str, Any]:
        key = str(client_key or "").strip()
        if not key:
            return {"ack_rows": [], "pending_rows": []}
        async with self._runtime.reading() as session:
            scope = current_scope()
            ack_rows = (
                await session.execute(
                    select(TrafficAck)
                    .where(TrafficAck.scope == scope, TrafficAck.client_key == key)
                    .order_by(TrafficAck.core)
                )
            ).scalars().all()
            pending_rows = (
                await session.execute(
                    select(TrafficPending)
                    .where(TrafficPending.scope == scope, TrafficPending.client_key == key)
                    .order_by(TrafficPending.core)
                )
            ).scalars().all()
            return {
                "ack_rows": [
                    {
                        "core": row.core,
                        "client_key": row.client_key,
                        "incoming": row.incoming,
                        "outgoing": row.outgoing,
                        "updated_at": row.updated_at,
                    }
                    for row in ack_rows
                ],
                "pending_rows": [
                    {
                        "core": row.core,
                        "client_key": row.client_key,
                        "delta_incoming": row.delta_incoming,
                        "delta_outgoing": row.delta_outgoing,
                        "current_incoming": row.current_incoming,
                        "current_outgoing": row.current_outgoing,
                        "updated_at": row.updated_at,
                    }
                    for row in pending_rows
                ],
            }

    async def get_traffic_ack(self, core: str, client_key: str) -> dict[str, int] | None:
        async with self._runtime.reading() as session:
            scope = current_scope()
            row = await session.get(TrafficAck, (scope, core, client_key))
            if row is None:
                return None
            return {"incoming": int(row.incoming), "outgoing": int(row.outgoing)}

    async def set_traffic_ack(self, core: str, client_key: str, incoming: int, outgoing: int) -> None:
        async with self._runtime.writing() as session:
            scope = current_scope()
            row = await session.get(TrafficAck, (scope, core, client_key))
            if row is None:
                session.add(
                    TrafficAck(
                        scope=scope,
                        core=core,
                        client_key=client_key,
                        incoming=int(incoming),
                        outgoing=int(outgoing),
                        updated_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            else:
                row.incoming = int(incoming)
                row.outgoing = int(outgoing)
                row.updated_at = datetime.now(timezone.utc).isoformat()
            await session.commit()

    async def delete_traffic_ack(self, core: str, client_key: str) -> None:
        async with self._runtime.writing() as session:
            scope = current_scope()
            await session.execute(
                delete(TrafficAck).where(
                    TrafficAck.scope == scope,
                    TrafficAck.core == core,
                    TrafficAck.client_key == client_key,
                )
            )
            await session.commit()

    async def upsert_traffic_pending(
        self,
        core: str,
        client_key: str,
        delta_incoming: int,
        delta_outgoing: int,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        async with self._runtime.writing() as session:
            scope = current_scope()
            await self._upsert_pending(
                session,
                scope,
                {
                    "core": core,
                    "client_key": client_key,
                    "delta_incoming": int(delta_incoming),
                    "delta_outgoing": int(delta_outgoing),
                    "current_incoming": int(current_incoming),
                    "current_outgoing": int(current_outgoing),
                },
            )
            await session.commit()

    async def _upsert_pending(self, session, scope: str, item: dict[str, Any]) -> None:
        """Update the one pending row for this client. Insert it only the first time."""
        now = datetime.now(timezone.utc).isoformat()
        stmt = sqlite_insert(TrafficPending).values(
            scope=scope,
            core=str(item["core"]),
            client_key=str(item["client_key"]),
            delta_incoming=int(item["delta_incoming"]),
            delta_outgoing=int(item["delta_outgoing"]),
            current_incoming=int(item["current_incoming"]),
            current_outgoing=int(item["current_outgoing"]),
            updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[TrafficPending.scope, TrafficPending.core, TrafficPending.client_key],
            set_={
                "delta_incoming": stmt.excluded.delta_incoming,
                "delta_outgoing": stmt.excluded.delta_outgoing,
                "current_incoming": stmt.excluded.current_incoming,
                "current_outgoing": stmt.excluded.current_outgoing,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        await session.execute(stmt)

    async def _upsert_sample_cursor(
        self,
        session,
        scope: str,
        core: str,
        client_key: str,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        key = (scope, str(core), str(client_key))
        row = await session.get(TrafficPending, key)
        if row is None:
            session.add(
                TrafficPending(
                    scope=scope,
                    core=str(core),
                    client_key=str(client_key),
                    delta_incoming=0,
                    delta_outgoing=0,
                    current_incoming=int(current_incoming),
                    current_outgoing=int(current_outgoing),
                    updated_at=now,
                )
            )
            return
        row.current_incoming = int(current_incoming)
        row.current_outgoing = int(current_outgoing)
        row.updated_at = now

    async def delete_traffic_pending(self, core: str, client_key: str) -> None:
        async with self._runtime.writing() as session:
            scope = current_scope()
            await session.execute(
                delete(TrafficPending).where(
                    TrafficPending.scope == scope,
                    TrafficPending.core == core,
                    TrafficPending.client_key == client_key,
                )
            )
            await session.execute(
                delete(TrafficPendingChunk).where(
                    TrafficPendingChunk.scope == scope,
                    TrafficPendingChunk.core == core,
                    TrafficPendingChunk.client_key == client_key,
                )
            )
            await session.commit()

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        _, pending = await self._traffic_books(scope=current_scope(), core=core)
        row = pending.get((str(core), str(client_key)))
        if row is None:
            return None
        return {
            "core": str(core),
            "client_key": str(client_key),
            "delta_incoming": int(row["delta_incoming"]),
            "delta_outgoing": int(row["delta_outgoing"]),
            "current_incoming": int(row["current_incoming"]),
            "current_outgoing": int(row["current_outgoing"]),
            "updated_at": None,
        }

    async def list_traffic_pending(self) -> list[dict[str, Any]]:
        _, pending = await self._traffic_books()
        rows: list[dict[str, Any]] = []
        for (core, client_key), item in sorted(pending.items()):
            rows.append(
                {
                    "core": core,
                    "client_key": client_key,
                    "delta_incoming": int(item["delta_incoming"]),
                    "delta_outgoing": int(item["delta_outgoing"]),
                    "current_incoming": int(item["current_incoming"]),
                    "current_outgoing": int(item["current_outgoing"]),
                    "updated_at": None,
                }
            )
        return rows

    async def count_traffic_pending(self) -> int:
        scope = current_scope()
        async with self._runtime.reading() as session:
            count = await session.scalar(
                select(func.count(func.distinct(TrafficPendingChunk.client_key)))
                .select_from(TrafficPendingChunk)
                .where(TrafficPendingChunk.scope == scope)
            )
            legacy = await session.scalar(
                select(func.count()).select_from(TrafficPending).where(TrafficPending.scope == scope)
            )
            return max(int(count or 0), int(legacy or 0))

    async def get_client_traffic_cursor(
        self,
        core: str,
        client_id: str,
    ) -> tuple[int, int] | None:
        async with self._runtime.reading() as session:
            row = await session.get(Client, (str(core), str(client_id)))
            if row is None or row.incoming is None and row.outgoing is None:
                return None
            return int(row.incoming or 0), int(row.outgoing or 0)

    async def bulk_set_client_traffic_cursors(
        self,
        scope: str,
        upserts: list[tuple[str, str, int, int]],
    ) -> None:
        if not upserts:
            return
        async with self._runtime.writing() as session:
            await self._apply_client_cursor_upserts(session, str(scope), upserts)
            await session.commit()

    async def clear_pending_traffic_queue(self, scope: str | None = None) -> dict[str, int]:
        """Delete all unacked pending chunks and legacy aggregate rows (panel will not bill them)."""
        scope = str(scope or current_scope())
        async with self._runtime.writing() as session:
            chunks_before = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(TrafficPendingChunk)
                        .where(TrafficPendingChunk.scope == scope)
                    )
                ).scalar_one()
                or 0
            )
            legacy_before = int(
                (
                    await session.execute(
                        select(func.count()).select_from(TrafficPending).where(TrafficPending.scope == scope)
                    )
                ).scalar_one()
                or 0
            )
            clients_before = int(
                (
                    await session.execute(
                        select(func.count(func.distinct(TrafficPendingChunk.client_key)))
                        .select_from(TrafficPendingChunk)
                        .where(TrafficPendingChunk.scope == scope)
                    )
                ).scalar_one()
                or 0
            )
            await session.execute(delete(TrafficPendingChunk).where(TrafficPendingChunk.scope == scope))
            await session.execute(delete(TrafficPending).where(TrafficPending.scope == scope))
            await session.commit()
        return {
            "chunks_deleted": chunks_before,
            "legacy_rows_deleted": legacy_before,
            "clients_cleared": clients_before,
        }

    async def list_traffic_pending_chunks(self) -> list[dict[str, Any]]:
        scope = current_scope()
        async with self._runtime.reading() as session:
            rows = (
                await session.execute(
                    select(TrafficPendingChunk)
                    .where(TrafficPendingChunk.scope == scope)
                    .order_by(TrafficPendingChunk.core, TrafficPendingChunk.client_key, TrafficPendingChunk.sampled_at)
                )
            ).scalars().all()
            return [
                {
                    "chunk_id": str(row.chunk_id),
                    "core": row.core,
                    "client_key": row.client_key,
                    "incoming": int(row.incoming),
                    "outgoing": int(row.outgoing),
                    "sampled_at": row.sampled_at,
                }
                for row in rows
            ]

    async def ack_traffic_chunk_ids(self, chunk_ids: list[str]) -> tuple[int, list[str]]:
        ids = [str(item).strip() for item in chunk_ids if str(item or "").strip()]
        if not ids:
            return 0, []
        scope = current_scope()
        deleted = 0
        async with self._runtime.writing() as session:
            rows = (
                await session.execute(
                    select(TrafficPendingChunk).where(
                        TrafficPendingChunk.scope == scope,
                        TrafficPendingChunk.chunk_id.in_(ids),
                    )
                )
            ).scalars().all()
            if not rows:
                return 0, ids
            found = {str(row.chunk_id) for row in rows}
            touched: set[tuple[str, str]] = set()
            for row in rows:
                touched.add((str(row.core), str(row.client_key)))
                await session.delete(row)
                deleted += 1
            for core, client_key in touched:
                left = await session.scalar(
                    select(func.count())
                    .select_from(TrafficPendingChunk)
                    .where(
                        TrafficPendingChunk.scope == scope,
                        TrafficPendingChunk.core == core,
                        TrafficPendingChunk.client_key == client_key,
                    )
                )
                if int(left or 0) == 0:
                    await session.execute(
                        delete(TrafficPending).where(
                            TrafficPending.scope == scope,
                            TrafficPending.core == core,
                            TrafficPending.client_key == client_key,
                        )
                    )
            await session.commit()
        missing = [item for item in ids if item not in found]
        return deleted, missing

    async def list_traffic_identity(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (
                await session.execute(
                    select(TrafficIdentity)
                    .where(TrafficIdentity.scope == current_scope())
                    .order_by(TrafficIdentity.core, TrafficIdentity.alias)
                )
            ).scalars().all()
            return [
                {"core": row.core, "alias": row.alias, "canonical_key": row.canonical_key}
                for row in rows
            ]

    async def _traffic_books(self, scope: str | None = None, core: str | None = None) -> tuple[
        dict[tuple[str, str], tuple[int, int]],
        dict[tuple[str, str], dict[str, int]],
    ]:
        scope = str(scope or current_scope())
        core_name = str(core or "").strip()
        async with self._runtime.reading() as session:
            ack_query = select(TrafficAck).where(TrafficAck.scope == scope)
            chunk_query = select(TrafficPendingChunk).where(TrafficPendingChunk.scope == scope)
            if core_name:
                ack_query = ack_query.where(TrafficAck.core == core_name)
                chunk_query = chunk_query.where(TrafficPendingChunk.core == core_name)
            ack_rows = (await session.execute(ack_query)).scalars().all()
            acks = {
                (str(row.core), str(row.client_key)): (int(row.incoming), int(row.outgoing))
                for row in ack_rows
            }
            chunk_rows = (await session.execute(chunk_query)).scalars().all()
            pending: dict[tuple[str, str], dict[str, int]] = {}
            cursor_map: dict[tuple[str, str], tuple[int, int]] = {}
            pending_keys: set[tuple[str, str]] = set()
            for row in chunk_rows:
                pending_keys.add((str(row.core), str(row.client_key)))
            if pending_keys:
                by_core: dict[str, list[str]] = defaultdict(list)
                for core_id, client_id in pending_keys:
                    by_core[str(core_id)].append(str(client_id))
                for core_id, client_ids in by_core.items():
                    unique = list(dict.fromkeys(client_ids))
                    for offset in range(0, len(unique), 400):
                        batch = unique[offset : offset + 400]
                        result = await session.execute(
                            select(Client).where(Client.core_id == core_id, Client.id.in_(batch))
                        )
                        for row in result.scalars().all():
                            if row.incoming is None and row.outgoing is None:
                                continue
                            cursor_map[(str(row.core_id), str(row.id))] = (
                                int(row.incoming or 0),
                                int(row.outgoing or 0),
                            )
            for row in chunk_rows:
                key = (str(row.core), str(row.client_key))
                agg = pending.setdefault(
                    key,
                    {
                        "delta_incoming": 0,
                        "delta_outgoing": 0,
                        "current_incoming": 0,
                        "current_outgoing": 0,
                    },
                )
                agg["delta_incoming"] += int(row.incoming)
                agg["delta_outgoing"] += int(row.outgoing)
            for key, agg in pending.items():
                cursor = cursor_map.get(key, (0, 0))
                agg["current_incoming"] = int(cursor[0])
                agg["current_outgoing"] = int(cursor[1])
            legacy_query = select(TrafficPending).where(TrafficPending.scope == scope)
            if core_name:
                legacy_query = legacy_query.where(TrafficPending.core == core_name)
            for row in (await session.execute(legacy_query)).scalars().all():
                key = (str(row.core), str(row.client_key))
                if key in pending:
                    # Chunk rows are authoritative; legacy TrafficPending deltas must not stack.
                    continue
                pending[key] = {
                    "delta_incoming": int(row.delta_incoming),
                    "delta_outgoing": int(row.delta_outgoing),
                    "current_incoming": int(row.current_incoming),
                    "current_outgoing": int(row.current_outgoing),
                }
            return acks, pending

    async def load_client_traffic_cursors(
        self,
        scope: str | None = None,
        core: str | None = None,
    ) -> dict[tuple[str, str], tuple[int, int]]:
        scope = str(scope or current_scope())
        core_name = str(core or "").strip()
        found: dict[tuple[str, str], tuple[int, int]] = {}
        async with self._runtime.reading() as session:
            client_query = select(Client).where(Client.scope == scope)
            if core_name:
                client_query = client_query.where(Client.core_id == core_name)
            for row in (await session.execute(client_query)).scalars().all():
                pair = (str(row.core_id), str(row.id))
                if row.incoming is None and row.outgoing is None:
                    continue
                found[pair] = (
                    int(row.incoming or 0),
                    int(row.outgoing or 0),
                )
        return found

    async def _merge_identity_cursors(
        self,
        scope: str,
        cursors: dict[tuple[str, str], tuple[int, int]],
    ) -> dict[tuple[str, str], tuple[int, int]]:
        if not cursors:
            return cursors
        merged = dict(cursors)
        for row in await self.list_traffic_identity():
            core = str(row.get("core") or "").strip()
            alias = str(row.get("alias") or "").strip()
            canonical = str(row.get("canonical_key") or "").strip()
            if not core or not alias or not canonical or alias == canonical:
                continue
            alias_pair = (core, alias)
            canon_pair = (core, canonical)
            alias_cursor = merged.pop(alias_pair, None)
            canon_cursor = merged.get(canon_pair)
            if alias_cursor is None and canon_cursor is None:
                continue
            if canon_cursor is None:
                merged[canon_pair] = alias_cursor
                continue
            if alias_cursor is None:
                continue
            merged[canon_pair] = (
                max(canon_cursor[0], alias_cursor[0]),
                max(canon_cursor[1], alias_cursor[1]),
            )
        return merged

    async def load_client_traffic_cursors_for_keys(
        self,
        scope: str | None = None,
        keys: set[tuple[str, str]] | None = None,
    ) -> dict[tuple[str, str], tuple[int, int]]:
        scope = str(scope or current_scope())
        if not keys:
            return {}
        by_core: dict[str, list[str]] = defaultdict(list)
        for core_name, client_id in keys:
            core_text = str(core_name or "").strip()
            client_text = str(client_id or "").strip()
            if not core_text or not client_text:
                continue
            by_core[core_text].append(client_text)
        found: dict[tuple[str, str], tuple[int, int]] = {}
        async with self._runtime.reading() as session:
            for core_name, client_ids in by_core.items():
                unique_ids = list(dict.fromkeys(client_ids))
                for offset in range(0, len(unique_ids), 400):
                    batch = unique_ids[offset : offset + 400]
                    result = await session.execute(
                        select(Client).where(
                            Client.core_id == core_name,
                            Client.id.in_(batch),
                        )
                    )
                    for row in result.scalars().all():
                        if row.incoming is None and row.outgoing is None:
                            continue
                        found[(str(row.core_id), str(row.id))] = (
                            int(row.incoming or 0),
                            int(row.outgoing or 0),
                        )
        return found

    async def apply_traffic_sample(
        self,
        plan,
        scope: str | None = None,
        core: str | None = None,
        *,
        fast_stats: bool = False,
        cursor_keys: set[tuple[str, str]] | None = None,
        return_sqlite_timing: bool = False,
    ) -> dict[str, int] | tuple[dict[str, int], dict[str, int]]:
        scope = str(scope or current_scope())
        cursor_started = time.monotonic()
        if cursor_keys:
            cursors = await self.load_client_traffic_cursors_for_keys(scope, cursor_keys)
        else:
            cursors = await self.load_client_traffic_cursors(scope, core)
        cursors = await self._merge_identity_cursors(scope, cursors)
        cursor_load_ms = int((time.monotonic() - cursor_started) * 1000)
        plan_started = time.monotonic()
        writes = plan(cursors)
        plan_ms = int((time.monotonic() - plan_started) * 1000)
        if isinstance(writes, dict):
            writes["scope"] = scope
        write_started = time.monotonic()
        await self._runtime.retry_locked(lambda: self._commit_traffic_plan(writes))
        write_ms = int((time.monotonic() - write_started) * 1000)
        stats = dict(writes.get("stats") or {})
        if not fast_stats:
            stats["pending"] = await self.count_traffic_pending()
        sqlite_detail = {
            "cursor_load_ms": cursor_load_ms,
            "plan_ms": plan_ms,
            "write_ms": write_ms,
            "chunk_count": len(writes.get("chunk_inserts") or []),
        }
        if return_sqlite_timing:
            return stats, sqlite_detail
        return stats

    async def _commit_traffic_plan(self, writes: dict[str, Any]) -> None:
        meta = writes.get("meta")
        body = dict(writes)
        body["meta"] = None
        async with self._runtime.writing() as session:
            try:
                await self._write_traffic_plan(session, body)
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        if isinstance(meta, tuple) and len(meta) == 3:
            from agent.services.meta_service import MetaService

            core, key, value = meta
            await MetaService(self._runtime).set_meta(core, key, value)

    async def _write_traffic_plan(self, session, writes: dict[str, Any]) -> None:
        scope = str(writes.get("scope") or current_scope())
        staged_ack: dict[tuple[str, str, str], TrafficAck] = {}
        for core, client_key, incoming, outgoing in writes.get("ack_upserts") or []:
            key = (scope, core, client_key)
            row = staged_ack.get(key)
            if row is None:
                row = await session.get(TrafficAck, key)
            if row is None:
                row = TrafficAck(
                    scope=scope,
                    core=core,
                    client_key=client_key,
                    incoming=int(incoming),
                    outgoing=int(outgoing),
                    updated_at=datetime.now(timezone.utc).isoformat(),
                )
                session.add(row)
            else:
                row.incoming = int(incoming)
                row.outgoing = int(outgoing)
                row.updated_at = datetime.now(timezone.utc).isoformat()
            staged_ack[key] = row
        for core, client_key in writes.get("ack_deletes") or []:
            await session.execute(
                delete(TrafficAck).where(
                    TrafficAck.scope == scope,
                    TrafficAck.core == core,
                    TrafficAck.client_key == client_key,
                )
            )
        # One statement per client updates the existing pending row.
        seen_pending: set[tuple[str, str]] = set()
        for item in writes.get("pending_upserts") or []:
            key = (str(item["core"]), str(item["client_key"]))
            if key in seen_pending:
                continue
            seen_pending.add(key)
            await self._upsert_pending(session, scope, item)
        for core, client_key in writes.get("pending_deletes") or []:
            await session.execute(
                delete(TrafficPending).where(
                    TrafficPending.scope == scope,
                    TrafficPending.core == core,
                    TrafficPending.client_key == client_key,
                )
            )
        identity_upserts = list(writes.get("identity_upserts") or [])
        if identity_upserts:
            aliases_by_core: dict[str, set[str]] = defaultdict(set)
            for core, alias, _canonical in identity_upserts:
                aliases_by_core[str(core)].add(str(alias))
            identity_rows: dict[tuple[str, str, str], TrafficIdentity] = {}
            for core_name, aliases in aliases_by_core.items():
                alias_list = list(aliases)
                for offset in range(0, len(alias_list), 400):
                    batch = alias_list[offset : offset + 400]
                    result = await session.execute(
                        select(TrafficIdentity).where(
                            TrafficIdentity.scope == scope,
                            TrafficIdentity.core == core_name,
                            TrafficIdentity.alias.in_(batch),
                        )
                    )
                    for row in result.scalars().all():
                        identity_rows[(scope, str(row.core), str(row.alias))] = row
            for core, alias, canonical_key in identity_upserts:
                row = identity_rows.get((scope, str(core), str(alias)))
                if row is None:
                    session.add(
                        TrafficIdentity(
                            scope=scope,
                            core=core,
                            alias=alias,
                            canonical_key=canonical_key,
                        )
                    )
                else:
                    row.canonical_key = canonical_key
        cursor_upserts = writes.get("client_cursor_upserts") or []
        await self._apply_client_cursor_upserts(session, scope, cursor_upserts)
        chunk_rows = [
            TrafficPendingChunk(
                scope=scope,
                chunk_id=str(item["chunk_id"]),
                core=str(item["core"]),
                client_key=str(item["client_key"]),
                incoming=int(item["incoming"]),
                outgoing=int(item["outgoing"]),
                sampled_at=str(item["sampled_at"]),
            )
            for item in writes.get("chunk_inserts") or []
        ]
        if chunk_rows:
            session.add_all(chunk_rows)

    async def _apply_client_cursor_upserts(
        self,
        session,
        scope: str,
        upserts: list[tuple[str, str, int, int]],
    ) -> None:
        if not upserts:
            return
        from collections import defaultdict

        from agent.database.models.core import Core

        by_core: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        for core, client_key, incoming, outgoing in upserts:
            core_name = str(core or "").strip()
            client_id = str(client_key or "").strip()
            if not core_name or not client_id:
                continue
            by_core[core_name].append((client_id, int(incoming), int(outgoing)))

        for core_name in by_core:
            if await session.get(Core, core_name) is None:
                session.add(Core(id=core_name))

        existing: dict[tuple[str, str], Client] = {}
        for core_name, rows in by_core.items():
            client_ids = [item[0] for item in rows]
            if not client_ids:
                continue
            result = await session.execute(
                select(Client).where(Client.core_id == core_name, Client.id.in_(client_ids))
            )
            for row in result.scalars().all():
                existing[(str(row.core_id), str(row.id))] = row

        for core_name, rows in by_core.items():
            for client_id, incoming, outgoing in rows:
                key = (core_name, client_id)
                client = existing.get(key)
                if client is None:
                    session.add(
                        Client(
                            core_id=core_name,
                            id=client_id,
                            scope=scope,
                            incoming=int(incoming),
                            outgoing=int(outgoing),
                        )
                    )
                    continue
                client.incoming = int(incoming)
                client.outgoing = int(outgoing)

    async def _update_client_traffic_cursor(
        self,
        session,
        scope: str,
        core: str,
        client_key: str,
        incoming: int,
        outgoing: int,
    ) -> None:
        await self._apply_client_cursor_upserts(session, scope, [(core, client_key, incoming, outgoing)])

    async def ack_billed_snapshots(self, rows: list[dict[str, Any]]) -> None:
        """Remove billed bytes from chunk rows (panel also sends chunk_ids)."""
        if not rows:
            return
        async with self._runtime.writing() as session:
            scope = current_scope()
            seen: set[tuple[str, str]] = set()
            for snap in rows:
                core = str(snap.get("core") or "")
                client_key = str(snap.get("client_key") or "")
                pair = (core, client_key)
                if not core or not client_key or pair in seen:
                    continue
                seen.add(pair)
                if "billed_incoming" in snap or "billed_outgoing" in snap:
                    take_in = max(0, int(snap.get("billed_incoming") or 0))
                    take_out = max(0, int(snap.get("billed_outgoing") or 0))
                else:
                    take_in = max(
                        0,
                        int(snap.get("incoming") or snap.get("delta_incoming") or 0),
                    )
                    take_out = max(
                        0,
                        int(snap.get("outgoing") or snap.get("delta_outgoing") or 0),
                    )
                if take_in == 0 and take_out == 0:
                    continue
                chunks = (
                    await session.execute(
                        select(TrafficPendingChunk)
                        .where(
                            TrafficPendingChunk.scope == scope,
                            TrafficPendingChunk.core == core,
                            TrafficPendingChunk.client_key == client_key,
                        )
                        .order_by(TrafficPendingChunk.sampled_at)
                    )
                ).scalars().all()
                await self._consume_chunks_fifo(session, chunks, take_in, take_out)
                left = await session.scalar(
                    select(func.count())
                    .select_from(TrafficPendingChunk)
                    .where(
                        TrafficPendingChunk.scope == scope,
                        TrafficPendingChunk.core == core,
                        TrafficPendingChunk.client_key == client_key,
                    )
                )
                if int(left or 0) == 0:
                    await session.execute(
                        delete(TrafficPending).where(
                            TrafficPending.scope == scope,
                            TrafficPending.core == core,
                            TrafficPending.client_key == client_key,
                        )
                    )
            await session.commit()

    @staticmethod
    async def _consume_chunks_fifo(
        session,
        chunks: list[TrafficPendingChunk],
        take_incoming: int,
        take_outgoing: int,
    ) -> list[TrafficPendingChunk]:
        remaining_in = int(take_incoming)
        remaining_out = int(take_outgoing)
        keep: list[TrafficPendingChunk] = []
        for chunk in chunks:
            if remaining_in <= 0 and remaining_out <= 0:
                keep.append(chunk)
                continue
            chunk_in = int(chunk.incoming)
            chunk_out = int(chunk.outgoing)
            if chunk_in <= remaining_in and chunk_out <= remaining_out:
                remaining_in -= chunk_in
                remaining_out -= chunk_out
                await session.delete(chunk)
                continue
            keep.append(chunk)
        return keep

    @staticmethod
    def _settle_billed_direction(
        live_current: int | None,
        live_delta: int,
        snap_current: int,
        snap_delta: int,
        previous_ack: int | None,
    ) -> tuple[int, int]:
        """Return the baseline and the pending bytes that must stay queued.

        A still-monotonic counter moves the baseline to the billed snapshot and
        keeps only the bytes above it. A counter that reset, or climbed back
        past the snapshot after a reset, keeps the sampler baseline and drops
        only the billed delta.
        """
        if live_current is None:
            if previous_ack is None or previous_ack <= snap_current:
                return snap_current, 0
            return previous_ack, 0
        growth = live_current - snap_current
        if live_current >= snap_current and live_delta == snap_delta + growth:
            baseline = snap_current if previous_ack is None or previous_ack <= snap_current else previous_ack
            return baseline, growth
        baseline = previous_ack if previous_ack is not None else live_current
        return baseline, max(0, live_delta - snap_delta)

    async def ack_traffic_rows(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        async with self._runtime.writing() as session:
            scope = current_scope()
            seen: set[tuple[str, str, str]] = set()
            for row in rows:
                key = (scope, str(row["core"]), str(row["client_key"]))
                if key in seen:
                    continue
                seen.add(key)
                existing = await session.get(TrafficAck, key)
                if existing is None:
                    session.add(
                        TrafficAck(
                            scope=scope,
                            core=key[1],
                            client_key=key[2],
                            incoming=int(row["current_incoming"]),
                            outgoing=int(row["current_outgoing"]),
                            updated_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                else:
                    existing.incoming = int(row["current_incoming"])
                    existing.outgoing = int(row["current_outgoing"])
                    existing.updated_at = datetime.now(timezone.utc).isoformat()
                await session.execute(
                    delete(TrafficPending).where(
                        TrafficPending.scope == scope,
                        TrafficPending.core == key[1],
                        TrafficPending.client_key == key[2],
                    )
                )
                await session.execute(
                    delete(TrafficPendingChunk).where(
                        TrafficPendingChunk.scope == scope,
                        TrafficPendingChunk.core == key[1],
                        TrafficPendingChunk.client_key == key[2],
                    )
                )
            await session.commit()

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
        from agent.database.models.client import Client
        from agent.database.models.quota import Quota
        from agent.services.document_store import DocumentStore

        documents = DocumentStore(self._runtime)
        async with self._runtime.writing() as session:
            try:
                for core, doc_id, data in puts:
                    await documents._save_quota_doc(session, core, doc_id, data)
                for core, doc_id in deletes:
                    await session.execute(delete(Quota).where(Quota.core_id == core, Quota.client_id == doc_id))
                    await session.execute(delete(Client).where(Client.core_id == core, Client.id == doc_id))
                scope = current_scope()
                for core, key, incoming, outgoing in ack_upserts:
                    await session.merge(
                        TrafficAck(
                            scope=scope,
                            core=core,
                            client_key=key,
                            incoming=incoming,
                            outgoing=outgoing,
                            updated_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                for core, key in ack_deletes:
                    await session.execute(
                        delete(TrafficAck).where(
                            TrafficAck.scope == scope,
                            TrafficAck.core == core,
                            TrafficAck.client_key == key,
                        )
                    )
                for core, key, delta_in, delta_out, current_in, current_out in pending_upserts:
                    await self._upsert_pending(
                        session,
                        scope,
                        {
                            "core": core,
                            "client_key": key,
                            "delta_incoming": delta_in,
                            "delta_outgoing": delta_out,
                            "current_incoming": current_in,
                            "current_outgoing": current_out,
                        },
                    )
                for core, key in pending_deletes:
                    await session.execute(
                        delete(TrafficPending).where(
                            TrafficPending.scope == scope,
                            TrafficPending.core == core,
                            TrafficPending.client_key == key,
                        )
                    )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
