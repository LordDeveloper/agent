from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy import and_, bindparam, delete, func, or_, select, text, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from agent.auth_scope import current_scope
from agent.database.models.client import Client
from agent.database.models.traffic import (
    TrafficAck,
    TrafficIdentity,
    TrafficPending,
    TrafficPendingChunk,
    TrafficPendingClient,
)
from agent.database.session import DatabaseRuntime


def _sqlite(session) -> bool:
    return session.get_bind().dialect.name == "sqlite"


# One panel GET must answer inside the 20s client timeout. Ask for a client
# page instead of the whole backlog. Each client also returns only its oldest
# chunks, so one huge queue cannot fill the body by itself.
BILLING_CLIENT_PAGE = 100
BILLING_CHUNKS_PER_CLIENT = 200


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
        _, pending = await self._traffic_books(
            scope=current_scope(),
            core=core,
            client_key=client_key,
        )
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
                    "chunk_count": int(item.get("chunk_count") or 0),
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
            if _sqlite(session):
                row = (
                    await session.execute(
                        text(
                            "SELECT incoming, outgoing FROM clients INDEXED BY ix_clients_cursor "
                            "WHERE core_id = :core AND id = :client_id"
                        ),
                        {"core": str(core), "client_id": str(client_id)},
                    )
                ).first()
            else:
                row = (
                    await session.execute(
                        select(Client.incoming, Client.outgoing).where(
                            Client.core_id == str(core),
                            Client.id == str(client_id),
                        )
                    )
                ).first()
            if row is None or row[0] is None and row[1] is None:
                return None
            return int(row[0] or 0), int(row[1] or 0)

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

    async def _select_pending_chunk_rows(
        self,
        session,
        scope: str,
        limit: int | None = None,
    ) -> list[Any]:
        """Ordered chunk rows from the covering index, not a sort of the whole table."""
        if _sqlite(session):
            sql = (
                "SELECT chunk_id, core, client_key, incoming, outgoing, sampled_at "
                "FROM traffic_pending_chunk INDEXED BY ix_traffic_pending_chunk_totals "
                "WHERE scope = :scope "
                "ORDER BY core, client_key, sampled_at"
            )
            params: dict[str, Any] = {"scope": scope}
            if limit is not None and limit > 0:
                sql += " LIMIT :limit"
                params["limit"] = int(limit)
            return (await session.execute(text(sql), params)).all()
        query = (
            select(
                TrafficPendingChunk.chunk_id,
                TrafficPendingChunk.core,
                TrafficPendingChunk.client_key,
                TrafficPendingChunk.incoming,
                TrafficPendingChunk.outgoing,
                TrafficPendingChunk.sampled_at,
            )
            .where(TrafficPendingChunk.scope == scope)
            .order_by(
                TrafficPendingChunk.core,
                TrafficPendingChunk.client_key,
                TrafficPendingChunk.sampled_at,
            )
        )
        if limit is not None and limit > 0:
            query = query.limit(int(limit))
        return (await session.execute(query)).all()

    async def list_traffic_pending_chunks(self) -> list[dict[str, Any]]:
        scope = current_scope()
        async with self._runtime.reading() as session:
            rows = await self._select_pending_chunk_rows(session, scope)
            return [
                {
                    "chunk_id": str(chunk_id),
                    "core": core,
                    "client_key": client_key,
                    "incoming": int(incoming),
                    "outgoing": int(outgoing),
                    "sampled_at": sampled_at,
                }
                for chunk_id, core, client_key, incoming, outgoing, sampled_at in rows
            ]

    async def _pending_client_keys(self, session, scope: str, limit: int | None) -> list[tuple[str, str]]:
        """Clients in index order. The rollup is one row per client, so LIMIT stops there."""
        if _sqlite(session):
            sql = (
                "SELECT core, client_key FROM traffic_pending_client "
                "WHERE scope = :scope AND chunk_count > 0 "
                "ORDER BY core, client_key"
            )
            params: dict[str, Any] = {"scope": scope}
            if limit is not None and limit > 0:
                sql += " LIMIT :limit"
                params["limit"] = int(limit)
            rows = (await session.execute(text(sql), params)).all()
        else:
            query = (
                select(TrafficPendingChunk.core, TrafficPendingChunk.client_key)
                .where(TrafficPendingChunk.scope == scope)
                .group_by(TrafficPendingChunk.core, TrafficPendingChunk.client_key)
                .order_by(TrafficPendingChunk.core, TrafficPendingChunk.client_key)
            )
            if limit is not None and limit > 0:
                query = query.limit(int(limit))
            rows = (await session.execute(query)).all()
        return [(str(core), str(client_key)) for core, client_key in rows]

    async def _select_client_chunks(
        self,
        session,
        scope: str,
        core: str,
        client_key: str,
        limit: int | None,
    ) -> list[Any]:
        if _sqlite(session):
            sql = (
                "SELECT chunk_id, core, client_key, incoming, outgoing, sampled_at "
                "FROM traffic_pending_chunk INDEXED BY ix_traffic_pending_chunk_totals "
                "WHERE scope = :scope AND core = :core AND client_key = :client "
                "ORDER BY sampled_at"
            )
            params: dict[str, Any] = {"scope": scope, "core": core, "client": client_key}
            if limit is not None and limit > 0:
                sql += " LIMIT :limit"
                params["limit"] = int(limit)
            return (await session.execute(text(sql), params)).all()
        query = (
            select(
                TrafficPendingChunk.chunk_id,
                TrafficPendingChunk.core,
                TrafficPendingChunk.client_key,
                TrafficPendingChunk.incoming,
                TrafficPendingChunk.outgoing,
                TrafficPendingChunk.sampled_at,
            )
            .where(
                TrafficPendingChunk.scope == scope,
                TrafficPendingChunk.core == core,
                TrafficPendingChunk.client_key == client_key,
            )
            .order_by(TrafficPendingChunk.sampled_at)
        )
        if limit is not None and limit > 0:
            query = query.limit(int(limit))
        return (await session.execute(query)).all()

    async def load_pending_billing(
        self,
        *,
        client_limit: int | None = None,
        chunks_per_client: int | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
        """One page of clients, oldest chunks first.

        Totals count only the chunks in this page, so the following ack deletes
        the same bytes. ``client_limit`` None reads every client.
        """
        scope = current_scope()
        client_fetch = int(client_limit) + 1 if client_limit is not None and client_limit > 0 else None
        chunk_fetch = (
            int(chunks_per_client) + 1 if chunks_per_client is not None and chunks_per_client > 0 else None
        )
        async with self._runtime.reading() as session:
            client_keys = await self._pending_client_keys(session, scope, client_fetch)
            truncated = client_fetch is not None and len(client_keys) >= client_fetch
            if truncated:
                client_keys = client_keys[: int(client_limit)]
            chunk_rows: list[Any] = []
            for core, client_key in client_keys:
                found = await self._select_client_chunks(session, scope, core, client_key, chunk_fetch)
                if chunk_fetch is not None and len(found) >= chunk_fetch:
                    truncated = True
                    found = found[: int(chunks_per_client)]
                chunk_rows.extend(found)
            chunks: list[dict[str, Any]] = []
            pending: dict[tuple[str, str], dict[str, int]] = {}
            for chunk_id, core, client_key, incoming, outgoing, sampled_at in chunk_rows:
                key = (str(core), str(client_key))
                agg = pending.setdefault(
                    key,
                    {
                        "delta_incoming": 0,
                        "delta_outgoing": 0,
                        "current_incoming": 0,
                        "current_outgoing": 0,
                    },
                )
                agg["delta_incoming"] += int(incoming)
                agg["delta_outgoing"] += int(outgoing)
                chunks.append(
                    {
                        "chunk_id": str(chunk_id),
                        "core": key[0],
                        "client_key": key[1],
                        "incoming": int(incoming),
                        "outgoing": int(outgoing),
                        "sampled_at": sampled_at,
                    }
                )
            legacy = (
                await session.execute(
                    select(
                        TrafficPending.core,
                        TrafficPending.client_key,
                        TrafficPending.delta_incoming,
                        TrafficPending.delta_outgoing,
                        TrafficPending.current_incoming,
                        TrafficPending.current_outgoing,
                    ).where(TrafficPending.scope == scope)
                )
            ).all()
            for core, client_key, delta_in, delta_out, current_in, current_out in legacy:
                key = (str(core), str(client_key))
                if key in pending or truncated:
                    continue
                pending[key] = {
                    "delta_incoming": int(delta_in),
                    "delta_outgoing": int(delta_out),
                    "current_incoming": int(current_in),
                    "current_outgoing": int(current_out),
                }
        rows = [
            {
                "core": core,
                "client_key": client_key,
                "delta_incoming": int(item["delta_incoming"]),
                "delta_outgoing": int(item["delta_outgoing"]),
                "current_incoming": int(item["current_incoming"]),
                "current_outgoing": int(item["current_outgoing"]),
                "updated_at": None,
            }
            for (core, client_key), item in sorted(pending.items())
        ]
        return chunks, rows, truncated

    async def rehome_pending_scopes(self) -> int:
        """Move default-scope queue rows onto the auth-token scope of their client.

        The sampler used to stamp every chunk with the worker scope. A panel
        that connects with its own token then reads an empty queue.
        """
        from agent.auth_scope import DEFAULT_SCOPE

        moved = 0
        while moved < 50000:
            count = await self._rehome_chunk_batch(DEFAULT_SCOPE, 1000)
            moved += count
            if count < 1000:
                break
        await self._rehome_legacy_pending(DEFAULT_SCOPE)
        await self._rehome_identity(DEFAULT_SCOPE)
        return moved

    async def _rehome_chunk_batch(self, default_scope: str, limit: int) -> int:
        async with self._runtime.writing() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT c.chunk_id, c.core, c.client_key, c.incoming, c.outgoing, "
                        "c.sampled_at, cl.scope "
                        "FROM traffic_pending_chunk AS c "
                        "JOIN clients AS cl ON cl.core_id = c.core AND cl.id = c.client_key "
                        "WHERE c.scope = :default_scope "
                        "AND cl.scope != :default_scope "
                        "AND cl.scope != '' "
                        "LIMIT :limit"
                    ),
                    {"default_scope": default_scope, "limit": int(limit)},
                )
            ).all()
            if not rows:
                return 0
            ids = [str(chunk_id) for chunk_id, *_rest in rows]
            await session.execute(
                delete(TrafficPendingChunk).where(
                    TrafficPendingChunk.scope == default_scope,
                    TrafficPendingChunk.chunk_id.in_(ids),
                )
            )
            session.add_all(
                [
                    TrafficPendingChunk(
                        scope=str(owner_scope),
                        chunk_id=str(chunk_id),
                        core=str(core),
                        client_key=str(client_key),
                        incoming=int(incoming or 0),
                        outgoing=int(outgoing or 0),
                        sampled_at=str(sampled_at),
                    )
                    for chunk_id, core, client_key, incoming, outgoing, sampled_at, owner_scope in rows
                ]
            )
            await session.commit()
        return len(rows)

    async def _rehome_legacy_pending(self, default_scope: str) -> None:
        async with self._runtime.writing() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT p.core, p.client_key, p.delta_incoming, p.delta_outgoing, "
                        "p.current_incoming, p.current_outgoing, cl.scope "
                        "FROM traffic_pending AS p "
                        "JOIN clients AS cl ON cl.core_id = p.core AND cl.id = p.client_key "
                        "WHERE p.scope = :default_scope "
                        "AND cl.scope != :default_scope "
                        "AND cl.scope != ''"
                    ),
                    {"default_scope": default_scope},
                )
            ).all()
            if not rows:
                return
            for core, client_key, delta_in, delta_out, current_in, current_out, owner_scope in rows:
                await session.execute(
                    delete(TrafficPending).where(
                        TrafficPending.scope == default_scope,
                        TrafficPending.core == str(core),
                        TrafficPending.client_key == str(client_key),
                    )
                )
                await self._upsert_pending(
                    session,
                    str(owner_scope),
                    {
                        "core": str(core),
                        "client_key": str(client_key),
                        "delta_incoming": int(delta_in or 0),
                        "delta_outgoing": int(delta_out or 0),
                        "current_incoming": int(current_in or 0),
                        "current_outgoing": int(current_out or 0),
                    },
                )
            await session.commit()

    async def _rehome_identity(self, default_scope: str) -> None:
        async with self._runtime.writing() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT i.core, i.alias, i.canonical_key, cl.scope "
                        "FROM traffic_identity AS i "
                        "JOIN clients AS cl ON cl.core_id = i.core AND cl.id = i.canonical_key "
                        "WHERE i.scope = :default_scope "
                        "AND cl.scope != :default_scope "
                        "AND cl.scope != ''"
                    ),
                    {"default_scope": default_scope},
                )
            ).all()
            if not rows:
                return
            for core, alias, canonical_key, owner_scope in rows:
                await session.execute(
                    delete(TrafficIdentity).where(
                        TrafficIdentity.scope == default_scope,
                        TrafficIdentity.core == str(core),
                        TrafficIdentity.alias == str(alias),
                    )
                )
                existing = await session.get(TrafficIdentity, (str(owner_scope), str(core), str(alias)))
                if existing is None:
                    session.add(
                        TrafficIdentity(
                            scope=str(owner_scope),
                            core=str(core),
                            alias=str(alias),
                            canonical_key=str(canonical_key),
                        )
                    )
                else:
                    existing.canonical_key = str(canonical_key)
            await session.commit()

    async def ack_traffic_chunk_ids(self, chunk_ids: list[str]) -> tuple[int, list[str]]:
        """Delete billed chunks in batches. One statement per batch, not one per row.

        The previous loop held the SQLite write lock across a DELETE and a COUNT
        for every chunk. A few hundred clients with a backlog never answered
        inside the panel's 20s read, so curl reported 0 bytes.
        """
        ids = list(dict.fromkeys(str(item).strip() for item in chunk_ids if str(item or "").strip()))
        if not ids:
            return 0, []
        from agent.auth_scope import DEFAULT_SCOPE

        scope = current_scope()
        # The panel posts the chunk ids it billed. Delete those rows in this
        # token's scope, and the same ids still sitting in default from before
        # samples were filed under the token.
        scopes = [scope] if scope == DEFAULT_SCOPE else [scope, DEFAULT_SCOPE]
        found: set[str] = set()
        touched: dict[str, set[tuple[str, str]]] = defaultdict(set)
        async with self._runtime.writing() as session:
            for offset in range(0, len(ids), 1000):
                batch = ids[offset : offset + 1000]
                # Do not use DELETE RETURNING here. The AFTER DELETE trigger on
                # traffic_pending_chunk runs more statements, SQLite clears the
                # cursor description, and SQLAlchemy raises AttributeError.
                rows = (
                    await session.execute(
                        select(
                            TrafficPendingChunk.scope,
                            TrafficPendingChunk.chunk_id,
                            TrafficPendingChunk.core,
                            TrafficPendingChunk.client_key,
                        ).where(
                            TrafficPendingChunk.scope.in_(scopes),
                            TrafficPendingChunk.chunk_id.in_(batch),
                        )
                    )
                ).all()
                by_scope: dict[str, list[str]] = defaultdict(list)
                for row_scope, chunk_id, core, client_key in rows:
                    row_scope = str(row_scope)
                    chunk_id = str(chunk_id)
                    found.add(chunk_id)
                    by_scope[row_scope].append(chunk_id)
                    touched[row_scope].add((str(core), str(client_key)))
                for row_scope, matched in by_scope.items():
                    await session.execute(
                        delete(TrafficPendingChunk).where(
                            TrafficPendingChunk.scope == row_scope,
                            TrafficPendingChunk.chunk_id.in_(matched),
                        )
                    )
            for row_scope, clients in touched.items():
                await self._delete_legacy_pending(session, row_scope, clients)
            await session.commit()
        missing = [item for item in ids if item not in found]
        return len(found), missing

    async def drop_pending_client_keys(self, client_keys: list[str]) -> list[str]:
        """Delete one client's queue by key. Does not read any other client's chunks."""
        keys = list(dict.fromkeys(str(item).strip() for item in client_keys if str(item or "").strip()))
        if not keys:
            return []
        from agent.auth_scope import DEFAULT_SCOPE

        scope = current_scope()
        scopes = [scope] if scope == DEFAULT_SCOPE else [scope, DEFAULT_SCOPE]
        dropped: list[str] = []
        async with self._runtime.writing() as session:
            pairs: set[tuple[str, str, str]] = set()
            for offset in range(0, len(keys), 400):
                batch = keys[offset : offset + 400]
                rows = (
                    await session.execute(
                        select(
                            TrafficPendingClient.scope,
                            TrafficPendingClient.core,
                            TrafficPendingClient.client_key,
                        ).where(
                            TrafficPendingClient.scope.in_(scopes),
                            TrafficPendingClient.client_key.in_(batch),
                        )
                    )
                ).all()
                for row_scope, core, client_key in rows:
                    pairs.add((str(row_scope), str(core), str(client_key)))
                legacy = (
                    await session.execute(
                        select(
                            TrafficPending.scope,
                            TrafficPending.core,
                            TrafficPending.client_key,
                        ).where(
                            TrafficPending.scope.in_(scopes),
                            TrafficPending.client_key.in_(batch),
                        )
                    )
                ).all()
                for row_scope, core, client_key in legacy:
                    pairs.add((str(row_scope), str(core), str(client_key)))
            by_scope_core: dict[tuple[str, str], list[str]] = defaultdict(list)
            legacy_by_scope: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for row_scope, core, client_key in pairs:
                by_scope_core[(row_scope, core)].append(client_key)
                legacy_by_scope[row_scope].add((core, client_key))
                dropped.append(client_key)
            for (row_scope, core), client_ids in by_scope_core.items():
                unique_ids = list(dict.fromkeys(client_ids))
                for offset in range(0, len(unique_ids), 50):
                    batch = unique_ids[offset : offset + 50]
                    await session.execute(
                        delete(TrafficPendingChunk).where(
                            TrafficPendingChunk.scope == row_scope,
                            TrafficPendingChunk.core == core,
                            TrafficPendingChunk.client_key.in_(batch),
                        )
                    )
            for row_scope, clients in legacy_by_scope.items():
                await self._delete_legacy_pending(session, row_scope, clients)
            await session.commit()
        return list(dict.fromkeys(dropped))

    async def _delete_legacy_pending(
        self,
        session,
        scope: str,
        clients: set[tuple[str, str]],
    ) -> None:
        """Drop old aggregate rows for these clients. The chunk index is not scanned."""
        by_core: dict[str, list[str]] = defaultdict(list)
        for core, client_key in clients:
            if core and client_key:
                by_core[core].append(client_key)
        for core, client_ids in by_core.items():
            unique_ids = list(dict.fromkeys(client_ids))
            for offset in range(0, len(unique_ids), 400):
                batch = unique_ids[offset : offset + 400]
                await session.execute(
                    delete(TrafficPending).where(
                        TrafficPending.scope == scope,
                        TrafficPending.core == core,
                        TrafficPending.client_key.in_(batch),
                    )
                )

    async def list_traffic_identity(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (
                await session.execute(
                    select(
                        TrafficIdentity.core,
                        TrafficIdentity.alias,
                        TrafficIdentity.canonical_key,
                    )
                    .where(TrafficIdentity.scope == current_scope())
                    .order_by(TrafficIdentity.core, TrafficIdentity.alias)
                )
            ).all()
            return [
                {"core": core, "alias": alias, "canonical_key": canonical_key}
                for core, alias, canonical_key in rows
            ]

    async def _select_cursors(
        self,
        session,
        keys: list[tuple[str, str]] | set[tuple[str, str]],
    ) -> dict[tuple[str, str], tuple[int, int]]:
        """Read kernel cursors from the covering index, not the client JSON row."""
        by_core: dict[str, list[str]] = defaultdict(list)
        for core_name, client_id in keys:
            core_text = str(core_name or "").strip()
            client_text = str(client_id or "").strip()
            if core_text and client_text:
                by_core[core_text].append(client_text)
        found: dict[tuple[str, str], tuple[int, int]] = {}
        sqlite = _sqlite(session)
        keyed = text(
            "SELECT core_id, id, incoming, outgoing FROM clients INDEXED BY ix_clients_cursor "
            "WHERE core_id = :core AND id IN :ids"
        ).bindparams(bindparam("ids", expanding=True))
        for core_name, client_ids in by_core.items():
            unique_ids = list(dict.fromkeys(client_ids))
            for offset in range(0, len(unique_ids), 400):
                batch = unique_ids[offset : offset + 400]
                if sqlite:
                    result = await session.execute(keyed, {"core": core_name, "ids": batch})
                else:
                    result = await session.execute(
                        select(Client.core_id, Client.id, Client.incoming, Client.outgoing).where(
                            Client.core_id == core_name,
                            Client.id.in_(batch),
                        )
                    )
                for core_id, client_id, incoming, outgoing in result.all():
                    if incoming is None and outgoing is None:
                        continue
                    found[(str(core_id), str(client_id))] = (int(incoming or 0), int(outgoing or 0))
        return found

    async def _sum_pending_chunks(
        self,
        session,
        scope: str,
        core_name: str,
        client_name: str,
    ) -> list[Any]:
        """Per-client sums. SQLite reads the one-row rollup, not every chunk."""
        if _sqlite(session):
            sql = (
                "SELECT core, client_key, incoming, outgoing, chunk_count "
                "FROM traffic_pending_client "
                "WHERE scope = :scope AND chunk_count > 0"
            )
            params: dict[str, Any] = {"scope": scope}
            if core_name:
                sql += " AND core = :core"
                params["core"] = core_name
            if client_name:
                sql += " AND client_key = :client"
                params["client"] = client_name
            return (await session.execute(text(sql), params)).all()
        query = (
            select(
                TrafficPendingChunk.core,
                TrafficPendingChunk.client_key,
                func.coalesce(func.sum(TrafficPendingChunk.incoming), 0),
                func.coalesce(func.sum(TrafficPendingChunk.outgoing), 0),
                func.count(),
            )
            .where(TrafficPendingChunk.scope == scope)
            .group_by(TrafficPendingChunk.core, TrafficPendingChunk.client_key)
        )
        if core_name:
            query = query.where(TrafficPendingChunk.core == core_name)
        if client_name:
            query = query.where(TrafficPendingChunk.client_key == client_name)
        return (await session.execute(query)).all()

    async def _traffic_books(
        self,
        scope: str | None = None,
        core: str | None = None,
        client_key: str | None = None,
    ) -> tuple[
        dict[tuple[str, str], tuple[int, int]],
        dict[tuple[str, str], dict[str, int]],
    ]:
        scope = str(scope or current_scope())
        core_name = str(core or "").strip()
        client_name = str(client_key or "").strip()
        async with self._runtime.reading() as session:
            ack_query = select(
                TrafficAck.core,
                TrafficAck.client_key,
                TrafficAck.incoming,
                TrafficAck.outgoing,
            ).where(TrafficAck.scope == scope)
            if core_name:
                ack_query = ack_query.where(TrafficAck.core == core_name)
            if client_name:
                ack_query = ack_query.where(TrafficAck.client_key == client_name)
            acks = {
                (str(ack_core), str(ack_key)): (int(incoming), int(outgoing))
                for ack_core, ack_key, incoming, outgoing in (await session.execute(ack_query)).all()
            }
            pending: dict[tuple[str, str], dict[str, int]] = {}
            summed = await self._sum_pending_chunks(session, scope, core_name, client_name)
            for chunk_core, chunk_key, incoming, outgoing, chunk_count in summed:
                pending[(str(chunk_core), str(chunk_key))] = {
                    "delta_incoming": int(incoming or 0),
                    "delta_outgoing": int(outgoing or 0),
                    "current_incoming": 0,
                    "current_outgoing": 0,
                    "chunk_count": int(chunk_count or 0),
                }
            cursor_map = await self._select_cursors(session, list(pending))
            for key, agg in pending.items():
                cursor = cursor_map.get(key, (0, 0))
                agg["current_incoming"] = int(cursor[0])
                agg["current_outgoing"] = int(cursor[1])
            legacy_query = select(
                TrafficPending.core,
                TrafficPending.client_key,
                TrafficPending.delta_incoming,
                TrafficPending.delta_outgoing,
                TrafficPending.current_incoming,
                TrafficPending.current_outgoing,
            ).where(TrafficPending.scope == scope)
            if core_name:
                legacy_query = legacy_query.where(TrafficPending.core == core_name)
            if client_name:
                legacy_query = legacy_query.where(TrafficPending.client_key == client_name)
            for row_core, row_key, delta_in, delta_out, current_in, current_out in (
                await session.execute(legacy_query)
            ).all():
                key = (str(row_core), str(row_key))
                if key in pending:
                    # Chunk rows are authoritative; legacy TrafficPending deltas must not stack.
                    continue
                pending[key] = {
                    "delta_incoming": int(delta_in),
                    "delta_outgoing": int(delta_out),
                    "current_incoming": int(current_in),
                    "current_outgoing": int(current_out),
                }
            return acks, pending

    async def load_client_traffic_cursors(
        self,
        scope: str | None = None,
        core: str | None = None,
    ) -> dict[tuple[str, str], tuple[int, int]]:
        scope = str(scope or current_scope())
        core_name = str(core or "").strip()
        async with self._runtime.reading() as session:
            if _sqlite(session):
                sql = (
                    "SELECT core_id, id, incoming, outgoing FROM clients "
                    "INDEXED BY ix_clients_scope_cursor WHERE scope = :scope"
                )
                params: dict[str, Any] = {"scope": scope}
                if core_name:
                    sql += " AND core_id = :core"
                    params["core"] = core_name
                rows = (await session.execute(text(sql), params)).all()
            else:
                client_query = select(Client.core_id, Client.id, Client.incoming, Client.outgoing).where(
                    Client.scope == scope
                )
                if core_name:
                    client_query = client_query.where(Client.core_id == core_name)
                rows = (await session.execute(client_query)).all()
            found: dict[tuple[str, str], tuple[int, int]] = {}
            for core_id, client_id, incoming, outgoing in rows:
                if incoming is None and outgoing is None:
                    continue
                found[(str(core_id), str(client_id))] = (int(incoming or 0), int(outgoing or 0))
            return await self._merge_identity_cursors(scope, found, session)

    async def _merge_identity_cursors(
        self,
        scope: str,
        cursors: dict[tuple[str, str], tuple[int, int]],
        session,
    ) -> dict[tuple[str, str], tuple[int, int]]:
        if not cursors:
            return cursors
        merged = dict(cursors)
        cores = sorted({core for core, _key in cursors})
        rows = (
            await session.execute(
                select(
                    TrafficIdentity.core,
                    TrafficIdentity.alias,
                    TrafficIdentity.canonical_key,
                ).where(
                    TrafficIdentity.scope == scope,
                    TrafficIdentity.core.in_(cores),
                )
            )
        ).all()
        for core, alias, canonical in rows:
            core = str(core or "").strip()
            alias = str(alias or "").strip()
            canonical = str(canonical or "").strip()
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
            # Keep the node_id cursor. A higher alias is a stale baseline and
            # would make every later sample bill the whole live counter again.
        return merged

    async def load_client_traffic_cursors_for_keys(
        self,
        scope: str | None = None,
        keys: set[tuple[str, str]] | None = None,
    ) -> dict[tuple[str, str], tuple[int, int]]:
        scope = str(scope or current_scope())
        if not keys:
            return {}
        async with self._runtime.reading() as session:
            found = await self._select_cursors(session, keys)
            return await self._merge_identity_cursors(scope, found, session)

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
        if by_core:
            await session.flush()

        existing: set[tuple[str, str]] = set()
        for core_name, rows in by_core.items():
            client_ids = list(dict.fromkeys(item[0] for item in rows))
            for offset in range(0, len(client_ids), 400):
                batch = client_ids[offset : offset + 400]
                if _sqlite(session):
                    result = await session.execute(
                        text(
                            "SELECT core_id, id FROM clients INDEXED BY ix_clients_cursor "
                            "WHERE core_id = :core AND id IN :ids"
                        ).bindparams(bindparam("ids", expanding=True)),
                        {"core": core_name, "ids": batch},
                    )
                else:
                    result = await session.execute(
                        select(Client.core_id, Client.id).where(
                            Client.core_id == core_name,
                            Client.id.in_(batch),
                        )
                    )
                for core_id, client_id in result.all():
                    existing.add((str(core_id), str(client_id)))

        updates: list[dict[str, Any]] = []
        for core_name, rows in by_core.items():
            for client_id, incoming, outgoing in rows:
                key = (core_name, client_id)
                if key not in existing:
                    session.add(
                        Client(
                            core_id=core_name,
                            id=client_id,
                            scope=scope,
                            incoming=int(incoming),
                            outgoing=int(outgoing),
                        )
                    )
                    existing.add(key)
                    continue
                updates.append(
                    {
                        "core_id": core_name,
                        "id": client_id,
                        "incoming": int(incoming),
                        "outgoing": int(outgoing),
                    }
                )
        if updates:
            await session.execute(update(Client), updates)

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
        plans: dict[tuple[str, str], tuple[int, int]] = {}
        for snap in rows:
            core = str(snap.get("core") or "")
            client_key = str(snap.get("client_key") or "")
            pair = (core, client_key)
            if not core or not client_key or pair in plans:
                continue
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
            plans[pair] = (take_in, take_out)
        if not plans:
            return
        async with self._runtime.writing() as session:
            scope = current_scope()
            by_core: dict[str, list[str]] = defaultdict(list)
            for core, client_key in plans:
                by_core[core].append(client_key)
            chunks_by_client: dict[tuple[str, str], list[TrafficPendingChunk]] = defaultdict(list)
            for core, client_ids in by_core.items():
                unique_ids = list(dict.fromkeys(client_ids))
                for offset in range(0, len(unique_ids), 400):
                    batch = unique_ids[offset : offset + 400]
                    found = (
                        await session.execute(
                            select(TrafficPendingChunk)
                            .where(
                                TrafficPendingChunk.scope == scope,
                                TrafficPendingChunk.core == core,
                                TrafficPendingChunk.client_key.in_(batch),
                            )
                            .order_by(TrafficPendingChunk.sampled_at)
                        )
                    ).scalars().all()
                    for chunk in found:
                        chunks_by_client[(core, str(chunk.client_key))].append(chunk)
            delete_ids: list[str] = []
            for pair, (take_in, take_out) in plans.items():
                delete_ids.extend(
                    self._chunk_ids_consumed_fifo(chunks_by_client.get(pair, []), take_in, take_out)
                )
            for offset in range(0, len(delete_ids), 400):
                batch = delete_ids[offset : offset + 400]
                if not batch:
                    continue
                await session.execute(
                    delete(TrafficPendingChunk).where(
                        TrafficPendingChunk.scope == scope,
                        TrafficPendingChunk.chunk_id.in_(batch),
                    )
                )
            await self._delete_pending_without_chunks(session, scope, set(plans))
            await session.commit()

    async def _delete_pending_without_chunks(
        self,
        session,
        scope: str,
        clients: set[tuple[str, str]],
    ) -> None:
        by_core: dict[str, list[str]] = defaultdict(list)
        for core, client_key in clients:
            if core and client_key:
                by_core[core].append(client_key)
        for core, client_ids in by_core.items():
            unique_ids = list(dict.fromkeys(client_ids))
            for offset in range(0, len(unique_ids), 400):
                batch = unique_ids[offset : offset + 400]
                await session.execute(
                    delete(TrafficPending).where(
                        TrafficPending.scope == scope,
                        TrafficPending.core == core,
                        TrafficPending.client_key.in_(batch),
                        ~select(TrafficPendingChunk.chunk_id)
                        .where(
                            TrafficPendingChunk.scope == TrafficPending.scope,
                            TrafficPendingChunk.core == TrafficPending.core,
                            TrafficPendingChunk.client_key == TrafficPending.client_key,
                        )
                        .exists(),
                    )
                )

    @staticmethod
    def _chunk_ids_consumed_fifo(
        chunks: list[TrafficPendingChunk],
        take_incoming: int,
        take_outgoing: int,
    ) -> list[str]:
        remaining_in = int(take_incoming)
        remaining_out = int(take_outgoing)
        consumed: list[str] = []
        for chunk in chunks:
            if remaining_in <= 0 and remaining_out <= 0:
                break
            chunk_in = int(chunk.incoming)
            chunk_out = int(chunk.outgoing)
            if chunk_in <= remaining_in and chunk_out <= remaining_out:
                remaining_in -= chunk_in
                remaining_out -= chunk_out
                consumed.append(str(chunk.chunk_id))
        return consumed

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
