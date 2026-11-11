from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from agent.auth_scope import current_scope
from agent.database.models.traffic import TrafficAck, TrafficIdentity, TrafficPending
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
            await session.commit()

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        async with self._runtime.reading() as session:
            scope = current_scope()
            row = await session.get(TrafficPending, (scope, core, client_key))
            if row is None:
                return None
            return {
                "core": row.core,
                "client_key": row.client_key,
                "delta_incoming": row.delta_incoming,
                "delta_outgoing": row.delta_outgoing,
                "current_incoming": row.current_incoming,
                "current_outgoing": row.current_outgoing,
                "updated_at": row.updated_at,
            }

    async def list_traffic_pending(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            scope = current_scope()
            rows = (
                await session.execute(
                    select(TrafficPending)
                    .where(TrafficPending.scope == scope)
                    .order_by(TrafficPending.core, TrafficPending.client_key)
                )
            ).scalars().all()
            return [
                {
                    "core": row.core,
                    "client_key": row.client_key,
                    "delta_incoming": row.delta_incoming,
                    "delta_outgoing": row.delta_outgoing,
                    "current_incoming": row.current_incoming,
                    "current_outgoing": row.current_outgoing,
                    "updated_at": row.updated_at,
                }
                for row in rows
            ]

    async def count_traffic_pending(self) -> int:
        async with self._runtime.reading() as session:
            count = await session.scalar(
                select(func.count()).select_from(TrafficPending).where(TrafficPending.scope == current_scope())
            )
            return int(count or 0)

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
            pending_query = select(TrafficPending).where(TrafficPending.scope == scope)
            if core_name:
                ack_query = ack_query.where(TrafficAck.core == core_name)
                pending_query = pending_query.where(TrafficPending.core == core_name)
            ack_rows = (await session.execute(ack_query)).scalars().all()
            acks = {
                (str(row.core), str(row.client_key)): (int(row.incoming), int(row.outgoing))
                for row in ack_rows
            }
            pending_rows = (await session.execute(pending_query)).scalars().all()
            pending = {
                (str(row.core), str(row.client_key)): {
                    "delta_incoming": int(row.delta_incoming),
                    "delta_outgoing": int(row.delta_outgoing),
                    "current_incoming": int(row.current_incoming),
                    "current_outgoing": int(row.current_outgoing),
                }
                for row in pending_rows
            }
            return acks, pending

    async def apply_traffic_sample(
        self,
        plan,
        scope: str | None = None,
        core: str | None = None,
    ) -> dict[str, int]:
        scope = str(scope or current_scope())
        acks, pending = await self._traffic_books(scope, core)
        writes = plan(acks, pending)
        if isinstance(writes, dict):
            writes["scope"] = scope
        await self._runtime.retry_locked(lambda: self._commit_traffic_plan(writes))
        stats = dict(writes.get("stats") or {})
        stats["pending"] = await self.count_traffic_pending()
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
        for core, alias, canonical_key in writes.get("identity_upserts") or []:
            row = await session.get(TrafficIdentity, (scope, core, alias))
            if row is None:
                session.add(TrafficIdentity(scope=scope, core=core, alias=alias, canonical_key=canonical_key))
            else:
                row.canonical_key = canonical_key
    async def ack_billed_snapshots(self, rows: list[dict[str, Any]]) -> None:
        """Drop only the pending bytes the panel already billed.

        Usage sampled after that read stays queued. A counter reset after the
        read keeps the baseline the sampler already moved; it is not rewound
        to the old snapshot.
        """
        if not rows:
            return
        async with self._runtime.writing() as session:
            scope = current_scope()
            seen: set[tuple[str, str, str]] = set()
            now = datetime.now(timezone.utc).isoformat()
            for snap in rows:
                core = str(snap.get("core") or "")
                client_key = str(snap.get("client_key") or "")
                key = (scope, core, client_key)
                if not core or not client_key or key in seen:
                    continue
                seen.add(key)
                live = await session.get(TrafficPending, key)
                ack = await session.get(TrafficAck, key)
                billed_in = int(snap.get("delta_incoming") or 0)
                billed_out = int(snap.get("delta_outgoing") or 0)
                snap_in = int(snap.get("current_incoming") or 0)
                snap_out = int(snap.get("current_outgoing") or 0)
                previous_in = int(ack.incoming) if ack is not None else None
                previous_out = int(ack.outgoing) if ack is not None else None
                if live is None:
                    ack_in, remain_in = self._settle_billed_direction(None, 0, snap_in, billed_in, previous_in)
                    ack_out, remain_out = self._settle_billed_direction(None, 0, snap_out, billed_out, previous_out)
                else:
                    ack_in, remain_in = self._settle_billed_direction(
                        int(live.current_incoming),
                        int(live.delta_incoming),
                        snap_in,
                        billed_in,
                        previous_in,
                    )
                    ack_out, remain_out = self._settle_billed_direction(
                        int(live.current_outgoing),
                        int(live.delta_outgoing),
                        snap_out,
                        billed_out,
                        previous_out,
                    )
                if ack is None:
                    session.add(
                        TrafficAck(
                            scope=scope,
                            core=core,
                            client_key=client_key,
                            incoming=ack_in,
                            outgoing=ack_out,
                            updated_at=now,
                        )
                    )
                else:
                    ack.incoming = ack_in
                    ack.outgoing = ack_out
                    ack.updated_at = now
                if live is None:
                    continue
                if remain_in or remain_out:
                    live.delta_incoming = remain_in
                    live.delta_outgoing = remain_out
                    live.updated_at = now
                else:
                    await session.delete(live)
            await session.commit()

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
