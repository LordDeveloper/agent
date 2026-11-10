from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select

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
            ack_rows = (
                await session.execute(
                    select(TrafficAck).where(TrafficAck.client_key == key).order_by(TrafficAck.core)
                )
            ).scalars().all()
            pending_rows = (
                await session.execute(
                    select(TrafficPending).where(TrafficPending.client_key == key).order_by(TrafficPending.core)
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
            row = await session.get(TrafficAck, (core, client_key))
            if row is None:
                return None
            return {"incoming": int(row.incoming), "outgoing": int(row.outgoing)}

    async def set_traffic_ack(self, core: str, client_key: str, incoming: int, outgoing: int) -> None:
        async with self._runtime.writing() as session:
            row = await session.get(TrafficAck, (core, client_key))
            if row is None:
                session.add(
                    TrafficAck(
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
            await session.execute(
                delete(TrafficAck).where(TrafficAck.core == core, TrafficAck.client_key == client_key)
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
            row = await session.get(TrafficPending, (core, client_key))
            if row is None:
                session.add(
                    TrafficPending(
                        core=core,
                        client_key=client_key,
                        delta_incoming=int(delta_incoming),
                        delta_outgoing=int(delta_outgoing),
                        current_incoming=int(current_incoming),
                        current_outgoing=int(current_outgoing),
                        updated_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            else:
                row.delta_incoming = int(delta_incoming)
                row.delta_outgoing = int(delta_outgoing)
                row.current_incoming = int(current_incoming)
                row.current_outgoing = int(current_outgoing)
                row.updated_at = datetime.now(timezone.utc).isoformat()
            await session.commit()

    async def delete_traffic_pending(self, core: str, client_key: str) -> None:
        async with self._runtime.writing() as session:
            await session.execute(
                delete(TrafficPending).where(TrafficPending.core == core, TrafficPending.client_key == client_key)
            )
            await session.commit()

    async def get_traffic_pending(self, core: str, client_key: str) -> dict[str, Any] | None:
        async with self._runtime.reading() as session:
            row = await session.get(TrafficPending, (core, client_key))
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
            rows = (
                await session.execute(select(TrafficPending).order_by(TrafficPending.core, TrafficPending.client_key))
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
            count = await session.scalar(select(func.count()).select_from(TrafficPending))
            return int(count or 0)

    async def list_traffic_identity(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (
                await session.execute(
                    select(TrafficIdentity).order_by(TrafficIdentity.core, TrafficIdentity.alias)
                )
            ).scalars().all()
            return [
                {"core": row.core, "alias": row.alias, "canonical_key": row.canonical_key}
                for row in rows
            ]

    async def _traffic_books(self) -> tuple[
        dict[tuple[str, str], tuple[int, int]],
        dict[tuple[str, str], dict[str, int]],
    ]:
        async with self._runtime.reading() as session:
            ack_rows = (await session.execute(select(TrafficAck))).scalars().all()
            acks = {
                (str(row.core), str(row.client_key)): (int(row.incoming), int(row.outgoing))
                for row in ack_rows
            }
            pending_rows = (await session.execute(select(TrafficPending))).scalars().all()
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

    async def apply_traffic_sample(self, plan) -> dict[str, int]:
        acks, pending = await self._traffic_books()
        writes = plan(acks, pending)
        await self._runtime.retry_locked(lambda: self._commit_traffic_plan(writes))
        stats = dict(writes.get("stats") or {})
        stats["pending"] = await self.count_traffic_pending()
        return stats

    async def _commit_traffic_plan(self, writes: dict[str, Any]) -> None:
        async with self._runtime.writing() as session:
            try:
                await self._write_traffic_plan(session, writes)
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def _write_traffic_plan(self, session, writes: dict[str, Any]) -> None:
        pending = 0
        for core, client_key, incoming, outgoing in writes.get("ack_upserts") or []:
            row = await session.get(TrafficAck, (core, client_key))
            if row is None:
                session.add(
                    TrafficAck(
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
            pending = await self._runtime.commit_chunk(session, pending + 1)

        for core, client_key in writes.get("ack_deletes") or []:
            await session.execute(
                delete(TrafficAck).where(TrafficAck.core == core, TrafficAck.client_key == client_key)
            )
            pending = await self._runtime.commit_chunk(session, pending + 1)

        for item in writes.get("pending_upserts") or []:
            core = item["core"]
            client_key = item["client_key"]
            row = await session.get(TrafficPending, (core, client_key))
            if row is None:
                session.add(
                    TrafficPending(
                        core=core,
                        client_key=client_key,
                        delta_incoming=int(item["delta_incoming"]),
                        delta_outgoing=int(item["delta_outgoing"]),
                        current_incoming=int(item["current_incoming"]),
                        current_outgoing=int(item["current_outgoing"]),
                        updated_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            else:
                row.delta_incoming = int(item["delta_incoming"])
                row.delta_outgoing = int(item["delta_outgoing"])
                row.current_incoming = int(item["current_incoming"])
                row.current_outgoing = int(item["current_outgoing"])
                row.updated_at = datetime.now(timezone.utc).isoformat()
            pending = await self._runtime.commit_chunk(session, pending + 1)

        for core, client_key in writes.get("pending_deletes") or []:
            await session.execute(
                delete(TrafficPending).where(TrafficPending.core == core, TrafficPending.client_key == client_key)
            )
            pending = await self._runtime.commit_chunk(session, pending + 1)

        for core, alias, canonical_key in writes.get("identity_upserts") or []:
            row = await session.get(TrafficIdentity, (core, alias))
            if row is None:
                session.add(TrafficIdentity(core=core, alias=alias, canonical_key=canonical_key))
            else:
                row.canonical_key = canonical_key
            pending = await self._runtime.commit_chunk(session, pending + 1)

        meta = writes.get("meta")
        if isinstance(meta, tuple) and len(meta) == 3:
            from agent.services.meta_service import MetaService

            core, key, value = meta
            meta_svc = MetaService(self._runtime)
            await meta_svc.set_meta(core, key, value)

    async def ack_traffic_rows(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        async with self._runtime.writing() as session:
            seen: set[tuple[str, str]] = set()
            for row in rows:
                key = (str(row["core"]), str(row["client_key"]))
                if key in seen:
                    continue
                seen.add(key)
                existing = await session.get(TrafficAck, key)
                if existing is None:
                    session.add(
                        TrafficAck(
                            core=key[0],
                            client_key=key[1],
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
                        TrafficPending.core == key[0],
                        TrafficPending.client_key == key[1],
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
                for core, key, incoming, outgoing in ack_upserts:
                    await session.merge(
                        TrafficAck(
                            core=core,
                            client_key=key,
                            incoming=incoming,
                            outgoing=outgoing,
                            updated_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                for core, key in ack_deletes:
                    await session.execute(
                        delete(TrafficAck).where(TrafficAck.core == core, TrafficAck.client_key == key)
                    )
                for core, key, delta_in, delta_out, current_in, current_out in pending_upserts:
                    await session.merge(
                        TrafficPending(
                            core=core,
                            client_key=key,
                            delta_incoming=delta_in,
                            delta_outgoing=delta_out,
                            current_incoming=current_in,
                            current_outgoing=current_out,
                            updated_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                for core, key in pending_deletes:
                    await session.execute(
                        delete(TrafficPending).where(TrafficPending.core == core, TrafficPending.client_key == key)
                    )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
