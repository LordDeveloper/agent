from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import selectinload

from agent.auth_scope import DEFAULT_SCOPE, SHARED_CORES, current_scope, row_visible, storage_scope
from agent.database.json_codec import decode_json, encode_json
from agent.database.models.client import Client, PARENT_INTERFACE, PARENT_SERVER
from agent.database.models.core import Core
from agent.database.models.core_artifact import CoreArtifact
from agent.database.models.interface import Interface
from agent.database.models.quota import Quota
from agent.database.models.resource_scope import ResourceScope
from agent.database.models.server import Server
from agent.database.session import DatabaseRuntime
from agent.services.legacy_compat import (
    assemble_interface,
    assemble_server,
    client_row_to_member,
    parent_type_for_kind,
    quota_row_to_document,
    split_interface_document,
    split_server_document,
)

QUOTA_KIND = "client_quota"
DISABLED_KIND = "xray_disabled_client"
ARTIFACT_KINDS = frozenset({"settings", "catalog", "location", "egress_state"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


class DocumentStore:
    def __init__(self, runtime: DatabaseRuntime):
        self._runtime = runtime

    async def _ensure_core(self, session, core: str) -> None:
        if not core:
            return
        exists = await session.get(Core, core)
        if exists is None:
            session.add(Core(id=core))

    async def put_doc(self, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        async with self._runtime.writing() as session:
            await self._ensure_core(session, core)
            if kind == "interface":
                await self._save_interface(session, core, str(doc_id), data)
            elif kind == "server":
                await self._save_server(session, core, str(doc_id), data)
            elif kind == QUOTA_KIND:
                await self._save_quota_doc(session, core, str(doc_id), data)
            elif kind == DISABLED_KIND:
                await self._save_disabled(session, core, str(doc_id), data)
            elif kind in ARTIFACT_KINDS:
                await self._save_artifact(session, core, kind, str(doc_id), data)
            else:
                await self._save_artifact(session, core, kind, str(doc_id), data)
            await session.commit()

    async def _save_interface(self, session, core: str, doc_id: str, data: dict[str, Any]) -> None:
        config, peers = split_interface_document(data)
        iface = await session.get(Interface, (core, doc_id))
        if iface is not None and not row_visible(core, iface.scope):
            return
        if iface is None:
            iface = Interface(
                core_id=core,
                id=doc_id,
                scope=storage_scope(core),
                config=config,
                updated_at=_now(),
            )
            session.add(iface)
        else:
            if str(core) in SHARED_CORES:
                iface.scope = DEFAULT_SCOPE
            iface.config = config
            iface.updated_at = _now()
        await session.flush()
        await self._sync_parent_members(
            session,
            core=core,
            parent_type=PARENT_INTERFACE,
            parent_id=doc_id,
            members=peers,
            role="peer",
            scope=str(iface.scope or DEFAULT_SCOPE),
        )

    async def _save_server(self, session, core: str, doc_id: str, data: dict[str, Any]) -> None:
        config, users = split_server_document(data)
        server = await session.get(Server, (core, doc_id))
        if server is not None and not row_visible(core, server.scope):
            return
        if server is None:
            server = Server(
                core_id=core,
                id=doc_id,
                scope=storage_scope(core),
                config=config,
                updated_at=_now(),
            )
            session.add(server)
        else:
            if str(core) in SHARED_CORES:
                server.scope = DEFAULT_SCOPE
            server.config = config
            server.updated_at = _now()
        await session.flush()
        await self._sync_parent_members(
            session,
            core=core,
            parent_type=PARENT_SERVER,
            parent_id=doc_id,
            members=users,
            role="user",
            scope=str(server.scope or DEFAULT_SCOPE),
        )

    async def _sync_parent_members(
        self,
        session,
        *,
        core: str,
        parent_type: str,
        parent_id: str,
        members: list[dict[str, Any]],
        role: str,
        scope: str,
    ) -> None:
        """Update peer/user rows in place.

        Deleting every child and inserting it again drops ``clients.incoming`` /
        ``outgoing`` (the traffic cursor) and, when SQLite foreign keys are on,
        cascades away unacked pending chunks. Stats sync then looks like a first
        sample and either bills the whole cumulative counter or bills nothing.
        """
        if parent_type == PARENT_INTERFACE:
            parent_filter = (
                Client.parent_interface_core_id == core,
                Client.parent_interface_id == parent_id,
            )
        else:
            parent_filter = (
                Client.parent_server_core_id == core,
                Client.parent_server_id == parent_id,
            )
        existing_ids = [
            str(item)
            for item in (
                await session.execute(
                    select(Client.id).where(Client.core_id == core, *parent_filter)
                )
            ).scalars().all()
        ]
        keep: set[str] = set()
        for member in members:
            client_id = str(member.get("node_id") or member.get("id") or "").strip()
            if not client_id:
                continue
            keep.add(client_id)
            await self._upsert_member(
                session,
                core=core,
                member=member,
                parent_type=parent_type,
                parent_core=core,
                parent_id=parent_id,
                role=role,
                client_id=client_id,
                scope=scope,
            )
        stale = [item for item in existing_ids if item not in keep]
        if not stale:
            return
        await session.execute(
            delete(Client).where(Client.core_id == core, Client.id.in_(stale))
        )

    async def _member_id(self, member: dict[str, Any], *, fallback: str = "") -> str:
        return str(member.get("node_id") or member.get("id") or fallback or "").strip()

    async def _upsert_member(
        self,
        session,
        *,
        core: str,
        member: dict[str, Any],
        parent_type: str,
        parent_core: str | None,
        parent_id: str | None,
        role: str,
        client_id: str | None = None,
        scope: str | None = None,
    ) -> None:
        client_id = str(client_id or await self._member_id(member) or "").strip()
        if not client_id:
            return
        meta = {
            k: v
            for k, v in member.items()
            if k
            not in {
                "id",
                "node_id",
                "email",
                "name",
                "is_enabled",
                "disabled_reason",
                "disabled_at",
                "volume",
                "_incoming",
                "_outgoing",
                "expires_at",
                "max_connection",
                "inbound_id",
                "inbound_tag",
            }
        }
        if role == "quota":
            if member.get("id") is not None:
                meta["id"] = member.get("id")
            if member.get("node_id") is not None:
                meta["node_id"] = member.get("node_id")
        row = await session.get(Client, (core, client_id))
        if row is None:
            row = Client(
                core_id=core,
                id=client_id,
                parent_type=parent_type,
                parent_interface_core_id=parent_core if parent_type == PARENT_INTERFACE else None,
                parent_interface_id=parent_id if parent_type == PARENT_INTERFACE else None,
                parent_server_core_id=parent_core if parent_type == PARENT_SERVER else None,
                parent_server_id=parent_id if parent_type == PARENT_SERVER else None,
                email=str(member.get("email") or "").strip() or None,
                name=str(member.get("name") or "").strip() or None,
                is_enabled=bool(member.get("is_enabled", True)),
                disabled_reason=str(member.get("disabled_reason") or "").strip() or None,
                disabled_at=str(member.get("disabled_at") or "").strip() or None,
                role=role,
                scope=str(scope or "").strip() or storage_scope(core),
                meta=meta,
                updated_at=_now(),
            )
            session.add(row)
        else:
            if not row_visible(core, row.scope):
                return
            row.parent_type = parent_type
            row.parent_interface_core_id = parent_core if parent_type == PARENT_INTERFACE else None
            row.parent_interface_id = parent_id if parent_type == PARENT_INTERFACE else None
            row.parent_server_core_id = parent_core if parent_type == PARENT_SERVER else None
            row.parent_server_id = parent_id if parent_type == PARENT_SERVER else None
            row.email = str(member.get("email") or "").strip() or None
            row.name = str(member.get("name") or "").strip() or None
            row.is_enabled = bool(member.get("is_enabled", True))
            row.disabled_reason = str(member.get("disabled_reason") or "").strip() or None
            row.disabled_at = str(member.get("disabled_at") or "").strip() or None
            row.role = role
            row.meta = meta
            row.updated_at = _now()

    async def _save_quota_doc(self, session, core: str, doc_id: str, data: dict[str, Any]) -> None:
        client_id = str(doc_id or data.get("node_id") or data.get("id") or "").strip()
        if not client_id:
            return
        existing = await session.get(Client, (core, client_id))
        if existing is not None and not row_visible(core, existing.scope):
            return
        quota_meta = {
            k: v
            for k, v in data.items()
            if k
            not in {
                "volume",
                "_incoming",
                "_outgoing",
                "expires_at",
                "max_connection",
                "inbound_id",
                "inbound_tag",
                "is_enabled",
            }
        }
        for key in ("agent_id", "primary_key", "client_link_uuid"):
            if key in data:
                quota_meta[key] = data[key]
        await self._upsert_member(
            session,
            core=core,
            member={**data, **quota_meta},
            parent_type="",
            parent_core=None,
            parent_id=None,
            role="quota",
            client_id=client_id,
        )
        client_row = await session.get(Client, (core, client_id))
        if client_row is not None:
            client_row.meta = quota_meta
        await session.flush()
        volume = data.get("volume")
        try:
            volume = int(volume) if volume is not None else None
        except (TypeError, ValueError):
            volume = None
        if volume is not None and volume < 0:
            volume = None
        row = await session.get(Quota, (core, client_id))
        if row is None:
            row = Quota(
                core_id=core,
                client_id=client_id,
                volume=volume,
                baseline_incoming=int(data.get("_incoming") or 0),
                baseline_outgoing=int(data.get("_outgoing") or 0),
                expires_at=data.get("expires_at"),
                max_connection=data.get("max_connection"),
                inbound_id=str(data.get("inbound_id") or "").strip() or None,
                inbound_tag=str(data.get("inbound_tag") or "").strip() or None,
                email=str(data.get("email") or "").strip() or None,
                protocol_id=str(data.get("client_link_uuid") or "").strip() or None,
                is_enabled=1 if data.get("is_enabled", True) else 0,
                updated_at=_now(),
            )
            session.add(row)
        else:
            row.volume = volume
            row.baseline_incoming = int(data.get("_incoming") or 0)
            row.baseline_outgoing = int(data.get("_outgoing") or 0)
            row.expires_at = data.get("expires_at")
            row.max_connection = data.get("max_connection")
            row.inbound_id = str(data.get("inbound_id") or "").strip() or None
            row.inbound_tag = str(data.get("inbound_tag") or "").strip() or None
            row.email = str(data.get("email") or "").strip() or None
            row.protocol_id = str(data.get("client_link_uuid") or data.get("id") or "").strip() or None
            row.is_enabled = 1 if data.get("is_enabled", True) else 0
            row.updated_at = _now()

    async def _save_disabled(self, session, core: str, doc_id: str, data: dict[str, Any]) -> None:
        existing = await session.get(Client, (core, str(doc_id)))
        if existing is not None and not row_visible(core, existing.scope):
            return
        payload = dict(data)
        payload["is_enabled"] = False
        await self._upsert_member(
            session,
            core=core,
            member=payload,
            parent_type="",
            parent_core=None,
            parent_id=None,
            role="xray_disabled",
        )

    async def _save_artifact(self, session, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        row = await session.get(CoreArtifact, (core, kind, doc_id))
        if row is None:
            session.add(
                CoreArtifact(
                    core_id=core,
                    kind=kind,
                    artifact_id=doc_id,
                    data=dict(data),
                    updated_at=_now(),
                )
            )
        else:
            row.data = dict(data)
            row.updated_at = _now()

    async def delete_doc(self, core: str, kind: str, doc_id: str) -> bool:
        async with self._runtime.writing() as session:
            removed = False
            if kind == "interface":
                iface = await session.get(Interface, (core, str(doc_id)))
                if iface is None or not row_visible(core, iface.scope):
                    return False
                removed = True
                await session.execute(delete(Interface).where(Interface.core_id == core, Interface.id == str(doc_id)))
                await session.execute(
                    delete(Client).where(
                        Client.core_id == core,
                        Client.parent_interface_core_id == core,
                        Client.parent_interface_id == str(doc_id),
                    )
                )
            elif kind == "server":
                server = await session.get(Server, (core, str(doc_id)))
                if server is None or not row_visible(core, server.scope):
                    return False
                removed = True
                await session.execute(delete(Server).where(Server.core_id == core, Server.id == str(doc_id)))
                await session.execute(
                    delete(Client).where(
                        Client.core_id == core,
                        Client.parent_server_core_id == core,
                        Client.parent_server_id == str(doc_id),
                    )
                )
            elif kind == QUOTA_KIND:
                client = await session.get(Client, (core, str(doc_id)))
                if client is not None and not row_visible(core, client.scope):
                    return False
                removed = (await session.get(Quota, (core, str(doc_id)))) is not None
                await session.execute(delete(Quota).where(Quota.core_id == core, Quota.client_id == str(doc_id)))
                await session.execute(delete(Client).where(Client.core_id == core, Client.id == str(doc_id)))
            elif kind == DISABLED_KIND:
                client = await session.get(Client, (core, str(doc_id)))
                if client is None or not row_visible(core, client.scope):
                    return False
                removed = True
                await session.execute(delete(Client).where(Client.core_id == core, Client.id == str(doc_id)))
            else:
                removed = (await session.get(CoreArtifact, (core, kind, str(doc_id)))) is not None
                await session.execute(
                    delete(CoreArtifact).where(
                        CoreArtifact.core_id == core,
                        CoreArtifact.kind == kind,
                        CoreArtifact.artifact_id == str(doc_id),
                    )
                )
            await session.commit()
            return removed

    def _quota_as_document(self, row: Quota, client: Client | None) -> dict[str, Any]:
        meta = dict(client.meta or {}) if client else {}
        data = dict(meta)
        if row.volume is not None:
            data["volume"] = row.volume
        if row.baseline_incoming:
            data["_incoming"] = int(row.baseline_incoming)
        if row.baseline_outgoing:
            data["_outgoing"] = int(row.baseline_outgoing)
        if row.expires_at is not None:
            data["expires_at"] = row.expires_at
        if row.max_connection is not None:
            data["max_connection"] = row.max_connection
        if row.inbound_id:
            data["inbound_id"] = row.inbound_id
        if row.inbound_tag:
            data["inbound_tag"] = row.inbound_tag
        if row.email and not data.get("email"):
            data["email"] = row.email
        if "id" not in data:
            if meta:
                data["id"] = str(meta.get("id") or meta.get("node_id") or row.client_id)
            elif (
                row.volume is None
                and not row.baseline_incoming
                and not row.baseline_outgoing
                and not row.email
            ):
                data["id"] = row.client_id
        return data

    async def get_doc(self, core: str, kind: str, doc_id: str) -> dict[str, Any] | None:
        async with self._runtime.reading() as session:
            if kind == "interface":
                iface = await session.get(Interface, (core, str(doc_id)))
                if iface is None:
                    return None
                rows = (
                    await session.execute(
                        select(Client).where(
                            Client.core_id == core,
                            Client.parent_interface_core_id == core,
                            Client.parent_interface_id == str(doc_id),
                        )
                    )
                ).scalars().all()
                peers = [client_row_to_member(row) for row in rows]
                doc = assemble_interface(dict(iface.config or {}), peers)
                doc["scope"] = str(iface.scope or DEFAULT_SCOPE)
                return doc
            if kind == "server":
                server = await session.get(Server, (core, str(doc_id)))
                if server is None:
                    return None
                rows = (
                    await session.execute(
                        select(Client).where(
                            Client.core_id == core,
                            Client.parent_server_core_id == core,
                            Client.parent_server_id == str(doc_id),
                        )
                    )
                ).scalars().all()
                users = [client_row_to_member(row) for row in rows]
                doc = assemble_server(dict(server.config or {}), users)
                doc["scope"] = str(server.scope or DEFAULT_SCOPE)
                return doc
            if kind == QUOTA_KIND:
                row = await session.get(Quota, (core, str(doc_id)))
                if row is None:
                    return None
                client = await session.get(Client, (core, str(doc_id)))
                return self._quota_as_document(row, client)
            if kind == DISABLED_KIND:
                row = await session.get(Client, (core, str(doc_id)))
                return client_row_to_member(row) if row else None
            artifact = await session.get(CoreArtifact, (core, kind, str(doc_id)))
            return dict(artifact.data) if artifact else None

    async def get_server_shell(self, core: str, doc_id: str) -> dict[str, Any] | None:
        """Server config only. Does not load every user row."""
        async with self._runtime.reading() as session:
            row = await session.get(Server, (core, str(doc_id)))
            if row is None:
                return None
            return self._server_shell(row)

    async def list_server_shells(self, core: str) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (
                await session.execute(select(Server).where(Server.core_id == core).order_by(Server.id))
            ).scalars().all()
            return [self._server_shell(row) for row in rows]

    async def save_server_config(self, core: str, doc_id: str, data: dict[str, Any]) -> None:
        """Update the server row. Leave user rows in place.

        A full put_doc deletes and reinserts every user, which holds the SQLite
        write lock long enough that a concurrent GET returns zero bytes.
        """
        config, _users = split_server_document(data)
        async with self._runtime.writing() as session:
            await self._ensure_core(session, core)
            row = await session.get(Server, (core, str(doc_id)))
            if row is None or not row_visible(core, row.scope):
                return
            if str(core) in SHARED_CORES:
                row.scope = DEFAULT_SCOPE
            row.config = config
            row.updated_at = _now()
            await session.commit()

    @staticmethod
    def _server_shell(row: Server) -> dict[str, Any]:
        doc = dict(row.config or {})
        doc["scope"] = str(row.scope or DEFAULT_SCOPE)
        doc["users"] = []
        if doc.get("id") is None:
            doc["id"] = row.id
        return doc

    async def _members_by_parent(self, session, core: str, parent_type: str) -> dict[str, list[dict[str, Any]]]:
        if parent_type == PARENT_INTERFACE:
            stmt = select(Client).where(
                Client.core_id == core,
                Client.parent_type == PARENT_INTERFACE,
                Client.parent_interface_core_id == core,
            )
            parent_attr = "parent_interface_id"
        else:
            stmt = select(Client).where(
                Client.core_id == core,
                Client.parent_type == PARENT_SERVER,
                Client.parent_server_core_id == core,
            )
            parent_attr = "parent_server_id"
        stmt = stmt.order_by(Client.id)
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in (await session.execute(stmt)).scalars().all():
            parent_id = getattr(row, parent_attr)
            if parent_id:
                grouped[str(parent_id)].append(client_row_to_member(row))
        return grouped

    async def _quota_documents(self, session, core: str) -> list[tuple[str, dict[str, Any]]]:
        rows = await session.execute(
            select(Quota, Client)
            .outerjoin(
                Client,
                and_(Client.core_id == Quota.core_id, Client.id == Quota.client_id),
            )
            .where(Quota.core_id == core)
            .order_by(Quota.client_id)
        )
        return [
            (str(quota.client_id), self._quota_as_document(quota, client))
            for quota, client in rows.all()
        ]

    async def list_docs(self, core: str, kind: str) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        async with self._runtime.reading() as session:
            if kind == "interface":
                rows = (
                    await session.execute(
                        select(Interface).where(Interface.core_id == core).order_by(Interface.id)
                    )
                ).scalars().all()
                members = await self._members_by_parent(session, core, PARENT_INTERFACE)
                for iface in rows:
                    doc = assemble_interface(dict(iface.config or {}), members.get(str(iface.id), []))
                    doc["scope"] = str(iface.scope or DEFAULT_SCOPE)
                    docs.append(doc)
                return docs
            if kind == "server":
                rows = (
                    await session.execute(select(Server).where(Server.core_id == core).order_by(Server.id))
                ).scalars().all()
                members = await self._members_by_parent(session, core, PARENT_SERVER)
                for server in rows:
                    doc = assemble_server(dict(server.config or {}), members.get(str(server.id), []))
                    doc["scope"] = str(server.scope or DEFAULT_SCOPE)
                    docs.append(doc)
                return docs
            if kind == QUOTA_KIND:
                return [doc for _client_id, doc in await self._quota_documents(session, core)]
            if kind == DISABLED_KIND:
                rows = (
                    await session.execute(
                        select(Client).where(Client.core_id == core, Client.role == "xray_disabled")
                    )
                ).scalars().all()
                return [client_row_to_member(row) for row in rows]
            artifacts = (
                await session.execute(
                    select(CoreArtifact).where(CoreArtifact.core_id == core, CoreArtifact.kind == kind)
                )
            ).scalars().all()
            return [dict(item.data or {}) for item in artifacts]
        return docs

    async def write_docs(
        self,
        core: str,
        kind: str,
        puts: list[tuple[str, dict[str, Any]]],
        deletes: list[str] | None = None,
    ) -> None:
        await self._runtime.retry_locked(
            lambda: self._write_docs_once(core, kind, puts, deletes or [])
        )

    async def _write_docs_once(
        self,
        core: str,
        kind: str,
        puts: list[tuple[str, dict[str, Any]]],
        deletes: list[str],
    ) -> None:
        async with self._runtime.writing() as session:
            await self._ensure_core(session, core)
            for doc_id, data in puts:
                if kind == QUOTA_KIND:
                    await self._save_quota_doc(session, core, str(doc_id), data)
                elif kind == "interface":
                    await self._save_interface(session, core, str(doc_id), data)
                elif kind == "server":
                    await self._save_server(session, core, str(doc_id), data)
                elif kind == DISABLED_KIND:
                    await self._save_disabled(session, core, str(doc_id), data)
                else:
                    await self._save_artifact(session, core, kind, str(doc_id), data)
            for doc_id in deletes:
                if kind == QUOTA_KIND:
                    await session.execute(delete(Quota).where(Quota.core_id == core, Quota.client_id == str(doc_id)))
                    await session.execute(delete(Client).where(Client.core_id == core, Client.id == str(doc_id)))
                elif kind == "interface":
                    await session.execute(delete(Interface).where(Interface.core_id == core, Interface.id == str(doc_id)))
                elif kind == "server":
                    await session.execute(delete(Server).where(Server.core_id == core, Server.id == str(doc_id)))
                elif kind == DISABLED_KIND:
                    await session.execute(delete(Client).where(Client.core_id == core, Client.id == str(doc_id)))
                else:
                    await session.execute(
                        delete(CoreArtifact).where(
                            CoreArtifact.core_id == core,
                            CoreArtifact.kind == kind,
                            CoreArtifact.artifact_id == str(doc_id),
                        )
                    )
            await session.commit()

    async def replace_docs(
        self,
        core: str,
        kind: str,
        docs: list[dict[str, Any]],
        id_key: str = "id",
    ) -> None:
        async with self._runtime.writing() as session:
            await self._ensure_core(session, core)
            if kind == "interface":
                await session.execute(delete(Interface).where(Interface.core_id == core))
                await session.execute(
                    delete(Client).where(Client.core_id == core, Client.parent_type == PARENT_INTERFACE)
                )
            elif kind == "server":
                await session.execute(delete(Server).where(Server.core_id == core))
                await session.execute(delete(Client).where(Client.core_id == core, Client.parent_type == PARENT_SERVER))
            elif kind == QUOTA_KIND:
                await session.execute(delete(Quota).where(Quota.core_id == core))
            elif kind == DISABLED_KIND:
                await session.execute(delete(Client).where(Client.core_id == core, Client.role == "xray_disabled"))
            else:
                await session.execute(
                    delete(CoreArtifact).where(CoreArtifact.core_id == core, CoreArtifact.kind == kind)
                )
            await session.commit()
        for doc in docs:
            doc_id = str(doc.get(id_key, "") or doc.get("id", ""))
            if doc_id:
                await self.put_doc(core, kind, doc_id, doc)

    async def lookup_document_keys(self, doc_ids: list[str]) -> list[dict[str, Any]]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in doc_ids:
            doc_id = str(raw or "").strip()
            if not doc_id or doc_id in seen or len(doc_id) > 512:
                continue
            seen.add(doc_id)
            cleaned.append(doc_id)
        if not cleaned:
            return []

        async with self._runtime.reading() as session:
            found: list[dict[str, Any]] = []
            matched: set[str] = set()
            stmt = select(Client).where(Client.id.in_(cleaned))
            for row in (await session.execute(stmt)).scalars().all():
                if not row_visible(row.core_id, row.scope):
                    continue
                matched.add(row.id)
                kind = "peer" if row.parent_type == PARENT_INTERFACE else "user"
                if row.role == "quota":
                    kind = QUOTA_KIND
                elif row.role == "xray_disabled":
                    kind = DISABLED_KIND
                meta = row.meta or {}
                item = {
                    "doc_id": row.id,
                    "core": row.core_id,
                    "kind": kind,
                    "email": _json_text(row.email),
                    "client_link_uuid": _json_text(meta.get("client_link_uuid")),
                    "protocol_id": _json_text(meta.get("id") or meta.get("client_link_uuid")),
                }
                parent_doc = row.parent_interface_id or row.parent_server_id
                if parent_doc and row.parent_type in (PARENT_INTERFACE, PARENT_SERVER):
                    item["parent_doc_id"] = str(parent_doc)
                found.append(item)
            quota_stmt = select(Quota).where(Quota.client_id.in_(cleaned))
            quota_rows = [
                row
                for row in (await session.execute(quota_stmt)).scalars().all()
                if row.client_id not in matched
            ]
            owners: dict[tuple[str, str], Client] = {}
            owners_by_core: dict[str, list[str]] = defaultdict(list)
            for row in quota_rows:
                owners_by_core[str(row.core_id)].append(str(row.client_id))
            for core_id, client_ids in owners_by_core.items():
                unique_ids = list(dict.fromkeys(client_ids))
                for offset in range(0, len(unique_ids), 400):
                    batch = unique_ids[offset : offset + 400]
                    owner_rows = (
                        await session.execute(
                            select(Client).where(Client.core_id == core_id, Client.id.in_(batch))
                        )
                    ).scalars().all()
                    for owner in owner_rows:
                        owners[(str(owner.core_id), str(owner.id))] = owner
            for row in quota_rows:
                owner = owners.get((str(row.core_id), str(row.client_id)))
                if owner is not None and not row_visible(owner.core_id, owner.scope):
                    continue
                matched.add(row.client_id)
                found.append({
                    "doc_id": row.client_id,
                    "core": row.core_id,
                    "kind": QUOTA_KIND,
                    "email": _json_text(row.email),
                    "client_link_uuid": _json_text(row.protocol_id),
                    "protocol_id": _json_text(row.protocol_id),
                })

            missing = set(cleaned) - matched
            if missing:
                found.extend(await self._lookup_nested_client_keys(session, missing))
            return found

    async def _lookup_nested_client_keys(self, session, wanted: set[str]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        seen: set[str] = set()
        stmt = select(Client).where(
            Client.parent_type.in_((PARENT_INTERFACE, PARENT_SERVER)),
            or_(Client.id.in_(wanted), Client.email.in_(wanted)),
        )
        for row in (await session.execute(stmt)).scalars().all():
            if not row_visible(row.core_id, row.scope):
                continue
            key = row.id
            if key not in wanted or key in seen:
                continue
            seen.add(key)
            kind = "peer" if row.parent_type == PARENT_INTERFACE else "user"
            parent_id = row.parent_interface_id or row.parent_server_id or ""
            meta = row.meta or {}
            found.append({
                "doc_id": key,
                "core": row.core_id,
                "kind": kind,
                "email": _json_text(row.email),
                "client_link_uuid": _json_text(meta.get("client_link_uuid")),
                "protocol_id": _json_text(meta.get("id") or row.id),
                "parent_doc_id": parent_id,
            })
        return found

    async def list_doc_records(
        self,
        *,
        core: str | None = None,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []

        async def append_docs(core_key: str, kind_key: str) -> None:
            if kind_key == QUOTA_KIND:
                async with self._runtime.reading() as session:
                    for client_id, doc in await self._quota_documents(session, core_key):
                        rows.append({
                            "core": core_key,
                            "kind": kind_key,
                            "doc_id": client_id,
                            "data": doc,
                        })
                return
            for doc in await self.list_docs(core_key, kind_key):
                doc_id = str(doc.get("id") or doc.get("node_id") or "")
                rows.append({
                    "core": core_key,
                    "kind": kind_key,
                    "doc_id": doc_id,
                    "data": doc,
                })

        if core is not None and kind is not None:
            await append_docs(core, kind)
            return rows

        if kind is not None:
            cores = [core] if core else ["xray", "wireguard", "amnezia", "l2tp", "openvpn", "mullvad"]
            for core_key in cores:
                await append_docs(core_key, kind)
            return rows

        if core is not None:
            for kind_key in ("interface", "server", QUOTA_KIND, DISABLED_KIND):
                await append_docs(core, kind_key)
            async with self._runtime.reading() as session:
                artifacts = (
                    await session.execute(select(CoreArtifact).where(CoreArtifact.core_id == core))
                ).scalars().all()
                for item in artifacts:
                    rows.append({
                        "core": item.core_id,
                        "kind": item.kind,
                        "doc_id": item.artifact_id,
                        "data": dict(item.data or {}),
                    })
            return rows

        for core_key in ("xray", "wireguard", "amnezia", "l2tp", "openvpn", "mullvad"):
            for kind_key in ("interface", "server", QUOTA_KIND, DISABLED_KIND):
                if kind_key == "interface" and core_key in ("openvpn", "l2tp", "xray", "mullvad"):
                    continue
                if kind_key == "server" and core_key in ("wireguard", "amnezia", "xray"):
                    continue
                await append_docs(core_key, kind_key)
        async with self._runtime.reading() as session:
            artifacts = (await session.execute(select(CoreArtifact))).scalars().all()
            for item in artifacts:
                rows.append({
                    "core": item.core_id,
                    "kind": item.kind,
                    "doc_id": item.artifact_id,
                    "data": dict(item.data or {}),
                })
        return rows

    async def bind_resource_scope(
        self,
        core: str,
        kind: str,
        resource_id: str,
        scope: str | None = None,
    ) -> None:
        resource_id = str(resource_id or "").strip()
        if not resource_id:
            return
        owner = str(scope or "").strip() or current_scope()
        try:
            async with self._runtime.writing() as session:
                row = await session.get(ResourceScope, (core, kind, resource_id))
                if row is None:
                    session.add(
                        ResourceScope(core_id=core, kind=kind, resource_id=resource_id, scope=owner)
                    )
                else:
                    row.scope = owner
                await session.commit()
        except OperationalError:
            return

    async def resource_scope(self, core: str, kind: str, resource_id: str) -> str:
        try:
            async with self._runtime.reading() as session:
                row = await session.get(ResourceScope, (core, kind, str(resource_id)))
            if row is None:
                return DEFAULT_SCOPE
            return str(row.scope or DEFAULT_SCOPE)
        except OperationalError:
            return DEFAULT_SCOPE

    async def resource_scope_map(self, core: str, kind: str) -> dict[str, str]:
        try:
            async with self._runtime.reading() as session:
                rows = (
                    await session.execute(
                        select(ResourceScope).where(
                            ResourceScope.core_id == core,
                            ResourceScope.kind == kind,
                        )
                    )
                ).scalars().all()
            return {str(row.resource_id): str(row.scope or DEFAULT_SCOPE) for row in rows}
        except OperationalError:
            return {}

    async def delete_resource_scope(self, core: str, kind: str, resource_id: str) -> None:
        try:
            async with self._runtime.writing() as session:
                await session.execute(
                    delete(ResourceScope).where(
                        ResourceScope.core_id == core,
                        ResourceScope.kind == kind,
                        ResourceScope.resource_id == str(resource_id),
                    )
                )
                await session.commit()
        except OperationalError:
            return

    async def dump_documents(self) -> list[dict[str, Any]]:
        return await self.list_doc_records()

    async def replace_all_documents(self, rows: list[dict[str, Any]]) -> int:
        async with self._runtime.writing() as session:
            await session.execute(delete(Client))
            await session.execute(delete(Quota))
            await session.execute(delete(Interface))
            await session.execute(delete(Server))
            await session.execute(delete(CoreArtifact))
            await session.commit()
        prepared = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            core = str(row.get("core") or "").strip()
            kind = str(row.get("kind") or "").strip()
            doc_id = str(row.get("doc_id") or "").strip()
            data = row.get("data")
            if not core or not kind or not doc_id or not isinstance(data, dict):
                continue
            await self.put_doc(core, kind, doc_id, data)
            prepared += 1
        return prepared
