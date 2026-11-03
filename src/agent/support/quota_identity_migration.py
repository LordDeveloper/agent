"""Rewrite stored Xray quota documents to the agent id contract.

Old rows kept the route key in ``agent_id`` or ``primary_key`` and used the
Xray/link UUID as ``id`` and often as the document key. Current rows store
the route key in ``id`` and the link UUID in ``node_id``.
"""

from __future__ import annotations

from typing import Any

from agent.db import Store
from agent.logutil import get_logger

_QUOTA_KIND = "client_quota"
_log = get_logger("quota.migrate")


def _trim(value: Any) -> str:
    return str(value or "").strip()


def _legacy_pk(data: dict[str, Any]) -> str:
    return _trim(data.get("agent_id") or data.get("primary_key"))


def _distinct_pk(data: dict[str, Any]) -> str:
    """Route id when this document already knows it apart from the link UUID."""
    link = _trim(data.get("node_id"))
    stored = _trim(data.get("id"))
    legacy = _legacy_pk(data)
    if legacy and legacy != link:
        return legacy
    if stored and link and stored != link and not legacy:
        return stored
    if legacy and legacy != stored:
        return legacy
    return ""


def _link_id(data: dict[str, Any], pk: str) -> str:
    link = _trim(data.get("node_id"))
    stored = _trim(data.get("id"))
    if link and link != pk:
        return link
    if stored and stored != pk:
        return stored
    return link


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, index: int) -> int:
        parent = self._parent
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root


def _group_rows(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    count = len(rows)
    groups = _UnionFind(count)
    pk_owner: dict[str, int] = {}
    email_owner: dict[str, int] = {}
    link_owner: dict[str, int] = {}

    for index, row in enumerate(rows):
        data = row["data"]
        email = _trim(data.get("email"))
        pk = _distinct_pk(data)
        link = _link_id(data, pk)
        if email:
            previous = email_owner.get(email)
            if previous is None:
                email_owner[email] = index
            else:
                groups.union(index, previous)
        if pk:
            previous = pk_owner.get(pk)
            if previous is None:
                pk_owner[pk] = index
            else:
                groups.union(index, previous)
            if link:
                link_owner.setdefault(link, index)

    for index, row in enumerate(rows):
        data = row["data"]
        tokens = {
            _trim(row.get("doc_id")),
            _trim(data.get("id")),
            _trim(data.get("node_id")),
            _trim(data.get("email")),
        }
        tokens.discard("")
        for token in tokens:
            owner = pk_owner.get(token)
            if owner is None:
                owner = link_owner.get(token)
            if owner is not None:
                groups.union(index, owner)

    buckets: dict[int, list[dict[str, Any]]] = {}
    for index, row in enumerate(rows):
        buckets.setdefault(groups.find(index), []).append(row)
    return list(buckets.values())


def _counter(data: dict[str, Any], key: str) -> int:
    try:
        return int(data.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _merge_group(rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    pk = ""
    for row in rows:
        found = _distinct_pk(row["data"])
        if found:
            pk = found
            break
    if not pk:
        return None

    link = ""
    for row in rows:
        found = _link_id(row["data"], pk)
        if found:
            link = found
            break

    ordered = sorted(rows, key=lambda row: len(row["data"]), reverse=True)
    merged: dict[str, Any] = {}
    for row in ordered:
        for key, value in row["data"].items():
            if key not in merged:
                merged[key] = value
    merged.pop("agent_id", None)
    merged.pop("primary_key", None)
    merged["id"] = pk
    if link:
        merged["node_id"] = link
    for key in ("_incoming", "_outgoing"):
        if any(key in row["data"] for row in rows):
            merged[key] = max(_counter(row["data"], key) for row in rows)
    return pk, merged


def plan_client_quota_migration(
    documents: list[dict[str, Any]],
) -> tuple[list[tuple[str, str, dict[str, Any]]], list[tuple[str, str]]]:
    """Return ``(puts, deletes)`` for quota documents that still use the old identity."""
    quota_rows = [
        row
        for row in documents
        if str(row.get("kind") or "") == _QUOTA_KIND and isinstance(row.get("data"), dict)
    ]
    by_core: dict[str, list[dict[str, Any]]] = {}
    for row in quota_rows:
        by_core.setdefault(str(row.get("core") or ""), []).append(row)

    puts: list[tuple[str, str, dict[str, Any]]] = []
    deletes: list[tuple[str, str]] = []
    for core, rows in by_core.items():
        for group in _group_rows(rows):
            planned = _merge_group(group)
            if planned is None:
                continue
            doc_id, data = planned
            old_ids = {_trim(row.get("doc_id")) for row in group}
            old_ids.discard("")
            same = [
                row
                for row in group
                if _trim(row.get("doc_id")) == doc_id and row["data"] == data
            ]
            extras = old_ids - {doc_id}
            if same and not extras:
                continue
            puts.append((core, doc_id, data))
            for old_id in sorted(extras):
                deletes.append((core, old_id))
    return puts, deletes


async def migrate_client_quota_identity(store: Store) -> int:
    """Rewrite quota documents in place. Returns how many documents were written."""
    documents = await store.dump_documents()
    puts, deletes = plan_client_quota_migration(documents)
    if not puts and not deletes:
        return 0

    by_core: dict[str, tuple[list[tuple[str, dict[str, Any]]], list[str]]] = {}
    for core, doc_id, data in puts:
        bucket = by_core.setdefault(core, ([], []))
        bucket[0].append((doc_id, data))
    for core, doc_id in deletes:
        bucket = by_core.setdefault(core, ([], []))
        bucket[1].append(doc_id)

    written = 0
    for core, (core_puts, core_deletes) in by_core.items():
        await store.write_docs(core, _QUOTA_KIND, core_puts, core_deletes)
        written += len(core_puts)
    _log.info("migrated client quota identity docs=%s removed=%s", written, len(deletes))
    return written
