"""Document reads must use relational indexes and WITHOUT ROWID tables."""

import sqlite3

import pytest

from agent.db import Store


async def _plans(store: Store, sql: str, params: tuple = ()) -> str:
    rows = await store._fetch(f"EXPLAIN QUERY PLAN {sql}", params)
    return " ".join(str(row[3]) for row in rows)


@pytest.mark.asyncio
async def test_fresh_documents_are_clustered_on_the_primary_key(tmp_path):
    store = Store(tmp_path / "agent.db")
    await store.open()
    try:
        await store.put_doc("xray", "client_quota", "a", {"id": "a"})
        await store.put_doc("wireguard", "interface", "wg0", {"name": "wg0"})

        schema = await store._fetch(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'clients'"
        )
        assert "WITHOUT ROWID" in str(schema[0][0]).upper()

        by_key = await _plans(
            store,
            "SELECT meta FROM clients WHERE core_id = ? AND parent_interface_id = ?",
            ("wireguard", "wg0"),
        )
        assert "PRIMARY KEY" in by_key.upper() or "clients" in by_key.lower()

        by_kind = await _plans(
            store,
            "SELECT core_id, client_id FROM quotas ORDER BY core_id, client_id",
        )
        assert "quotas" in by_kind.lower()

        quota = await store.list_doc_records(kind="client_quota")
        assert [row["doc_id"] for row in quota] == ["a"]
        assert await store.get_doc("wireguard", "interface", "wg0") == {"name": "wg0"}
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_legacy_rowid_documents_are_rebuilt_without_rowid(tmp_path):
    path = tmp_path / "agent.db"
    raw = sqlite3.connect(path)
    raw.execute(
        """
        CREATE TABLE documents (
            core TEXT NOT NULL,
            kind TEXT NOT NULL,
            doc_id TEXT NOT NULL,
            data TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (core, kind, doc_id)
        )
        """
    )
    raw.execute(
        "INSERT INTO documents (core, kind, doc_id, data) VALUES (?, ?, ?, ?)",
        ("xray", "client_quota", "a", '{"id":"a"}'),
    )
    raw.execute(
        "INSERT INTO documents (core, kind, doc_id, data) VALUES (?, ?, ?, ?)",
        ("wireguard", "interface", "wg0", '{"name":"wg0"}'),
    )
    raw.commit()
    raw.close()

    store = Store(path)
    await store.open()
    try:
        assert await store.get_doc("xray", "client_quota", "a") == {"id": "a"}
        assert await store.list_docs("wireguard", "interface") == [{"name": "wg0"}]
        schema = await store._fetch(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'clients'"
        )
        assert schema, "clients table missing after legacy migration"
        assert "WITHOUT ROWID" in str(schema[0][0]).upper()
    finally:
        await store.close()
