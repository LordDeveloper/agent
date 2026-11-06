"""Document reads must use the clustered primary key or the kind index."""

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
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'documents'"
        )
        assert "WITHOUT ROWID" in str(schema[0][0]).upper()

        by_key = await _plans(
            store,
            "SELECT data FROM documents WHERE core = ? AND kind = ? ORDER BY doc_id",
            ("wireguard", "interface"),
        )
        assert "PRIMARY KEY" in by_key.upper()

        by_kind = await _plans(
            store,
            "SELECT core, doc_id, data FROM documents WHERE kind = ? ORDER BY core, doc_id",
            ("client_quota",),
        )
        assert "documents_by_kind" in by_kind

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
        schema = await store._fetch(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'documents'"
        )
        assert "WITHOUT ROWID" in str(schema[0][0]).upper()
        assert await store.get_doc("xray", "client_quota", "a") == {"id": "a"}
        assert await store.list_docs("wireguard", "interface") == [{"name": "wg0"}]
    finally:
        await store.close()
