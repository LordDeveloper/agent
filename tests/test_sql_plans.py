"""Hot reads must use covering indexes and must not select client JSON."""

import pytest
from sqlalchemy import text

from agent.db import Store


async def _plans(store: Store, sql: str, params: tuple = ()) -> str:
    rows = await store._fetch(f"EXPLAIN QUERY PLAN {sql}", params)
    return " ".join(str(row[3]) for row in rows)


@pytest.mark.asyncio
async def test_cursor_reads_use_covering_indexes(tmp_path):
    store = Store(tmp_path / "agent.db")
    await store.open()
    try:
        await store.put_doc(
            "wireguard",
            "interface",
            "wg0",
            {"name": "wg0", "peers": [{"id": "peer-1", "public_key": "abc"}]},
        )
        async with store._runtime.writing() as session:
            await session.execute(text("ANALYZE"))
            await session.commit()

        by_key = await _plans(
            store,
            "SELECT core_id, id, incoming, outgoing FROM clients INDEXED BY ix_clients_cursor "
            "WHERE core_id = ? AND id = ?",
            ("wireguard", "peer-1"),
        )
        assert "ix_clients_cursor" in by_key
        assert "COVERING" in by_key.upper()

        by_scope = await _plans(
            store,
            "SELECT core_id, id, incoming, outgoing FROM clients INDEXED BY ix_clients_scope_cursor "
            "WHERE scope = ? AND core_id = ?",
            ("default", "wireguard"),
        )
        assert "ix_clients_scope_cursor" in by_scope
        assert "COVERING" in by_scope.upper()

        chunks = await _plans(
            store,
            "SELECT core, client_key, sum(incoming), sum(outgoing) "
            "FROM traffic_pending_chunk WHERE scope = ? GROUP BY core, client_key",
            ("default",),
        )
        assert "ix_traffic_pending_chunk_client" in chunks
    finally:
        await store.close()
