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
            "SELECT core, client_key, coalesce(sum(incoming), 0), coalesce(sum(outgoing), 0), count(*) "
            "FROM traffic_pending_chunk INDEXED BY ix_traffic_pending_chunk_totals "
            "WHERE scope = ? GROUP BY core, client_key",
            ("default",),
        )
        assert "ix_traffic_pending_chunk_totals" in chunks
        assert "COVERING" in chunks.upper()

        ordered = await _plans(
            store,
            "SELECT chunk_id, core, client_key, incoming, outgoing, sampled_at "
            "FROM traffic_pending_chunk INDEXED BY ix_traffic_pending_chunk_totals "
            "WHERE scope = ? ORDER BY core, client_key, sampled_at",
            ("default",),
        )
        assert "ix_traffic_pending_chunk_totals" in ordered
        assert "COVERING" in ordered.upper()
    finally:
        await store.close()
