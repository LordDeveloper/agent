from agent.support.node_id_pk_migration import migrate_node_id_primary_key
from agent.support.quota_identity_migration import migrate_client_quota_identity


async def _quota(store):
    rows = await store.dump_documents()
    return [row for row in rows if row["kind"] == "client_quota"]


async def test_split_quota_uses_existing_primary_key_and_keeps_protocol_uuid(store):
    link = "dc0ef2c2-7489-47ad-a614-d38900000001"
    agent_id = "90c10bb2-ea51-492a-84c5-cfcef6aeaa55"
    await store.put_doc(
        "xray",
        "client_quota",
        link,
        {
            "id": link,
            "node_id": link,
            "agent_id": agent_id,
            "email": "nhZNct",
            "volume": 1024,
            "_incoming": 5,
            "_outgoing": 7,
        },
    )
    assert await migrate_client_quota_identity(store) == 1

    await store.set_traffic_ack("xray", link, 10, 4)
    await store.set_traffic_ack("xray", agent_id, 3, 9)
    await store.upsert_traffic_pending("xray", "nhZNct", 5, 1, 20, 8)
    await store.upsert_traffic_pending("xray", agent_id, 2, 2, 10, 10)

    assert await migrate_node_id_primary_key(store) >= 1

    rows = await _quota(store)
    assert len(rows) == 1
    assert rows[0]["doc_id"] == agent_id
    data = rows[0]["data"]
    assert data["id"] == agent_id
    assert data["node_id"] == agent_id
    assert data["client_link_uuid"] == link
    assert data["email"] == "nhZNct"
    assert data["volume"] == 1024
    assert data["_incoming"] == 5
    assert data["_outgoing"] == 7
    assert "agent_id" not in data

    assert await store.get_traffic_ack("xray", agent_id) == {"incoming": 10, "outgoing": 9}
    assert await store.get_traffic_ack("xray", link) is None
    pending = await store.get_traffic_pending("xray", agent_id)
    assert pending["delta_incoming"] == 5
    assert pending["delta_outgoing"] == 1
    assert await store.get_traffic_pending("xray", "nhZNct") is None

    backup = store.path.with_name(store.path.name + ".bak-node-id-pk")
    assert backup.exists() and backup.stat().st_size > 0
    assert await migrate_node_id_primary_key(store) == 0
    assert (await _quota(store))[0]["data"]["node_id"] == agent_id


async def test_unsplit_identity_is_not_replaced(store):
    client_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    payload = {"id": client_id, "node_id": client_id, "email": "solo", "volume": 3}
    await store.put_doc("xray", "client_quota", client_id, dict(payload))

    assert await migrate_node_id_primary_key(store) == 0
    rows = await _quota(store)
    assert rows[0]["doc_id"] == client_id
    assert rows[0]["data"]["node_id"] == client_id
    assert rows[0]["data"]["id"] == client_id
    backup = store.path.with_name(store.path.name + ".bak-node-id-pk")
    assert not backup.exists()


async def test_rewrite_is_skipped_when_backup_fails(store, monkeypatch):
    link = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    agent_id = "12121212-3434-4545-8686-787878787878"
    await store.put_doc(
        "xray",
        "client_quota",
        agent_id,
        {"id": agent_id, "node_id": link, "email": "kept", "volume": 9, "_incoming": 4},
    )

    async def fail_backup(_dest):
        raise OSError("backup failed")

    monkeypatch.setattr(store, "backup_database", fail_backup)

    assert await migrate_node_id_primary_key(store) == 0
    rows = await _quota(store)
    assert rows[0]["doc_id"] == agent_id
    assert rows[0]["data"]["node_id"] == link
    assert rows[0]["data"]["_incoming"] == 4
    assert "client_link_uuid" not in rows[0]["data"]
