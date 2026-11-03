from agent.support.quota_identity_migration import migrate_client_quota_identity


async def _docs(store, kind="client_quota"):
    rows = await store.dump_documents()
    return [row for row in rows if row["kind"] == kind]


async def test_legacy_agent_id_becomes_document_id(store):
    xray_id = "dc0ef2c2-7489-47ad-a614-d38900000001"
    agent_id = "90c10bb2-ea51-492a-84c5-cfcef6aeaa55"
    await store.put_doc(
        "xray",
        "client_quota",
        xray_id,
        {
            "id": xray_id,
            "node_id": xray_id,
            "agent_id": agent_id,
            "email": "nhZNct",
            "volume": 1024,
            "_incoming": 5,
            "_outgoing": 7,
        },
    )

    assert await migrate_client_quota_identity(store) == 1
    rows = await _docs(store)
    assert len(rows) == 1
    assert rows[0]["doc_id"] == agent_id
    assert rows[0]["data"] == {
        "id": agent_id,
        "node_id": xray_id,
        "email": "nhZNct",
        "volume": 1024,
        "_incoming": 5,
        "_outgoing": 7,
    }
    assert "agent_id" not in rows[0]["data"]
    assert await migrate_client_quota_identity(store) == 0


async def test_primary_key_alias_and_duplicate_email_doc_collapse(store):
    link = "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    agent_id = "11111111-2222-4333-8444-555555555555"
    await store.put_doc(
        "xray",
        "client_quota",
        link,
        {
            "id": link,
            "node_id": link,
            "primary_key": agent_id,
            "email": "HxCc1M",
            "volume": 10,
            "_incoming": 1,
        },
    )
    await store.put_doc(
        "xray",
        "client_quota",
        "HxCc1M",
        {"id": link, "email": "HxCc1M", "_incoming": 4, "_outgoing": 2},
    )

    assert await migrate_client_quota_identity(store) == 1
    rows = await _docs(store)
    assert [row["doc_id"] for row in rows] == [agent_id]
    assert rows[0]["data"]["id"] == agent_id
    assert rows[0]["data"]["node_id"] == link
    assert rows[0]["data"]["volume"] == 10
    assert rows[0]["data"]["_incoming"] == 4
    assert rows[0]["data"]["_outgoing"] == 2
    assert "primary_key" not in rows[0]["data"]


async def test_unsplit_quota_is_left_alone(store):
    client_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    payload = {"id": client_id, "node_id": client_id, "email": "solo", "volume": 3}
    await store.put_doc("xray", "client_quota", client_id, payload)

    assert await migrate_client_quota_identity(store) == 0
    rows = await _docs(store)
    assert rows[0]["doc_id"] == client_id
    assert rows[0]["data"] == payload


async def test_stale_link_doc_is_folded_into_current_id(store):
    link = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    agent_id = "12121212-3434-4545-8686-787878787878"
    await store.put_doc(
        "xray",
        "client_quota",
        agent_id,
        {"id": agent_id, "node_id": link, "email": "kept", "volume": 9},
    )
    await store.put_doc(
        "xray",
        "client_quota",
        link,
        {"id": link, "node_id": link, "email": "kept", "_incoming": 8},
    )

    assert await migrate_client_quota_identity(store) == 1
    rows = await _docs(store)
    assert len(rows) == 1
    assert rows[0]["doc_id"] == agent_id
    assert rows[0]["data"]["id"] == agent_id
    assert rows[0]["data"]["node_id"] == link
    assert rows[0]["data"]["volume"] == 9
    assert rows[0]["data"]["_incoming"] == 8
