from agent.support.client_identity import apply_panel_identity, panel_client_response


def test_split_link_uuid_and_agent_route_id():
    row = apply_panel_identity(
        {
            "node_id": "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2",
            "email": "HxCc1M",
            "is_enabled": True,
        },
        store_kind="xray",
    )
    assert row["id"] == "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    assert row["node_id"] == "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    assert row["agent_id"] != row["id"]

    response = panel_client_response(row)
    assert response["id"] == row["agent_id"]
    assert response["node_id"] == row["agent_id"]
    assert response["client_link_uuid"] == "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    assert response["client_link_uuid"] != response["node_id"]
    assert response["email"] == "HxCc1M"


def test_legacy_single_id_payload():
    legacy_id = "876f18a0-644b-401b-a61a-a1064db044bf"
    row = apply_panel_identity({"id": legacy_id, "email": "user"}, store_kind="xray")
    assert row["id"] == legacy_id
    assert row["agent_id"] == legacy_id
    assert row["node_id"] == legacy_id


def test_vless_user_id_is_panel_node_id_not_agent_pk():
    from agent.support import xray_protocol_user

    user = xray_protocol_user(
        "vless",
        {
            "id": "agent-pk",
            "node_id": "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2",
            "email": "HxCc1M",
            "flow": "xtls-rprx-vision",
        },
    )
    assert user["id"] == "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    assert user["email"] == "HxCc1M"
    assert "node_id" not in user
    assert "agent_id" not in user


def test_second_apply_keeps_agent_id():
    first = apply_panel_identity(
        {"node_id": "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2", "email": "HxCc1M"},
        store_kind="xray",
    )
    second = apply_panel_identity(first, store_kind="xray")
    assert second["id"] == "c6768135-1fa9-4cf8-8cf2-7ca02524b6f2"
    assert second["agent_id"] == first["agent_id"]
    assert second["agent_id"] != second["id"]


def test_explicit_client_link_uuid_is_not_replaced_by_agent_pk():
    link = "77682cfe-dd5f-43c6-9688-8be48138e954"
    agent_pk = "ad72524c-2513-4555-b451-2c1092068514"
    row = apply_panel_identity(
        {
            "id": agent_pk,
            "node_id": link,
            "client_link_uuid": link,
            "email": "P0CbTS",
        },
        store_kind="xray",
    )
    assert row["id"] == link
    assert row["client_link_uuid"] == link
    assert row["agent_id"] == agent_pk
    response = panel_client_response(row)
    assert response["id"] == agent_pk
    assert response["node_id"] == agent_pk
    assert response["client_link_uuid"] == link


def test_wireguard_store_uses_agent_id():
    row = apply_panel_identity(
        {
            "node_id": "panel-global",
            "id": "agent-pk",
            "email": "peer1",
        },
        store_kind="agent",
    )
    assert row["id"] == "agent-pk"
    assert row["node_id"] == "panel-global"
