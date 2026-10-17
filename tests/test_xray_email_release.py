from agent.support import emails_on_other_inbounds, xray_client_rows


def test_client_rows_keep_one_email_across_clients_and_users():
    inbound = {
        "settings": {
            "clients": [{"id": "new", "email": "same"}],
            "users": [{"id": "old", "email": "same"}, {"id": "other", "email": "kept"}],
        }
    }

    rows = xray_client_rows(inbound)
    emails = [row["email"] for row in rows]

    assert emails == ["same", "kept"]
    assert rows[0]["id"] == "new"


def test_protocol_move_email_is_released_from_the_previous_inbound():
    config = {
        "inbounds": [
            {
                "tag": "inbound-1",
                "protocol": "vless",
                "settings": {"clients": [{"id": "old-uuid", "email": "user1"}]},
            },
            {
                "tag": "inbound-2",
                "protocol": "vmess",
                "settings": {"clients": [{"id": "other", "email": "someone"}]},
            },
        ]
    }

    plan = emails_on_other_inbounds(config, {"user1"}, keep_tag="inbound-2")

    assert plan == {"inbound-1": ["user1"]}


def test_release_skips_the_inbound_being_updated():
    config = {
        "inbounds": [
            {
                "tag": "inbound-2",
                "settings": {"clients": [{"id": "new-uuid", "email": "user1"}]},
            }
        ]
    }

    assert emails_on_other_inbounds(config, {"user1"}, keep_tag="inbound-2") == {}
