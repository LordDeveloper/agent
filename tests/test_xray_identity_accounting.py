from agent.support.client_diagnose import describe_traffic_accounting
from agent.support.client_identity import apply_panel_identity, billing_client_id, select_quota_meta
from agent.support.diagnose_format import format_diagnose_report


NODE_ID = "11111111-1111-4111-8111-111111111111"
XRAY_UUID = "3f114cba-9b5f-48f3-8570-152de1d85464"


def test_panel_identity_keeps_node_id_and_does_not_mint_another():
    created = apply_panel_identity(
        {
            "id": NODE_ID,
            "node_id": NODE_ID,
            "client_link_uuid": XRAY_UUID,
            "email": "user@example.com",
        },
        store_kind="xray",
    )
    assert created["node_id"] == NODE_ID
    assert created["id"] == XRAY_UUID
    assert created["client_link_uuid"] == XRAY_UUID

    updated = apply_panel_identity(
        {
            "id": NODE_ID,
            "node_id": NODE_ID,
            "client_link_uuid": XRAY_UUID,
            "email": "renamed@example.com",
        },
        store_kind="xray",
    )
    assert updated["node_id"] == NODE_ID
    assert updated["client_link_uuid"] == XRAY_UUID


def test_quota_lookup_uses_distinct_node_id_not_the_xray_uuid():
    coupled = {
        "id": XRAY_UUID,
        "node_id": XRAY_UUID,
        "client_link_uuid": XRAY_UUID,
        "email": "user@example.com",
    }
    current = {
        "id": NODE_ID,
        "node_id": NODE_ID,
        "client_link_uuid": XRAY_UUID,
        "email": "user@example.com",
    }
    index = {
        f"n:{XRAY_UUID}": coupled,
        f"i:{XRAY_UUID}": coupled,
        f"l:{XRAY_UUID}": current,
        f"e:user@example.com": current,
        f"n:{NODE_ID}": current,
    }

    meta = select_quota_meta(index, protocol_id=XRAY_UUID, email="user@example.com")
    assert billing_client_id(meta, protocol_id=XRAY_UUID, email="user@example.com") == NODE_ID


def test_legacy_coupled_row_keeps_its_existing_key():
    coupled = {"id": XRAY_UUID, "node_id": XRAY_UUID, "email": "user@example.com"}
    index = {f"n:{XRAY_UUID}": coupled, f"e:user@example.com": coupled}

    meta = select_quota_meta(index, protocol_id=XRAY_UUID, email="user@example.com")
    assert billing_client_id(meta, protocol_id=XRAY_UUID, email="user@example.com") == XRAY_UUID


def test_legacy_swapped_quota_row_returns_the_stored_primary_key():
    swapped = {"id": NODE_ID, "node_id": XRAY_UUID, "email": "user@example.com"}
    meta = select_quota_meta({f"n:{XRAY_UUID}": swapped}, protocol_id=XRAY_UUID, email="")
    assert billing_client_id(meta, protocol_id=XRAY_UUID, email="") == NODE_ID


def test_accounting_states_do_not_invent_ack_success():
    missing = describe_traffic_accounting(
        node_id=NODE_ID,
        queried=True,
        ack_rows=[],
        pending_rows=[],
        live_uplink=368_327,
        live_downlink=2_128_283,
    )
    assert missing["status"] == "missing"
    assert missing["delta_uplink"] is None
    assert missing["last_successful_ack_at"] is None
    assert missing["ack_retry_count"] is None
    assert missing["last_persisted_usage"] is None

    waiting = describe_traffic_accounting(
        node_id=NODE_ID,
        queried=True,
        ack_rows=[{"core": "xray", "incoming": 2_000_000, "outgoing": 300_000, "updated_at": "2026-11-08 12:00:00"}],
        pending_rows=[{
            "core": "xray",
            "delta_incoming": 128_283,
            "delta_outgoing": 68_327,
            "updated_at": "2026-11-08 12:01:00",
        }],
        live_uplink=368_327,
        live_downlink=2_128_283,
    )
    assert waiting["status"] == "pending"
    assert waiting["pending_ack"] is True
    assert waiting["pending_ack_id"] == NODE_ID
    assert waiting["delta_uplink"] == 68_327
    assert waiting["delta_downlink"] == 128_283
    assert waiting["last_ack_error"] is None

    inconsistent = describe_traffic_accounting(
        node_id=NODE_ID,
        queried=True,
        ack_rows=[{"core": "xray", "incoming": 2_000_000, "outgoing": 300_000, "updated_at": "t"}],
        pending_rows=[],
        live_uplink=368_327,
        live_downlink=2_128_283,
    )
    assert inconsistent["status"] == "inconsistent"

    reset = describe_traffic_accounting(
        node_id=NODE_ID,
        queried=True,
        ack_rows=[{"core": "xray", "incoming": 2_128_283, "outgoing": 368_327, "updated_at": "t"}],
        pending_rows=[],
        live_uplink=10,
        live_downlink=20,
    )
    assert reset["status"] == "reset"

    empty_node = describe_traffic_accounting(
        node_id="",
        queried=False,
        ack_rows=[{"core": "xray", "incoming": 1, "outgoing": 1}],
        pending_rows=[{"core": "xray", "delta_incoming": 1, "delta_outgoing": 1}],
        live_uplink=1,
        live_downlink=1,
    )
    assert empty_node["status"] == "missing"
    assert empty_node["pending_ack"] is None
    assert empty_node["pending_ack_id"] is None


def test_diagnose_report_shows_pending_ack_and_does_not_treat_stats_as_billing():
    report = {
        "core": "xray",
        "found": True,
        "key": NODE_ID,
        "email": "user@example.com",
        "summary": {"healthy": False, "issue_count": 1, "warning_count": 0, "match_count": 1},
        "matches": [
            {
                "email": "user@example.com",
                "node_id": NODE_ID,
                "xray_uuid": XRAY_UUID,
                "client_link_uuid": XRAY_UUID,
                "client": {"email": "user@example.com", "id": XRAY_UUID, "is_enabled": True},
                "live": {
                    "online_status": "online",
                    "traffic": {"uplink": 368_327, "downlink": 2_128_283, "kind": "cumulative"},
                },
                "traffic_accounting": describe_traffic_accounting(
                    node_id=NODE_ID,
                    queried=True,
                    ack_rows=[],
                    pending_rows=[],
                    live_uplink=368_327,
                    live_downlink=2_128_283,
                ),
                "checks": [
                    {"name": "traffic_stats", "ok": True, "meaning": "xray counters were read"},
                    {"name": "online_now", "ok": True, "status": "online"},
                    {"name": "pending_usage", "ok": False, "status": "missing"},
                    {"name": "ack_completion", "ok": None, "reason": "panel ACK completion is not stored on the agent"},
                ],
                "issues": [],
                "inbound": {"tag": "inbound-1", "port": 443, "protocol": "vless"},
            }
        ],
    }

    text = format_diagnose_report(report, use_color=False)
    assert "node_id:      " + NODE_ID in text
    assert "Xray UUID:    " + XRAY_UUID in text
    assert NODE_ID != XRAY_UUID
    assert "Traffic Accounting / Pending ACK" in text
    assert "ACK status:              Missing or inconsistent accounting state" in text
    assert "ACK processing:          unavailable" in text
    assert "ACK retry count:         unavailable" in text
    assert "Last successful ACK:     unavailable" in text
    assert "Last persisted usage:    unavailable" in text
    assert "traffic_stats" in text
    assert "ack_completion" in text
