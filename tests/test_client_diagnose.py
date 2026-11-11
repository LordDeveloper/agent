from __future__ import annotations

import asyncio
import time

from agent.support.client_diagnose import diagnose_xray_client, diagnose_xray_clients_by_key
from agent.support.diagnose_format import format_diagnose_report


class _FakeXrayDriver:
    key = "xray"

    def inbound_tag(self, inbound_id):
        return f"inbound-{inbound_id}"

    def id_from_tag(self, tag):
        text = str(tag or "")
        if text.startswith("inbound-"):
            tail = text.split("-", 1)[1]
            return int(tail) if tail.isdigit() else tail
        return None

    async def read_config(self):
        return {
            "inbounds": [
                {
                    "tag": "inbound-7",
                    "id": 7,
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": "uuid-1",
                                "email": "abc123",
                                "is_enabled": True,
                                "volume": 1024,
                                "_incoming": 0,
                                "_outgoing": 0,
                            }
                        ]
                    },
                }
            ]
        }

    def running(self):
        return True

    def list_inbounds(self):
        return [
            {
                "tag": "inbound-7",
                "id": 7,
                "settings": {
                    "clients": [
                        {
                            "id": "uuid-1",
                            "email": "abc123",
                            "is_enabled": True,
                        }
                    ]
                },
            }
        ]

    def online_users(self):
        return []

    def client_ips(self, _email):
        return []

    async def _quota_index(self):
        row = {
            "id": "node-1",
            "node_id": "node-1",
            "client_link_uuid": "uuid-1",
            "email": "abc123",
        }
        return {
            "l:uuid-1": row,
            "n:node-1": row,
            "i:node-1": row,
            "e:abc123": row,
        }

    def usage_snapshot(self):
        from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel

        return UsageSnapshotModel(
            inbounds=[
                InboundUsageModel(
                    id=7,
                    tag="inbound-7",
                    incoming=0,
                    outgoing=0,
                    clients=[
                        ClientUsageModel(
                            id="uuid-1",
                            email="abc123",
                            incoming=100,
                            outgoing=50,
                            inbound_id=7,
                        )
                    ],
                )
            ]
        )


def test_diagnose_xray_client_by_inbound():
    report = asyncio.run(diagnose_xray_client(_FakeXrayDriver(), 7, "abc123"))
    assert report["found"] is True
    assert report["email"] == "abc123"
    assert report["matches"][0]["healthy"] is True
    assert report["matches"][0]["bandwidth"]["status"] == "not_applicable"
    assert report["matches"][0]["bandwidth"]["configured"] is False


def test_diagnose_xray_client_by_email_all_inbounds():
    report = asyncio.run(diagnose_xray_clients_by_key(_FakeXrayDriver(), "abc123"))
    assert report["found"] is True
    assert report["summary"]["match_count"] == 1


def test_diagnose_xray_client_missing():
    report = asyncio.run(diagnose_xray_clients_by_key(_FakeXrayDriver(), "missing"))
    assert report["found"] is False
    assert report["summary"]["issue_count"] == 1


def test_diagnose_reports_orphan_quota_hint_when_config_misses_the_client():
    class Driver(_FakeXrayDriver):
        async def read_config(self):
            return {"inbounds": []}

        async def _quota_index(self):
            row = {"id": "node-x", "node_id": "node-x", "email": "orphan@x"}
            return {"n:node-x": row, "e:orphan@x": row}

        async def _lookup_keys_for_panel_id(self, key):
            return [key]

        def _probe_email(self, aliases):
            return ""

        async def _filtered_live_user(self, tag, email):
            return None

    report = asyncio.run(diagnose_xray_clients_by_key(Driver(), "node-x"))
    assert report["found"] is False
    codes = [row["code"] for row in report["issues"]]
    assert "ORPHAN_QUOTA_DOC" in codes


def _online_check(report: dict) -> dict:
    checks = report["matches"][0]["checks"]
    return next(row for row in checks if row["name"] == "online_now")


def _issue_codes(report: dict) -> list[str]:
    return [row["code"] for row in report["matches"][0]["issues"]]


def test_online_when_user_list_contains_uuid_instead_of_email():
    class Driver(_FakeXrayDriver):
        def online_users(self):
            # XrayDriver.online_users() rewrites the email to the protocol id.
            return ["uuid-1"]

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    live = report["matches"][0]["live"]
    assert live["online"] is True
    assert live["online_status"] == "online"
    assert live["online_source"] == "online_users"
    assert "CLIENT_OFFLINE" not in _issue_codes(report)
    check = _online_check(report)
    assert check["ok"] is True
    assert check["counters"] == "cumulative"
    assert check["downlink"] == 100
    assert check["uplink"] == 50
    assert "Cumulative" not in check["reason"]


def test_fresh_session_ip_is_online_even_when_user_list_misses_the_client():
    seen = time.time()
    called: list[str] = []

    class Driver(_FakeXrayDriver):
        def client_ip_last_seen(self, key):
            called.append(key)
            assert key == "abc123"
            return {"91.102.127.240": seen}

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    live = report["matches"][0]["live"]
    assert live["online"] is True
    assert live["online_source"] == "online_ips"
    assert live["ips"] == ["91.102.127.240"]
    assert live["last_activity"] == seen
    assert "CLIENT_OFFLINE" not in _issue_codes(report)
    rendered = format_diagnose_report(report, use_color=False)
    assert "Source:" in rendered
    assert "online_ips" in rendered
    assert "91.102.127.240" in rendered
    assert "cumulative, not used as presence" in rendered
    assert called == ["abc123"]


def test_session_ip_lookup_does_not_query_iplist_with_the_protocol_uuid():
    called: list[str] = []

    class Driver(_FakeXrayDriver):
        async def read_config(self):
            config = await super().read_config()
            config["inbounds"][0]["settings"]["clients"][0]["id"] = "7764fdcf-7773-4e64-bd3a-0ea4550c167f"
            return config

        def client_ip_last_seen(self, key):
            called.append(key)
            return {}

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    assert called == ["abc123"]
    assert "7764fdcf-7773-4e64-bd3a-0ea4550c167f" not in called
    assert report["matches"][0]["live"]["online"] is False


def test_online_user_email_match_is_case_insensitive():
    class Driver(_FakeXrayDriver):
        def online_users(self):
            return ["ABC123"]

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    assert report["matches"][0]["live"]["online"] is True
    assert "CLIENT_OFFLINE" not in _issue_codes(report)


def test_cumulative_traffic_alone_does_not_count_as_online():
    report = asyncio.run(diagnose_xray_client(_FakeXrayDriver(), 7, "abc123"))
    live = report["matches"][0]["live"]
    assert live["online"] is False
    assert live["online_status"] == "offline"
    assert live["traffic"]["downlink"] == 100
    assert "CLIENT_OFFLINE" in _issue_codes(report)
    assert "Cumulative" in report["matches"][0]["issues"][0]["message"]
    check = _online_check(report)
    assert check["ok"] is False
    assert check["window_seconds"] == 60


def test_failed_online_sources_are_unknown_not_offline():
    class Driver(_FakeXrayDriver):
        def online_users(self):
            raise RuntimeError("stats api down")

        def client_ips(self, _email):
            raise RuntimeError("iplist down")

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    live = report["matches"][0]["live"]
    assert live["online"] is None
    assert live["online_status"] == "unknown"
    assert "CLIENT_OFFLINE" not in _issue_codes(report)
    assert "ONLINE_STATUS_UNKNOWN" in _issue_codes(report)
    assert _online_check(report)["ok"] is None
    assert report["summary"]["warning_count"] == 0


def test_one_negative_source_and_one_failed_source_is_unknown():
    class Driver(_FakeXrayDriver):
        def online_users(self):
            raise RuntimeError("online users unavailable")

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    assert report["matches"][0]["live"]["online_status"] == "unknown"
    assert "CLIENT_OFFLINE" not in _issue_codes(report)


def test_stopped_xray_does_not_report_client_offline():
    class Driver(_FakeXrayDriver):
        def running(self):
            return False

    report = asyncio.run(diagnose_xray_client(Driver(), 7, "abc123"))
    assert report["matches"][0]["live"]["online_status"] == "unknown"
    assert "CLIENT_OFFLINE" not in _issue_codes(report)
    assert "XRAY_NOT_RUNNING" in _issue_codes(report)
