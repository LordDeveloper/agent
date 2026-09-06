from __future__ import annotations

from agent.support.client_diagnose import diagnose_xray_client, diagnose_xray_clients_by_key


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

    def read_config(self):
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
    report = diagnose_xray_client(_FakeXrayDriver(), 7, "abc123")
    assert report["found"] is True
    assert report["email"] == "abc123"
    assert report["matches"][0]["healthy"] is True


def test_diagnose_xray_client_by_email_all_inbounds():
    report = diagnose_xray_clients_by_key(_FakeXrayDriver(), "abc123")
    assert report["found"] is True
    assert report["summary"]["match_count"] == 1


def test_diagnose_xray_client_missing():
    report = diagnose_xray_clients_by_key(_FakeXrayDriver(), "missing")
    assert report["found"] is False
    assert report["summary"]["issue_count"] == 1
