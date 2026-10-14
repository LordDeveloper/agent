from __future__ import annotations

import time

from agent.db import Store
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.traffic.service import TrafficService


class FakeDriver:
    key = "xray"

    def __init__(self, clients: list[ClientUsageModel]):
        self._clients = clients

    def usage_snapshot(self) -> UsageSnapshotModel:
        return UsageSnapshotModel(
            inbounds=[
                InboundUsageModel(
                    id=1,
                    tag="test-in",
                    clients=self._clients,
                )
            ]
        )


class FakeRegistry:
    def __init__(self, cores: list[str], driver: FakeDriver):
        self.settings = type("S", (), {"cores": lambda self: cores})()
        self._driver = driver

    def get(self, core: str) -> FakeDriver:
        return self._driver


def test_traffic_service_tracks_pending_delta(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    driver = FakeDriver(
        [
            ClientUsageModel(
                id="uuid-1",
                email="user@example.com",
                incoming=1_000_000,
                outgoing=500_000,
            )
        ]
    )
    registry = FakeRegistry(["xray"], driver)

    stats = traffic.sample_all(registry)
    assert stats["initialized"] == 1
    assert traffic.pending_payload()["users"] == {}

    driver._clients[0].incoming = 1_200_000
    driver._clients[0].outgoing = 700_000
    traffic.sample_all(registry)

    payload = traffic.pending_payload()
    assert payload["users"]["uuid-1"] == {
        "core": "xray",
        "uplink": 200_000,
        "downlink": 200_000,
    }

    acked = traffic.ack_pending()
    assert acked == 1
    assert traffic.pending_payload()["users"] == {}

    driver._clients[0].incoming = 1_300_000
    traffic.sample_all(registry)
    payload = traffic.pending_payload()
    assert payload["users"]["uuid-1"]["downlink"] == 100_000


def test_traffic_service_regression_resets_baseline(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-2", email="reset@example.com", incoming=900, outgoing=100)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    traffic.sample_all(registry)
    client.incoming = 1_500
    client.outgoing = 200
    traffic.sample_all(registry)
    assert traffic.pending_payload()["users"]["uuid-2"]["downlink"] == 600

    traffic.ack_pending()
    client.incoming = 200
    client.outgoing = 50
    stats = traffic.sample_all(registry)
    assert stats["regressed"] == 1
    assert traffic.pending_payload()["users"] == {}


def test_traffic_service_migrates_legacy_email_rows_to_client_id(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    client = ClientUsageModel(
        id="uuid-new",
        email="legacy@example.com",
        incoming=1_000,
        outgoing=500,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    store.set_traffic_ack("xray", "legacy@example.com", 800, 400)
    store.upsert_traffic_pending("xray", "legacy@example.com", 200, 100, 1_000, 500)

    traffic.sample_all(registry)

    assert traffic.pending_payload()["users"]["uuid-new"] == {
        "core": "xray",
        "uplink": 100,
        "downlink": 200,
    }
    assert traffic.pending_payload()["users"]["legacy@example.com"] == {
        "core": "xray",
        "uplink": 100,
        "downlink": 200,
    }
    assert store.get_traffic_pending("xray", "legacy@example.com") is None
    assert store.get_traffic_ack("xray", "legacy@example.com") is None
    assert store.get_traffic_ack("xray", "uuid-new") == {
        "incoming": 800,
        "outgoing": 400,
    }


def test_wireguard_stale_handshake_still_tracks_pending(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    stale = int(time.time()) - 300
    client = ClientUsageModel(
        id="peer-1",
        email="wg@example.com",
        incoming=1_000,
        outgoing=500,
        handshake_at=stale,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    traffic.sample_all(registry)
    client.incoming = 1_148
    stats = traffic.sample_all(registry)

    assert stats["pending"] == 1
    assert traffic.pending_payload()["users"]["peer-1"]["downlink"] == 148
    assert traffic.pending_payload()["users"]["wg@example.com"]["downlink"] == 148


def test_ack_clients_accepts_email_alias(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-mail", email="alias@example.com", incoming=100, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    traffic.sample_all(registry)
    client.incoming = 400
    traffic.sample_all(registry)
    traffic.pending_payload()

    acked, not_found = traffic.ack_clients(["alias@example.com"])
    assert acked == ["alias@example.com"]
    assert not_found == []
    assert traffic.pending_payload()["users"] == {}


def test_ack_uses_get_snapshot_so_later_growth_stays_queued(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-snap", email="snap@example.com", incoming=1_000, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    traffic.sample_all(registry)
    client.incoming = 1_100
    traffic.sample_all(registry)
    payload = traffic.pending_payload()
    assert payload["users"]["uuid-snap"]["downlink"] == 100

    client.incoming = 1_250
    traffic.sample_all(registry)

    acked, not_found = traffic.ack_clients(["uuid-snap"])
    assert acked == ["uuid-snap"]
    assert not_found == []

    traffic.sample_all(registry)
    leftover = traffic.pending_payload()["users"]["uuid-snap"]
    assert leftover["downlink"] == 150
