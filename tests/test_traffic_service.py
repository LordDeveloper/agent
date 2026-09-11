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


def test_wireguard_stale_handshake_does_not_create_pending(tmp_path):
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

    assert stats["stale_handshake"] == 1
    assert traffic.pending_payload()["users"] == {}


def test_wireguard_fresh_handshake_still_tracks_pending(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    fresh = int(time.time()) - 30
    client = ClientUsageModel(
        id="peer-2",
        email="live@example.com",
        incoming=1_000,
        outgoing=500,
        handshake_at=fresh,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    traffic.sample_all(registry)
    client.incoming = 1_500
    stats = traffic.sample_all(registry)

    assert stats.get("pending", 0) >= 1 or "peer-2" in traffic.pending_payload()["users"]
    assert traffic.pending_payload()["users"]["peer-2"]["downlink"] == 500


def test_wireguard_stale_handshake_freezes_existing_pending(tmp_path):
    store = Store(tmp_path / "agent.db")
    traffic = TrafficService(store)
    fresh = int(time.time()) - 30
    client = ClientUsageModel(
        id="peer-3",
        email="freeze@example.com",
        incoming=1_000,
        outgoing=0,
        handshake_at=fresh,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    traffic.sample_all(registry)
    client.incoming = 1_400
    traffic.sample_all(registry)
    assert traffic.pending_payload()["users"]["peer-3"]["downlink"] == 400

    client.handshake_at = int(time.time()) - 300
    client.incoming = 1_548
    stats = traffic.sample_all(registry)

    assert stats["pending_frozen"] == 1
    pending = traffic.pending_payload()["users"]["peer-3"]
    assert pending["downlink"] == 400

    traffic.ack_clients(["peer-3"])
    client.incoming = 1_600
    stats = traffic.sample_all(registry)
    assert stats["stale_handshake"] == 1
    assert traffic.pending_payload()["users"] == {}
