from __future__ import annotations

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
    assert payload["users"]["user@example.com"] == {
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
    assert payload["users"]["user@example.com"]["downlink"] == 100_000


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
    assert traffic.pending_payload()["users"]["reset@example.com"]["downlink"] == 600

    traffic.ack_pending()
    client.incoming = 200
    client.outgoing = 50
    stats = traffic.sample_all(registry)
    assert stats["regressed"] == 1
    assert traffic.pending_payload()["users"] == {}
