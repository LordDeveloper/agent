from __future__ import annotations

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


async def test_pending_is_not_requeued_after_ack_when_counters_are_unchanged(store):
    """Regression: stale pending must not survive a successful POST ack."""
    traffic = TrafficService(store)
    client = ClientUsageModel(
        id="node-billing",
        email="billing@example.com",
        incoming=0,
        outgoing=0,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await traffic.sample_all(registry)
    client.incoming = 200 * 1024 * 1024
    client.outgoing = 3 * 1024 * 1024
    await traffic.sample_all(registry)

    first = await traffic.pending_payload()
    assert first["users"]["node-billing"]["downlink"] == 200 * 1024 * 1024

    acked, not_found = await traffic.ack_clients(["node-billing"])
    assert acked == ["node-billing"]
    assert not_found == []

    await traffic.sample_all(registry)
    second = await traffic.pending_payload()
    assert second["users"] == {}
