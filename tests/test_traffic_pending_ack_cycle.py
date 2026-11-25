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


async def test_pending_page_leaves_the_rest_of_the_queue(store):
    """A capped GET bills only the chunks it returned. The next page stays queued."""
    traffic = TrafficService(store)
    first = ClientUsageModel(id="a-page", email="a@example.com", incoming=0, outgoing=0)
    later = ClientUsageModel(id="z-later", email="z@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([first, later])
    registry = FakeRegistry(["xray"], driver)

    await traffic.sample_all(registry)
    first.incoming = 10
    await traffic.sample_all(registry)
    first.incoming = 30
    await traffic.sample_all(registry)
    first.incoming = 60
    await traffic.sample_all(registry)
    later.incoming = 7
    await traffic.sample_all(registry)

    page = await traffic.pending_payload(
        persist_snapshot=False,
        client_limit=1,
        chunks_per_client=2,
    )
    assert page["truncated"] is True
    assert page["users"]["a-page"]["downlink"] == 30
    assert len(page["users"]["a-page"]["chunks"]) == 2
    assert "z-later" not in page["users"]

    deleted, missing = await traffic.ack_chunk_ids(
        [chunk["id"] for chunk in page["users"]["a-page"]["chunks"]]
    )
    assert deleted == 2
    assert missing == []
    await traffic.ack_clients(
        ["a-page"],
        billed={"a-page": (30, 0)},
        consume_billed_chunks=False,
    )

    rest = await traffic.pending_payload(
        persist_snapshot=False,
        client_limit=10,
        chunks_per_client=10,
    )
    assert rest["truncated"] is False
    assert rest["users"]["a-page"]["downlink"] == 30
    assert rest["users"]["z-later"]["downlink"] == 7
