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


async def _sample(traffic: TrafficService, registry: FakeRegistry):
    return await traffic.sample_all(registry)


async def test_traffic_service_tracks_pending_delta(store):
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

    stats = await _sample(traffic, registry)
    assert stats["initialized"] == 1
    assert (await traffic.pending_payload())["users"] == {}

    driver._clients[0].incoming = 1_200_000
    driver._clients[0].outgoing = 700_000
    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-1"] == {
        "core": "xray",
        "uplink": 200_000,
        "downlink": 200_000,
    }

    acked = await traffic.ack_pending()
    assert acked == 1
    assert (await traffic.pending_payload())["users"] == {}

    driver._clients[0].incoming = 1_300_000
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-1"]["downlink"] == 100_000


async def test_traffic_service_regression_resets_baseline(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-2", email="reset@example.com", incoming=900, outgoing=100)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_500
    client.outgoing = 200
    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"]["uuid-2"]["downlink"] == 600

    await traffic.ack_pending()
    client.incoming = 200
    client.outgoing = 50
    stats = await _sample(traffic, registry)
    assert stats["regressed"] == 1
    assert (await traffic.pending_payload())["users"] == {}


async def test_traffic_service_migrates_legacy_email_rows_to_client_id(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(
        id="uuid-new",
        email="legacy@example.com",
        incoming=1_000,
        outgoing=500,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await store.set_traffic_ack("xray", "legacy@example.com", 800, 400)
    await store.upsert_traffic_pending("xray", "legacy@example.com", 200, 100, 1_000, 500)

    await _sample(traffic, registry)

    assert (await traffic.pending_payload())["users"]["uuid-new"] == {
        "core": "xray",
        "uplink": 100,
        "downlink": 200,
    }
    assert (await traffic.pending_payload())["users"]["legacy@example.com"] == {
        "core": "xray",
        "uplink": 100,
        "downlink": 200,
    }
    assert await store.get_traffic_pending("xray", "legacy@example.com") is None
    assert await store.get_traffic_ack("xray", "legacy@example.com") is None
    assert await store.get_traffic_ack("xray", "uuid-new") == {
        "incoming": 800,
        "outgoing": 400,
    }


async def test_wireguard_stale_handshake_still_tracks_pending(store):
    import time

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

    await _sample(traffic, registry)
    client.incoming = 1_148
    stats = await _sample(traffic, registry)

    assert stats["pending"] == 1
    payload = await traffic.pending_payload()
    assert payload["users"]["peer-1"]["downlink"] == 148
    assert payload["users"]["wg@example.com"]["downlink"] == 148


async def test_ack_clients_accepts_email_alias(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-mail", email="alias@example.com", incoming=100, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 400
    await _sample(traffic, registry)
    await traffic.pending_payload()

    acked, not_found = await traffic.ack_clients(["alias@example.com"])
    assert acked == ["alias@example.com"]
    assert not_found == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_traffic_sample_writes_many_clients_in_one_plan(store):
    plans: list[dict] = []
    real_write = store._write_traffic_plan

    async def wrapped_write(conn, writes):
        plans.append(writes)
        return await real_write(conn, writes)

    store._write_traffic_plan = wrapped_write
    clients = [
        ClientUsageModel(id=f"id-{index}", email=f"user{index}@example.com", incoming=10, outgoing=1)
        for index in range(40)
    ]
    traffic = TrafficService(store)
    driver = FakeDriver(clients)
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    assert len(plans) == 1
    assert len(plans[0]["ack_upserts"]) == 40
    assert plans[0]["pending_deletes"] == []

    await _sample(traffic, registry)
    assert len(plans) == 2
    assert plans[1]["ack_upserts"] == []
    assert plans[1]["ack_deletes"] == []
    assert plans[1]["pending_upserts"] == []
    assert plans[1]["pending_deletes"] == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_ack_uses_get_snapshot_so_later_growth_stays_queued(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-snap", email="snap@example.com", incoming=1_000, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_100
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-snap"]["downlink"] == 100

    client.incoming = 1_250
    await _sample(traffic, registry)

    acked, not_found = await traffic.ack_clients(["uuid-snap"])
    assert acked == ["uuid-snap"]
    assert not_found == []

    await _sample(traffic, registry)
    leftover = (await traffic.pending_payload())["users"]["uuid-snap"]
    assert leftover["downlink"] == 150
