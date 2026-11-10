from __future__ import annotations

import asyncio

import pytest

from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.traffic.service import PendingReadLocked, TrafficService


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
    reset = (await traffic.pending_payload())["users"]["uuid-2"]
    assert reset["downlink"] == 200
    assert reset["uplink"] == 50

    client.incoming = 230
    await _sample(traffic, registry)
    grown = (await traffic.pending_payload())["users"]["uuid-2"]
    assert grown["downlink"] == 230
    assert grown["uplink"] == 50


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

    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-new"] == {
        "core": "xray",
        "uplink": 100,
        "downlink": 200,
    }
    assert "legacy@example.com" not in payload["users"]
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
    assert "wg@example.com" not in payload["users"]


async def test_pending_aliases_are_visible_to_another_process(store):
    """agent serve and agent work do not share the in-memory alias map."""
    writer = TrafficService(store)
    client = ClientUsageModel(
        id="vless-link-uuid",
        email="s0NTPq",
        incoming=1_000,
        outgoing=500,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(writer, registry)
    client.incoming = 249_133_115
    client.outgoing = 52_952_697
    await _sample(writer, registry)

    reader = TrafficService(store)
    payload = await reader.pending_payload()
    assert payload["users"]["vless-link-uuid"]["downlink"] == 249_133_115 - 1_000
    assert payload["users"]["vless-link-uuid"]["uplink"] == 52_952_697 - 500
    assert "s0NTPq" not in payload["users"]

    acked, not_found = await reader.ack_clients(["s0NTPq"])
    assert acked == ["vless-link-uuid"]
    assert not_found == []
    assert (await reader.pending_payload())["users"] == {}


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
    assert acked == ["uuid-mail"]
    assert not_found == []
    assert (await traffic.pending_payload())["users"] == {}

    await _sample(traffic, registry)
    client.incoming = 700
    await _sample(traffic, registry)
    await traffic.pending_payload()

    acked, not_found = await traffic.ack_clients(["uuid-mail"])
    assert acked == ["uuid-mail"]
    assert not_found == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_traffic_sample_writes_many_clients_in_one_plan(store):
    plans: list[dict] = []
    real_write = store._traffic._write_traffic_plan

    async def wrapped_write(session, writes):
        plans.append(writes)
        return await real_write(session, writes)

    store._traffic._write_traffic_plan = wrapped_write
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


async def test_pending_read_stays_locked_until_the_other_process_acks(store):
    owner = TrafficService(store)
    owner._pending_reader_id = "proc-a"
    client = ClientUsageModel(id="locked-node", email="locked@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(owner, registry)
    client.incoming = 500
    await _sample(owner, registry)
    payload = await owner.pending_payload()
    assert payload["users"]["locked-node"]["downlink"] == 500

    other = TrafficService(store)
    other._pending_reader_id = "proc-b"
    other._write_snapshot({
        "stale-node": [{
            "core": "xray",
            "client_key": "stale-node",
            "delta_incoming": 1,
            "delta_outgoing": 0,
            "current_incoming": 1,
            "current_outgoing": 0,
        }],
    })

    with pytest.raises(PendingReadLocked):
        await other.pending_payload()

    acked, not_found = await other.ack_clients(["locked-node"])
    assert acked == ["locked-node"]
    assert not_found == []

    again = await other.pending_payload()
    assert "locked-node" not in again["users"]


async def test_ack_billed_amount_when_snapshot_is_missing_keeps_later_growth(store):
    writer = TrafficService(store)
    client = ClientUsageModel(id="uuid-replay", email="replay@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(writer, registry)
    client.incoming = 1_000
    client.outgoing = 200
    await _sample(writer, registry)
    client.incoming = 1_250
    client.outgoing = 260
    await _sample(writer, registry)

    plain, missing = await TrafficService(store).ack_clients(["uuid-replay"])
    assert plain == []
    assert missing == ["uuid-replay"]
    assert (await store.get_traffic_pending("xray", "uuid-replay"))["delta_incoming"] == 1_250

    acked, not_found = await TrafficService(store).ack_clients(
        ["uuid-replay"],
        {"uuid-replay": (1_000, 200)},
    )
    assert acked == ["uuid-replay"]
    assert not_found == []
    kept = await store.get_traffic_pending("xray", "uuid-replay")
    assert kept["delta_incoming"] == 250
    assert kept["delta_outgoing"] == 60
    ack = await store.get_traffic_ack("xray", "uuid-replay")
    assert ack["incoming"] == 1_000
    assert ack["outgoing"] == 200

    client.incoming = 1_400
    await _sample(writer, registry)
    grown = await store.get_traffic_pending("xray", "uuid-replay")
    assert grown["delta_incoming"] == 400
    assert grown["delta_outgoing"] == 60


async def test_drop_discards_pending_when_snapshot_is_missing_and_keeps_later_growth(store):
    writer = TrafficService(store)
    client = ClientUsageModel(id="ghost-node", email="ghost@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(writer, registry)
    client.incoming = 800
    client.outgoing = 50
    await _sample(writer, registry)

    reader = TrafficService(store)
    acked, not_found = await reader.ack_clients([], drop=["ghost-node"])
    assert acked == ["ghost-node"]
    assert not_found == []
    assert await store.get_traffic_pending("xray", "ghost-node") is None

    await _sample(writer, registry)
    assert "ghost-node" not in (await writer.pending_payload())["users"]

    client.incoming = 900
    await _sample(writer, registry)
    grown = await store.get_traffic_pending("xray", "ghost-node")
    assert grown["delta_incoming"] == 100
    assert grown["delta_outgoing"] == 0

    missing_acked, missing = await TrafficService(store).ack_clients([], drop=["ghost-node"])
    assert "ghost-node" in missing_acked
    assert missing == []


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

    kept = await store.get_traffic_pending("xray", "uuid-snap")
    assert kept["delta_incoming"] == 150
    assert (await store.get_traffic_ack("xray", "uuid-snap"))["incoming"] == 1_100

    other = TrafficService(store)
    again, missing = await other.ack_clients(["uuid-snap"])
    assert again == []
    assert missing == ["uuid-snap"]
    assert (await store.get_traffic_pending("xray", "uuid-snap"))["delta_incoming"] == 150

    client.incoming = 1_400
    await _sample(traffic, registry)
    grown = await store.get_traffic_pending("xray", "uuid-snap")
    assert grown["delta_incoming"] == 300


async def test_ack_keeps_usage_that_arrived_after_the_read_when_the_counter_resets(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="uuid-reset", email="reset@example.com", incoming=1_000, outgoing=400)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_100
    client.outgoing = 450
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-reset"]["downlink"] == 100
    assert payload["users"]["uuid-reset"]["uplink"] == 50

    client.incoming = 1_180
    client.outgoing = 470
    await _sample(traffic, registry)
    client.incoming = 30
    client.outgoing = 10
    await _sample(traffic, registry)

    acked, not_found = await traffic.ack_clients(["uuid-reset"])
    assert acked == ["uuid-reset"]
    assert not_found == []

    pending = await store.get_traffic_pending("xray", "uuid-reset")
    assert pending["delta_incoming"] == 110
    assert pending["delta_outgoing"] == 30
    ack = await store.get_traffic_ack("xray", "uuid-reset")
    assert ack["incoming"] == 30
    assert ack["outgoing"] == 10


async def test_inspect_traffic_ack_reads_only_the_node_id(store):
    await store.set_traffic_ack("xray", "node-1", 10, 4)
    await store.upsert_traffic_pending("xray", "node-1", 2, 1, 12, 5)
    await store.set_traffic_ack("xray", "s0NTPq", 99, 88)

    found = await store.inspect_traffic_ack("node-1")
    assert [row["client_key"] for row in found["ack_rows"]] == ["node-1"]
    assert found["ack_rows"][0]["incoming"] == 10
    assert found["ack_rows"][0]["outgoing"] == 4
    assert found["ack_rows"][0]["updated_at"]
    assert found["pending_rows"][0]["delta_incoming"] == 2
    assert found["pending_rows"][0]["delta_outgoing"] == 1

    assert (await store.inspect_traffic_ack("missing-node"))["ack_rows"] == []
    assert (await store.get_traffic_ack("xray", "s0NTPq")) == {"incoming": 99, "outgoing": 88}


async def test_counter_reset_keeps_unacked_bytes_and_does_not_rebill_them(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-1", email="user@example.com", incoming=1_000, outgoing=400)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_600
    client.outgoing = 500
    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"]["node-1"]["downlink"] == 600

    client.incoming = 200
    client.outgoing = 50
    stats = await _sample(traffic, registry)
    assert stats["regressed"] == 1
    kept = (await traffic.pending_payload())["users"]["node-1"]
    assert kept["downlink"] == 800
    assert kept["uplink"] == 150

    client.incoming = 250
    client.outgoing = 80
    await _sample(traffic, registry)
    grown = (await traffic.pending_payload())["users"]["node-1"]
    assert grown["downlink"] == 850
    assert grown["uplink"] == 180

    await traffic.ack_clients(["node-1"])
    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"] == {}


async def test_one_sided_reset_keeps_growth_on_the_other_direction(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-1", email="user@example.com", incoming=1_000, outgoing=400)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_600
    client.outgoing = 500
    await _sample(traffic, registry)

    client.incoming = 200
    client.outgoing = 550
    stats = await _sample(traffic, registry)
    assert stats["regressed"] == 1
    kept = (await traffic.pending_payload())["users"]["node-1"]
    assert kept["downlink"] == 800
    assert kept["uplink"] == 150


async def test_xray_uuid_pending_moves_to_node_id_without_double_billing(store):
    traffic = TrafficService(store)
    await store.set_traffic_ack("xray", "xray-uuid", 1_000, 500)
    await store.upsert_traffic_pending("xray", "xray-uuid", 200, 100, 1_200, 600)
    client = ClientUsageModel(
        id="node-1",
        email="user@example.com",
        protocol_id="xray-uuid",
        incoming=1_300,
        outgoing=700,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    assert payload["users"]["node-1"] == {
        "core": "xray",
        "uplink": 200,
        "downlink": 300,
    }
    assert "xray-uuid" not in payload["users"]
    assert await store.get_traffic_pending("xray", "xray-uuid") is None
    assert await store.get_traffic_ack("xray", "node-1") == {"incoming": 1_000, "outgoing": 500}

    acked, not_found = await traffic.ack_clients(["xray-uuid"])
    assert acked == ["node-1"]
    assert not_found == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_protocol_uuid_row_is_not_stolen_from_another_client(store):
    traffic = TrafficService(store)
    await store.upsert_traffic_pending("xray", "xray-uuid", 40, 10, 40, 10)
    await store.set_traffic_ack("xray", "xray-uuid", 0, 0)
    clients = [
        ClientUsageModel(id="node-1", email="one@example.com", protocol_id="xray-uuid", incoming=90, outgoing=0),
        ClientUsageModel(id="xray-uuid", email="two@example.com", incoming=40, outgoing=10),
    ]
    driver = FakeDriver(clients)
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    assert payload["users"]["xray-uuid"]["downlink"] == 40
    assert "node-1" not in payload["users"]


async def test_pending_get_reads_the_queue_without_deleting_rows(store):
    """GET pending is a read. Absent clients stay queued until a sample or an ack."""
    await store.put_doc(
        "wireguard",
        "interface",
        "wg1",
        {
            "id": "wg1",
            "peers": [
                {
                    "id": "live-node",
                    "node_id": "live-node",
                    "email": "0wPo9T",
                    "is_enabled": False,
                }
            ],
        },
    )
    await store.upsert_traffic_pending("wireguard", "0wPo9T", 400, 50, 500, 80)
    await store.upsert_traffic_pending("wireguard", "live-node", 10, 5, 10, 5)
    await store.upsert_traffic_pending(
        "wireguard",
        "56a3e781-fe73-456e-80cf-4027ca3e52d9",
        9,
        1,
        9,
        1,
    )
    await store.upsert_traffic_pending("xray", "still-unlisted", 3, 1, 3, 1)

    traffic = TrafficService(store)
    payload = await traffic.pending_payload()

    assert set(payload["users"]) == {
        "0wPo9T",
        "live-node",
        "56a3e781-fe73-456e-80cf-4027ca3e52d9",
        "still-unlisted",
    }
    assert payload["users"]["live-node"] == {
        "core": "wireguard",
        "uplink": 5,
        "downlink": 10,
    }
    email = await store.get_traffic_pending("wireguard", "0wPo9T")
    assert int(email["delta_incoming"]) == 400
    assert int(email["delta_outgoing"]) == 50
    assert await store.get_traffic_pending("wireguard", "56a3e781-fe73-456e-80cf-4027ca3e52d9") is not None
    kept = await store.get_traffic_pending("wireguard", "live-node")
    assert int(kept["delta_incoming"]) == 10
    assert int(kept["delta_outgoing"]) == 5
    assert await store.get_traffic_pending("xray", "still-unlisted") is not None

    acked, not_found = await traffic.ack_clients(["live-node"])
    assert acked == ["live-node"]
    assert not_found == []
    assert "live-node" not in (await traffic.pending_payload())["users"]


async def test_pending_email_does_not_replace_a_larger_node_id_row(store):
    await store.put_doc(
        "wireguard",
        "interface",
        "wg1",
        {
            "id": "wg1",
            "peers": [{"id": "live-node", "node_id": "live-node", "email": "0wPo9T"}],
        },
    )
    await store.upsert_traffic_pending("wireguard", "0wPo9T", 5, 5, 5, 5)
    await store.upsert_traffic_pending("wireguard", "live-node", 80, 20, 80, 20)

    payload = await TrafficService(store).pending_payload()

    assert payload["users"]["live-node"] == {
        "core": "wireguard",
        "uplink": 20,
        "downlink": 80,
    }
    assert payload["users"]["0wPo9T"]["downlink"] == 5
    assert await store.get_traffic_pending("wireguard", "0wPo9T") is not None
    assert int((await store.get_traffic_pending("wireguard", "live-node"))["delta_incoming"]) == 80


async def test_xray_pending_uses_quota_node_id_and_drops_removed_clients(store):
    await store.put_doc(
        "xray",
        "client_quota",
        "node-a",
        {"id": "node-a", "node_id": "node-a", "email": "iEhV1M"},
    )
    await store.upsert_traffic_pending("xray", "iEhV1M", 30, 7, 30, 7)
    await store.upsert_traffic_pending("xray", "deleted-uuid", 4, 4, 4, 4)

    payload = await TrafficService(store).pending_payload()

    assert set(payload["users"]) == {"iEhV1M", "deleted-uuid"}
    assert payload["users"]["iEhV1M"] == {
        "core": "xray",
        "uplink": 7,
        "downlink": 30,
    }
    assert await store.get_traffic_pending("xray", "iEhV1M") is not None
    assert await store.get_traffic_pending("xray", "deleted-uuid") is not None


async def test_pending_is_only_the_growth_above_the_stored_baseline(store):
    """100MB/3MB recorded, then 105MB/3.5MB, queues 5MB/0.5MB and not the whole counter."""
    mb = 1024 * 1024
    traffic = TrafficService(store)
    client = ClientUsageModel(id="peer-1", email="wg@example.com", incoming=100 * mb, outgoing=3 * mb)
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    await _sample(traffic, registry)
    client.incoming = 105 * mb
    client.outgoing = int(3.5 * mb)
    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    assert payload["users"]["peer-1"]["downlink"] == 5 * mb
    assert payload["users"]["peer-1"]["uplink"] == int(0.5 * mb)

    await store.delete_traffic_pending("wireguard", "peer-1")
    await _sample(traffic, registry)
    restored = (await traffic.pending_payload())["users"]["peer-1"]
    assert restored["downlink"] == 5 * mb
    assert restored["uplink"] == int(0.5 * mb)


async def test_xray_restart_adds_the_new_counter_to_pending(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-1", email="user@example.com", incoming=1_000, outgoing=400)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_600
    client.outgoing = 500
    await _sample(traffic, registry)
    await traffic.ack_pending()

    client.incoming = 200
    client.outgoing = 50
    stats = await _sample(traffic, registry)
    assert stats["regressed"] == 1
    pending = (await traffic.pending_payload())["users"]["node-1"]
    assert pending["downlink"] == 200
    assert pending["uplink"] == 50

    client.incoming = 260
    client.outgoing = 70
    await _sample(traffic, registry)
    grown = (await traffic.pending_payload())["users"]["node-1"]
    assert grown["downlink"] == 260
    assert grown["uplink"] == 70


async def test_fast_core_samples_while_another_core_is_still_reading(store):
    release = asyncio.Event()

    class FastDriver:
        key = "xray"

        def __init__(self) -> None:
            self.incoming = 1_000

        def usage_snapshot(self) -> UsageSnapshotModel:
            return UsageSnapshotModel(
                inbounds=[
                    InboundUsageModel(
                        id=1,
                        tag="xray",
                        clients=[
                            ClientUsageModel(
                                id="fast",
                                email="fast@example.com",
                                incoming=self.incoming,
                                outgoing=0,
                            )
                        ],
                    )
                ]
            )

    class SlowDriver:
        key = "wireguard"

        async def usage_snapshot(self) -> UsageSnapshotModel:
            await release.wait()
            return UsageSnapshotModel(
                inbounds=[
                    InboundUsageModel(
                        id=1,
                        tag="wg0",
                        clients=[
                            ClientUsageModel(
                                id="slow",
                                email="slow@example.com",
                                incoming=50,
                                outgoing=0,
                            )
                        ],
                    )
                ]
            )

    fast = FastDriver()
    slow = SlowDriver()

    class Registry:
        def __init__(self) -> None:
            self.settings = type("S", (), {"cores": lambda self: ["xray", "wireguard"]})()
            self._drivers = {"xray": fast, "wireguard": slow}

        def get(self, core: str):
            return self._drivers[core]

    traffic = TrafficService(store)
    registry = Registry()
    started = await traffic.sample_unless_overlapping(registry, lock_seconds=30)
    assert started == {"started": 2}

    for _ in range(100):
        flight = traffic._core_flights.get("xray")
        if flight is None or flight[0].done():
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("xray sample did not finish while wireguard was blocked")

    slow_flight = traffic._core_flights["wireguard"][0]
    assert not slow_flight.done()

    fast.incoming = 1_500
    again = await traffic.sample_unless_overlapping(registry, lock_seconds=30)
    assert again == {"started": 1}

    for _ in range(100):
        flight = traffic._core_flights.get("xray")
        if flight is None or flight[0].done():
            break
        await asyncio.sleep(0.01)

    payload = await traffic.pending_payload()
    assert payload["users"]["fast"]["downlink"] == 500
    assert "slow" not in payload["users"]

    release.set()
    await slow_flight


async def test_sample_does_not_commit_in_chunks(store, monkeypatch):
    chunks = {"n": 0}

    async def track_chunk(session, pending):
        chunks["n"] += 1
        return pending

    monkeypatch.setattr(store._runtime, "commit_chunk", track_chunk)
    traffic = TrafficService(store)
    driver = FakeDriver(
        [
            ClientUsageModel(id="a", email="a@example.com", incoming=100, outgoing=10),
            ClientUsageModel(id="b", email="b@example.com", incoming=200, outgoing=20),
        ]
    )
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    driver._clients[0].incoming = 150
    driver._clients[1].incoming = 260
    await _sample(traffic, registry)

    assert chunks["n"] == 0
    payload = await traffic.pending_payload()
    assert payload["users"]["a"]["downlink"] == 50
    assert payload["users"]["b"]["downlink"] == 60


async def test_interrupted_sample_does_not_leave_a_partial_plan(store, monkeypatch):
    chunks = {"n": 0}

    async def track_chunk(session, pending):
        chunks["n"] += 1
        return pending

    monkeypatch.setattr(store._runtime, "commit_chunk", track_chunk)
    original = store._traffic._write_traffic_plan

    async def write_then_fail(session, writes):
        await original(session, writes)
        raise RuntimeError("sample interrupted")

    monkeypatch.setattr(store._traffic, "_write_traffic_plan", write_then_fail)
    traffic = TrafficService(store)
    driver = FakeDriver(
        [
            ClientUsageModel(id="a", email="a@example.com", incoming=100, outgoing=10),
            ClientUsageModel(id="b", email="b@example.com", incoming=200, outgoing=20),
        ]
    )

    await _sample(traffic, FakeRegistry(["xray"], driver))

    assert chunks["n"] == 0
    assert await store.list_traffic_pending() == []
    assert await store.get_traffic_ack("xray", "a") is None
    assert await store.get_traffic_ack("xray", "b") is None


async def test_unacked_samples_sum_download_and_upload(store):
    """Three growth samples before any ack are one pending total, per direction."""
    mb = 1024 * 1024
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-sum", email="sum@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"] == {}

    client.incoming = 1 * mb
    client.outgoing = 2 * mb
    await _sample(traffic, registry)

    client.incoming = 6 * mb
    client.outgoing = 3 * mb
    await _sample(traffic, registry)
    midway = (await traffic.pending_payload())["users"]["node-sum"]
    assert midway["downlink"] == 6 * mb
    assert midway["uplink"] == 3 * mb

    client.incoming = 9 * mb
    client.outgoing = 7 * mb
    await _sample(traffic, registry)
    pending = (await traffic.pending_payload())["users"]["node-sum"]
    assert pending["downlink"] == 9 * mb
    assert pending["uplink"] == 7 * mb
