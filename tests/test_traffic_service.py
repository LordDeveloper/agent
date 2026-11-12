from __future__ import annotations

import asyncio

import pytest

from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.traffic.service import TrafficService


class FakeDriver:
    key = "xray"

    def __init__(self, clients: list[ClientUsageModel]):
        self._clients = clients

    def usage_snapshot(self, **kwargs: object) -> UsageSnapshotModel:
        self.last_snapshot_kwargs = kwargs
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
        self.settings = type(
            "S",
            (),
            {
                "cores": lambda self: cores,
                "traffic_billing_cores": lambda self: cores,
                "traffic_xray_reset_stats": False,
            },
        )()
        self._driver = driver

    def get(self, core: str) -> FakeDriver:
        return self._driver


async def _sample(traffic: TrafficService, registry: FakeRegistry):
    return await traffic.sample_all(registry)


def test_interval_delta_matches_panel_per_direction_formula():
    tick_in, tick_out, reg = TrafficService._interval_delta_from_cursor(130, 65, 100, 50)
    assert tick_in == 30
    assert tick_out == 15
    assert not reg

    tick_in, tick_out, reg = TrafficService._interval_delta_from_cursor(200, 550, 1600, 500)
    assert tick_in == 200
    assert tick_out == 50
    assert reg


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
    user = payload["users"]["uuid-1"]
    assert user["core"] == "xray"
    assert user["downlink"] == 200_000
    assert user["uplink"] == 200_000
    assert len(user["chunks"]) == 1

    acked = await traffic.ack_pending()
    assert acked == 1
    assert (await traffic.pending_payload())["users"] == {}

    driver._clients[0].incoming = 1_300_000
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    assert payload["users"]["uuid-1"]["downlink"] == 100_000


async def test_linked_l2tp_delta_is_queued_on_the_wireguard_peer(store):
    """PPP bytes for a companion use the peer node_id and do not move the kernel cursor."""
    traffic = TrafficService(store)
    companion = ClientUsageModel(
        id="peer-1",
        email="wg@example.com",
        incoming=1_000,
        outgoing=400,
        billing_core="wireguard",
        billing_key="peer-1",
    )
    driver = FakeDriver([companion])
    registry = FakeRegistry(["l2tp"], driver)

    await _sample(traffic, registry)
    companion.incoming = 1_500
    companion.outgoing = 450
    await _sample(traffic, registry)

    pending = await traffic.pending_payload()
    user = pending["users"]["peer-1"]
    assert user["core"] == "wireguard"
    assert user["downlink"] == 500
    assert user["uplink"] == 50
    assert await store.get_traffic_ack("l2tp", "peer-1") is None
    cursor = await store.get_traffic_ack("wireguard", "peer-1")
    assert cursor is None or cursor == {"incoming": 0, "outgoing": 0}


async def test_reboot_bills_only_the_new_core_counter(store):
    """Cursor is the last core counter. A reboot bills that new counter, not the history."""
    traffic = TrafficService(store)
    client = ClientUsageModel(
        id="peer-reboot",
        email="reboot@example.com",
        incoming=14_650_000_000,
        outgoing=250_000_000,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"] == {}

    client.incoming = 14_700_000_000
    client.outgoing = 251_000_000
    await _sample(traffic, registry)
    grown = (await traffic.pending_payload())["users"]["peer-reboot"]
    assert grown["downlink"] == 50_000_000
    assert grown["uplink"] == 1_000_000
    await traffic.ack_pending()

    client.incoming = 80_000_000
    client.outgoing = 2_000_000
    stats = await _sample(traffic, registry)
    assert stats["regressed"] == 1
    reset = (await traffic.pending_payload())["users"]["peer-reboot"]
    assert reset["downlink"] == 80_000_000
    assert reset["uplink"] == 2_000_000

    client.incoming = 90_000_000
    client.outgoing = 2_500_000
    await _sample(traffic, registry)
    after = (await traffic.pending_payload())["users"]["peer-reboot"]
    assert after["downlink"] == 90_000_000
    assert after["uplink"] == 2_500_000


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

    await _sample(traffic, registry)
    client.incoming = 1_200
    client.outgoing = 600
    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    user = payload["users"]["uuid-new"]
    assert user["core"] == "xray"
    assert user["downlink"] == 200
    assert user["uplink"] == 100
    assert len(user["chunks"]) == 1
    assert "legacy@example.com" not in payload["users"]


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
    assert len(plans[0]["client_cursor_upserts"]) == 80
    assert plans[0]["chunk_inserts"] == []

    await _sample(traffic, registry)
    assert len(plans) == 2
    assert plans[1]["chunk_inserts"] == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_pending_get_is_not_blocked_while_snapshot_awaits_ack(store):
    """Single-writer panel billing; GET must not 409 while ack is still in flight."""
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
    again = await other.pending_payload()
    assert again["users"]["locked-node"]["downlink"] == 500

    acked, not_found = await other.ack_clients(["locked-node"])
    assert acked == ["locked-node"]
    assert not_found == []

    cleared = await other.pending_payload()
    assert "locked-node" not in cleared["users"]


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

    await traffic.pending_payload()
    acked, not_found = await traffic.ack_clients(["node-1"])
    assert acked == ["node-1"]
    assert not_found == []
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
    client.incoming = 1_600
    client.outgoing = 900
    await _sample(traffic, registry)

    payload = await traffic.pending_payload()
    user = payload["users"]["node-1"]
    assert user["core"] == "xray"
    assert user["downlink"] == 300
    assert user["uplink"] == 200
    assert len(user["chunks"]) == 1
    assert "xray-uuid" not in payload["users"]

    acked, not_found = await traffic.ack_clients(["xray-uuid"])
    assert acked == ["node-1"]
    assert not_found == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_protocol_uuid_row_is_not_stolen_from_another_client(store):
    traffic = TrafficService(store)
    await store.set_traffic_ack("xray", "xray-uuid", 0, 0)
    clients = [
        ClientUsageModel(id="node-1", email="one@example.com", protocol_id="xray-uuid", incoming=90, outgoing=0),
        ClientUsageModel(id="xray-uuid", email="two@example.com", incoming=40, outgoing=10),
    ]
    driver = FakeDriver(clients)
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    clients[1].incoming = 80
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
    live = payload["users"]["live-node"]
    assert live["core"] == "wireguard"
    assert live["downlink"] == 10
    assert live["uplink"] == 5
    assert live["chunks"] == []
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

    live = payload["users"]["live-node"]
    assert live["core"] == "wireguard"
    assert live["downlink"] == 80
    assert live["uplink"] == 20
    assert live["chunks"] == []
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
    quoted = payload["users"]["iEhV1M"]
    assert quoted["core"] == "xray"
    assert quoted["downlink"] == 30
    assert quoted["uplink"] == 7
    assert quoted["chunks"] == []
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
    assert (await traffic.pending_payload())["users"] == {}


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


async def test_sample_does_not_commit_in_chunks(store):
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

    payload = await traffic.pending_payload()
    assert payload["users"]["a"]["downlink"] == 50
    assert payload["users"]["b"]["downlink"] == 60
    rows = await store.list_traffic_pending()
    assert len(rows) == 2
    assert {row["client_key"] for row in rows} == {"a", "b"}


async def test_interrupted_sample_does_not_leave_a_partial_plan(store, monkeypatch):
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

    assert await store.list_traffic_pending() == []
    assert await store.get_traffic_ack("xray", "a") is None
    assert await store.get_traffic_ack("xray", "b") is None


async def test_stale_email_cursor_does_not_rebill_the_live_counter_every_sample(store):
    """A higher cursor left under the email must not reset the baseline every sample.

    That path queues the whole live counter again on each tick, so unacked
    volume climbs by the same GiB block instead of the interval delta.
    """
    from agent.auth_scope import DEFAULT_SCOPE

    traffic = TrafficService(store)
    client = ClientUsageModel(
        id="adb5e0dc-0d9b-4dad-bdd1-c0522efd00f9",
        email="wg@example.com",
        incoming=13_000_000_000,
        outgoing=3_900_000_000,
    )
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    await _sample(traffic, registry)
    await store.bulk_set_client_traffic_cursors(
        DEFAULT_SCOPE,
        [("wireguard", "wg@example.com", 54_000_000_000, 16_000_000_000)],
    )

    client.incoming = 13_100_000_000
    client.outgoing = 3_950_000_000
    await _sample(traffic, registry)
    client.incoming = 13_250_000_000
    client.outgoing = 3_980_000_000
    await _sample(traffic, registry)

    user = (await traffic.pending_payload())["users"][client.id]
    assert user["downlink"] == 250_000_000
    assert user["uplink"] == 80_000_000
    assert len(user["chunks"]) == 2


async def test_interface_save_keeps_the_wireguard_billing_cursor(store):
    """Saving peer stats must not wipe the sampler cursor or the unacked chunk."""
    traffic = TrafficService(store)
    client = ClientUsageModel(id="peer-1", email="peer@example.com", incoming=1_000, outgoing=100)
    driver = FakeDriver([client])
    registry = FakeRegistry(["wireguard"], driver)

    await _sample(traffic, registry)
    await store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg0",
            "peers": [{
                "id": "peer-1",
                "email": "peer@example.com",
                "incoming": 1_500,
                "outgoing": 140,
                "_raw_incoming": 1_500,
                "_raw_outgoing": 140,
            }],
        },
    )
    client.incoming = 1_500
    client.outgoing = 140
    await _sample(traffic, registry)

    user = (await traffic.pending_payload())["users"]["peer-1"]
    assert user["downlink"] == 500
    assert user["uplink"] == 40

    await store.put_doc(
        "wireguard",
        "interface",
        "1",
        {"id": 1, "name": "wg0", "peers": []},
    )
    saved = await store.get_doc("wireguard", "interface", "1")
    assert saved.get("peers") in (None, [])


async def test_wireguard_still_queues_pending_when_xray_reset_flag_is_on(store):
    """reset_stats is Xray-only. Other cores are sampled with no extra arguments."""

    class CoreDriver:
        def __init__(self, clients: list[ClientUsageModel]) -> None:
            self._clients = clients

        def usage_snapshot(self) -> UsageSnapshotModel:
            return UsageSnapshotModel(
                inbounds=[InboundUsageModel(id=1, tag="wg0", clients=self._clients)]
            )

    driver = CoreDriver(
        [ClientUsageModel(id="peer-1", email="peer@example.com", incoming=100, outgoing=10)]
    )

    class Registry:
        def __init__(self) -> None:
            self.settings = type(
                "S",
                (),
                {
                    "cores": lambda self: ["wireguard"],
                    "traffic_billing_cores": lambda self: ["wireguard"],
                    "traffic_xray_reset_stats": True,
                },
            )()

        def get(self, core: str) -> CoreDriver:
            assert core == "wireguard"
            return driver

    traffic = TrafficService(store)
    registry = Registry()
    first = await traffic.sample_all(registry)
    assert first.get("initialized", 0) >= 1
    assert (await traffic.pending_payload())["users"] == {}

    driver._clients[0].incoming = 180
    driver._clients[0].outgoing = 25
    await traffic.sample_all(registry)
    user = (await traffic.pending_payload())["users"]["peer-1"]
    assert user["core"] == "wireguard"
    assert user["downlink"] == 80
    assert user["uplink"] == 15


async def test_sample_all_passes_reset_stats_only_to_xray(store):
    class WireGuardDriver:
        def __init__(self) -> None:
            self.calls = 0
            self._clients = [ClientUsageModel(id="peer-1", incoming=10, outgoing=1)]

        def usage_snapshot(self) -> UsageSnapshotModel:
            self.calls += 1
            return UsageSnapshotModel(
                inbounds=[InboundUsageModel(id=1, tag="wg0", clients=self._clients)]
            )

    wg = WireGuardDriver()
    xray = FakeDriver([ClientUsageModel(id="x-1", incoming=5, outgoing=1)])

    class Registry:
        def __init__(self) -> None:
            self.settings = type(
                "S",
                (),
                {
                    "cores": lambda self: ["xray", "wireguard"],
                    "traffic_billing_cores": lambda self: ["xray", "wireguard"],
                    "traffic_xray_reset_stats": True,
                },
            )()
            self._drivers = {"xray": xray, "wireguard": wg}

        def get(self, core: str):
            return self._drivers[core]

    stats = await TrafficService(store).sample_all(Registry())
    assert wg.calls == 1
    assert xray.last_snapshot_kwargs == {"reset_stats": True}
    # Xray reset_stats counts the first interval as pending; WG anchors without a chunk.
    assert stats.get("initialized", 0) >= 1
    users = (await TrafficService(store).pending_payload())["users"]
    assert users["x-1"]["downlink"] == 5
    assert "peer-1" not in users


async def test_snapshot_failure_is_recorded_in_sample_timing(store):
    import json

    from agent.traffic.service import AGENT_META_CORE, LAST_SAMPLE_TIMING_META_KEY

    class BrokenDriver:
        def usage_snapshot(self) -> UsageSnapshotModel:
            raise RuntimeError("wg dump failed")

    class Registry:
        def __init__(self) -> None:
            self.settings = type(
                "S",
                (),
                {
                    "cores": lambda self: ["wireguard"],
                    "traffic_billing_cores": lambda self: ["wireguard"],
                    "traffic_xray_reset_stats": True,
                },
            )()

        def get(self, core: str) -> BrokenDriver:
            return BrokenDriver()

    await TrafficService(store).sample_cores_blocking(Registry())
    raw = await store.get_meta(AGENT_META_CORE, LAST_SAMPLE_TIMING_META_KEY)
    timing = json.loads(raw) if isinstance(raw, str) else raw
    assert "wg dump failed" in timing["wireguard"]["error"]
    assert "wg dump failed" in timing["errors"]["wireguard"]


async def test_xray_reset_stats_queues_interval_and_sums_client_cursor(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-x", email="x@example.com", incoming=100, outgoing=40)
    driver = FakeDriver([client])
    settings = type(
        "S",
        (),
        {
            "cores": lambda self: ["xray"],
            "traffic_billing_cores": lambda self: ["xray"],
            "traffic_xray_reset_stats": True,
        },
    )()
    registry = FakeRegistry(["xray"], driver)
    registry.settings = settings

    await _sample(traffic, registry)
    assert driver.last_snapshot_kwargs == {"reset_stats": True}
    payload = await traffic.pending_payload()
    assert payload["users"]["node-x"]["downlink"] == 100
    assert payload["users"]["node-x"]["uplink"] == 40

    client.incoming = 30
    client.outgoing = 10
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    assert payload["users"]["node-x"]["downlink"] == 130
    assert payload["users"]["node-x"]["uplink"] == 50


async def test_zero_cursor_does_not_queue_lifetime_total(store):
    from agent.auth_scope import DEFAULT_SCOPE

    traffic = TrafficService(store)
    gb = 1024**3
    client = ClientUsageModel(id="node-zero", email="zero@example.com", incoming=2 * gb, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await store.bulk_set_client_traffic_cursors(
        DEFAULT_SCOPE,
        [("xray", "node-zero", 0, 0)],
    )
    stats = await _sample(traffic, registry)
    assert stats.get("initialized", 0) >= 1
    assert (await traffic.pending_payload())["users"] == {}


async def test_legacy_traffic_pending_does_not_stack_on_chunks(store):
    """Stale traffic_pending rows must not inflate chunk sums (watch / GET pending)."""
    from agent.auth_scope import DEFAULT_SCOPE
    from agent.database.models.traffic import TrafficPending

    mb = 1024 * 1024
    traffic = TrafficService(store)
    client = ClientUsageModel(id="node-legacy", email="legacy@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 5 * mb
    client.outgoing = mb
    await _sample(traffic, registry)

    async with store._runtime.writing() as session:
        session.add(
            TrafficPending(
                scope=DEFAULT_SCOPE,
                core="xray",
                client_key="node-legacy",
                delta_incoming=500 * mb,
                delta_outgoing=0,
                current_incoming=0,
                current_outgoing=0,
            )
        )
        await session.commit()

    rows = await store.list_traffic_pending()
    assert len(rows) == 1
    assert rows[0]["delta_incoming"] == 5 * mb
    assert rows[0]["delta_outgoing"] == mb


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

    rows = await store.list_traffic_pending()
    assert len(rows) == 1
    assert rows[0]["client_key"] == "node-sum"
    assert rows[0]["delta_incoming"] == 9 * mb
    assert rows[0]["delta_outgoing"] == 7 * mb

    # A counter reset updates that same row: previous pending plus the new counter.
    client.incoming = 2 * mb
    client.outgoing = 1 * mb
    await _sample(traffic, registry)
    rows = await store.list_traffic_pending()
    assert len(rows) == 1
    assert rows[0]["client_key"] == "node-sum"
    assert rows[0]["delta_incoming"] == 11 * mb
    assert rows[0]["delta_outgoing"] == 8 * mb


async def test_ack_chunk_ids_clears_billed_chunks(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="chunk-node", email="chunk@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 1_000
    client.outgoing = 500
    await _sample(traffic, registry)
    payload = await traffic.pending_payload()
    chunk_ids = [str(item["id"]) for item in payload["users"]["chunk-node"]["chunks"]]
    assert chunk_ids

    deleted, missing = await traffic.ack_chunk_ids(chunk_ids)
    assert deleted == len(chunk_ids)
    assert missing == []
    assert (await traffic.pending_payload())["users"] == {}


async def test_clear_pending_queue_wipes_chunks(store):
    traffic = TrafficService(store)
    client = ClientUsageModel(id="clear-me", email="clear@example.com", incoming=0, outgoing=0)
    driver = FakeDriver([client])
    registry = FakeRegistry(["xray"], driver)

    await _sample(traffic, registry)
    client.incoming = 50_000
    await _sample(traffic, registry)
    assert (await traffic.pending_payload())["users"]

    cleared = await traffic.clear_pending_queue()
    assert int(cleared["chunks_deleted"]) >= 1
    assert (await traffic.pending_payload())["users"] == {}
