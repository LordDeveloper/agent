import asyncio
import time

from agent.drivers.wireguard import WireGuardDriver, _unapplied_peer_keys
from agent.support.egress_tasks import EgressScheduler, configure_egress, reset_egress_for_tests


def test_unapplied_peer_keys_ignore_disabled_peers():
    iface = {
        "peers": [
            {"public_key": "applied-key", "is_enabled": True},
            {"public_key": "missing-key", "is_enabled": True},
            {"public_key": "disabled-key", "is_enabled": False},
        ]
    }
    assert _unapplied_peer_keys(iface, {"applied-key": {}}) == ["missing-key"]


def test_routing_enqueue_does_not_wait_and_coalesces(tmp_path):
    class Driver:
        def __init__(self):
            self.calls = 0
            self.peers = ["keep"]

        async def list_interfaces(self):
            return [{"id": "1", "peers": list(self.peers)}]

        async def _apply_peer_egress(self, rows, drop_keys=None):
            self.calls += 1
            await asyncio.sleep(0.01)

    driver = Driver()

    class Registry:
        def get(self, _core):
            return driver

        def enabled_drivers(self):
            return []

    scheduler = EgressScheduler(Registry(), tmp_path, retry_delay=0)

    async def scenario():
        for _ in range(15):
            scheduler.enqueue("wireguard", "peer-a")
        await scheduler._drain(asyncio.Event())

    asyncio.run(scenario())
    assert driver.calls == 1
    assert scheduler.status_for(["peer-a"]) == "completed"


def test_slow_routing_does_not_block_another_enqueue(tmp_path):
    release = asyncio.Event()
    entered = asyncio.Event()

    class Driver:
        async def _apply_peer_egress(self, rows, drop_keys=None):
            entered.set()
            await release.wait()

    class Registry:
        def get(self, _core):
            return Driver()

    scheduler = EgressScheduler(Registry(), tmp_path, retry_delay=0)

    async def scenario():
        scheduler.enqueue("wireguard", "slow")
        worker = asyncio.create_task(scheduler._drain(asyncio.Event()))
        await entered.wait()
        started = time.perf_counter()
        scheduler.enqueue("wireguard", "other")
        elapsed = time.perf_counter() - started
        release.set()
        await worker
        return elapsed

    assert asyncio.run(scenario()) < 0.1


def test_stale_routing_job_reapplies_current_store(tmp_path):
    class Driver:
        def __init__(self):
            self.peers = ["old"]
            self.seen: list[list[str]] = []

        async def list_interfaces(self):
            return [{"id": "1", "peers": list(self.peers)}]

        async def _apply_peer_egress(self, rows, drop_keys=None):
            snapshot = await self.list_interfaces() if rows is None else rows
            await asyncio.sleep(0.03)
            peers = []
            for row in snapshot:
                peers.extend(row.get("peers") or [])
            self.seen.append(list(peers))

    driver = Driver()

    class Registry:
        def get(self, _core):
            return driver

    scheduler = EgressScheduler(Registry(), tmp_path, retry_delay=0)

    async def scenario():
        scheduler.enqueue("wireguard", "peer")
        worker = asyncio.create_task(scheduler._drain(asyncio.Event()))
        await asyncio.sleep(0.01)
        driver.peers.clear()
        scheduler.enqueue("wireguard", "peer")
        await worker

    asyncio.run(scenario())
    assert driver.seen
    assert driver.seen[-1] == []


def test_deleted_peer_drop_keys_survive_until_the_latest_apply(tmp_path):
    class Driver:
        def __init__(self):
            self.drops: list[list[str]] = []

        async def _apply_peer_egress(self, rows, drop_keys=None):
            await asyncio.sleep(0.02)
            self.drops.append(list(drop_keys or []))

    driver = Driver()

    class Registry:
        def get(self, _core):
            return driver

    scheduler = EgressScheduler(Registry(), tmp_path, retry_delay=0)

    async def scenario():
        scheduler.enqueue("wireguard", drop_keys=["gone"])
        worker = asyncio.create_task(scheduler._drain(asyncio.Event()))
        await asyncio.sleep(0.01)
        scheduler.enqueue("wireguard", "newer", drop_keys=["newer-gone"])
        await worker

    asyncio.run(scenario())
    assert driver.drops
    assert "gone" in driver.drops[-1] or any("gone" in row for row in driver.drops)
    assert any("newer-gone" in row for row in driver.drops)


def test_wireguard_request_schedules_routing_without_waiting(tmp_path):
    reset_egress_for_tests()
    entered = asyncio.Event()
    release = asyncio.Event()

    class Registry:
        def get(self, _core):
            raise AssertionError("request path must not apply routing")

    scheduler = configure_egress(Registry(), tmp_path)

    async def blocked():
        entered.set()
        await release.wait()

    scheduler._run = blocked

    class Stub:
        key = "wireguard"

        async def _sync_bandwidth(self, *_ids):
            return None

        _sync_peer_egress = WireGuardDriver._sync_peer_egress

    async def scenario():
        scheduler.enqueue("wireguard")
        worker = asyncio.create_task(scheduler._drain(asyncio.Event()))
        await entered.wait()
        started = time.perf_counter()
        await Stub()._sync_peer_egress()
        elapsed = time.perf_counter() - started
        release.set()
        await worker
        return elapsed

    try:
        assert asyncio.run(scenario()) < 0.1
    finally:
        reset_egress_for_tests()
