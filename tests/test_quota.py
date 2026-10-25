import asyncio
import logging
import warnings

from agent.quota_enforcer import enforce_all
from agent.support.quota import (
    apply_quota_meta,
    enforce_driver_quotas,
    has_volume_quota,
    quota_exceeded,
    quota_meta_from_client,
    reseed_baseline_if_stale,
    seed_ahead_baseline,
    seed_stale_zero_baseline,
)


def test_unlimited_client_without_volume_field_is_not_enforced():
    client = {"is_enabled": True, "incoming": 999, "outgoing": 999}

    assert has_volume_quota(client) is False
    assert quota_exceeded(client, 10_000_000_000, 10_000_000_000) is False


def test_zero_volume_means_unlimited_not_enforced():
    client = {
        "is_enabled": True,
        "volume": 0,
        "_incoming": 1_000,
        "_outgoing": 0,
    }

    assert has_volume_quota(client) is False
    assert quota_exceeded(client, 1_000, 0) is False


def test_zero_remaining_disables_immediately():
    client = {
        "is_enabled": True,
        "volume": 1,
        "_incoming": 1_000,
        "_outgoing": 0,
    }

    assert quota_exceeded(client, 1_001, 0) is True


def test_delta_below_remaining_is_allowed():
    client = {
        "is_enabled": True,
        "volume": 1_000_000,
        "_incoming": 5_000_000,
        "_outgoing": 0,
    }

    assert quota_exceeded(client, 5_400_000, 0) is False


def test_delta_at_remaining_is_exceeded():
    client = {
        "is_enabled": True,
        "volume": 500_000,
        "_incoming": 5_000_000,
        "_outgoing": 0,
    }

    assert quota_exceeded(client, 5_500_000, 0) is True


def test_seed_stale_zero_baseline_aligns_cumulative_counters():
    client = {
        "is_enabled": False,
        "disabled_reason": "quota_exceeded",
        "volume": 20_000_000_000,
        "_incoming": 0,
        "_outgoing": 0,
        "incoming": 19_762_603_472,
        "outgoing": 1_715_621_664,
    }

    assert seed_stale_zero_baseline(client) is True
    assert client["_incoming"] == 19_762_603_472
    assert client["_outgoing"] == 1_715_621_664
    assert "disabled_reason" not in client
    assert quota_exceeded(client, 19_762_603_472, 1_715_621_664) is False


def test_seed_stale_zero_baseline_skips_when_baseline_already_set():
    client = {
        "_incoming": 100,
        "_outgoing": 0,
        "incoming": 500,
        "outgoing": 0,
    }

    assert seed_stale_zero_baseline(client) is False
    assert client["_incoming"] == 100


def test_baseline_ahead_of_live_does_not_trigger_quota_exceeded():
    client = {
        "is_enabled": True,
        "volume": 20_000_000_000,
        "_incoming": 29_024_362_008,
        "_outgoing": 5_595_810_232,
    }

    live_in = 29_003_014_804
    live_out = 5_590_366_664

    assert quota_exceeded(client, live_in, live_out) is False


def test_seed_ahead_baseline_aligns_stale_shadow_counters():
    client = {
        "is_enabled": False,
        "disabled_reason": "quota_exceeded",
        "volume": 19_091_014_172,
        "_incoming": 29_024_362_008,
        "_outgoing": 5_595_810_232,
        "incoming": 29_003_014_804,
        "outgoing": 5_590_366_664,
    }

    live_in = 29_003_014_804
    live_out = 5_590_366_664

    assert seed_ahead_baseline(client, live_in, live_out) is True
    assert client["_incoming"] == live_in
    assert client["_outgoing"] == live_out
    assert "disabled_reason" not in client
    assert quota_exceeded(client, live_in, live_out) is False


def test_reseed_baseline_if_stale_heals_disabled_peer_for_enforcer():
    client = {
        "is_enabled": False,
        "disabled_reason": "quota_exceeded",
        "volume": 19_091_014_172,
        "_incoming": 29_024_362_008,
        "_outgoing": 5_595_810_232,
        "incoming": 29_003_014_804,
        "outgoing": 5_590_366_664,
    }

    live_in = 29_003_014_804
    live_out = 5_590_366_664

    assert reseed_baseline_if_stale(client, live_in, live_out) is True
    assert quota_exceeded(client, live_in, live_out) is False


def test_seed_stale_zero_baseline_heals_legacy_raw_kernel_baseline():
    client = {
        "is_enabled": True,
        "volume": 20_000_000_000,
        "_incoming": 4204,
        "_outgoing": 1764,
        "incoming": 66_505_328_660,
        "outgoing": 5_403_803_980,
    }

    assert seed_stale_zero_baseline(client) is True
    assert client["_incoming"] == 66_505_328_660
    assert client["_outgoing"] == 5_403_803_980
    assert quota_exceeded(client, 66_505_328_660, 5_403_803_980) is False


def test_quota_meta_round_trip_restores_volume_stripped_by_xray():
    synced = {
        "id": "node-1",
        "email": "user@example",
        "volume": 50 * 1024**3,
        "_incoming": 1000,
        "_outgoing": 2000,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "max_connection": 3,
        "is_enabled": True,
    }
    meta = quota_meta_from_client(synced)
    stored = {"id": "node-1", "email": "user@example", "is_enabled": True}
    apply_quota_meta(stored, meta, include_flags=True)

    assert stored["volume"] == 50 * 1024**3
    assert stored["_incoming"] == 1000
    assert stored["_outgoing"] == 2000
    assert stored["expires_at"].startswith("2030-01-01")
    assert stored["max_connection"] == 3
    assert has_volume_quota(stored) is True


def test_quota_meta_clears_volume_for_unlimited():
    client = {"id": "node-1", "email": "user@example", "volume": 1024, "is_enabled": True}
    meta = quota_meta_from_client({"id": "node-1", "email": "user@example", "is_enabled": True})
    apply_quota_meta(client, meta, include_flags=False)

    assert "volume" not in client
    assert has_volume_quota(client) is False


class _UsageClient:
    def __init__(self, email: str, incoming: int, outgoing: int, client_id: str = ""):
        self.email = email
        self.id = client_id
        self.incoming = incoming
        self.outgoing = outgoing


class _UsageInbound:
    def __init__(self, clients: list[_UsageClient]):
        self.clients = clients


class _UsageSnapshot:
    def __init__(self, inbounds: list[_UsageInbound]):
        self.inbounds = inbounds


class _LiveXray:
    key = "xray"

    def __init__(self, clients: list[dict], disabled: list[dict] | None = None):
        self.clients = clients
        self.disabled = disabled or []
        self.batches: list[list[dict]] = []

    def running(self) -> bool:
        return True

    def usage_snapshot(self) -> _UsageSnapshot:
        rows = [
            _UsageClient(
                str(client.get("email") or ""),
                int(client.get("_incoming") or 0),
                int(client.get("_outgoing") or 0),
                str(client.get("id") or ""),
            )
            for client in self.clients
        ]
        return _UsageSnapshot([_UsageInbound(rows)])

    def list_inbounds(self) -> list[dict]:
        return [{"id": 1, "settings": {"clients": self.clients}}]

    def _clients_of(self, inbound: dict) -> list[dict]:
        return list(inbound["settings"]["clients"])

    def _disabled_docs(self) -> list[dict]:
        return self.disabled

    def batch_clients(self, inbound_id, clients=None, *, mode="update"):
        self.batches.append(list(clients or []))
        return {"ok": True, "succeeded": len(clients or [])}


def test_enforcer_cuts_client_left_live_after_panel_disable():
    """Panel already stored quota_exceeded, but Xray ignored enable=false."""
    driver = _LiveXray(
        clients=[{
            "id": "node-1",
            "email": "spent@x",
            "is_enabled": True,
            "volume": 1,
            "_incoming": 500,
            "_outgoing": 500,
        }],
        disabled=[{
            "id": "node-1",
            "email": "spent@x",
            "is_enabled": False,
            "disabled_reason": "quota_exceeded",
        }],
    )

    assert asyncio.run(enforce_driver_quotas(driver)) == 1
    assert driver.batches[0][0]["is_enabled"] is False
    assert driver.batches[0][0]["disabled_reason"] == "quota_exceeded"


def test_enforcer_reuses_cached_snapshot_instead_of_dumping_again():
    driver = _LiveXray(
        clients=[{
            "id": "node-1",
            "email": "ok@x",
            "is_enabled": True,
            "volume": 1_000_000,
            "_incoming": 10,
            "_outgoing": 0,
        }],
    )
    cached = driver.usage_snapshot()

    def fail_dump():
        raise AssertionError("quota must not start a second full stats dump")

    driver.cached_usage_snapshot = lambda: cached
    driver.usage_snapshot = fail_dump

    assert asyncio.run(enforce_driver_quotas(driver)) == 0
    assert driver.batches == []


def test_enforcer_leaves_a_client_with_remaining_quota():
    driver = _LiveXray(
        clients=[{
            "id": "node-2",
            "email": "ok@x",
            "is_enabled": True,
            "volume": 10_000,
            "_incoming": 100,
            "_outgoing": 100,
        }],
    )

    assert asyncio.run(enforce_driver_quotas(driver)) == 0
    assert driver.batches == []


class _AsyncDisabledXray(_LiveXray):
    """Real Xray methods are async. A sync call iterates the coroutine."""

    async def running(self) -> bool:
        return True

    async def usage_snapshot(self) -> _UsageSnapshot:
        return super().usage_snapshot()

    async def list_inbounds(self) -> list[dict]:
        return super().list_inbounds()

    async def _disabled_docs(self) -> list[dict]:
        return super()._disabled_docs()

    async def batch_clients(self, inbound_id, clients=None, *, mode="update"):
        return super().batch_clients(inbound_id, clients=clients, mode=mode)


def test_xray_enforcer_awaits_async_disabled_docs():
    driver = _AsyncDisabledXray(
        clients=[{
            "id": "node-1",
            "email": "spent@x",
            "is_enabled": True,
            "volume": 1,
            "_incoming": 500,
            "_outgoing": 500,
        }],
        disabled=[{
            "id": "node-1",
            "email": "spent@x",
            "is_enabled": False,
            "disabled_reason": "quota_exceeded",
        }],
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        assert asyncio.run(enforce_driver_quotas(driver)) == 1

    assert not any("never awaited" in str(item.message) for item in caught)
    assert driver.batches[0][0]["is_enabled"] is False
    assert driver.batches[0][0]["disabled_reason"] == "quota_exceeded"


class _AsyncTunnel:
    def __init__(self, key: str, interfaces: list[dict], live: dict[str, tuple[int, int]]):
        self.key = key
        self.interfaces = interfaces
        self.live = live
        self.calls: list[str] = []
        self.batches: list[tuple] = []
        self.release = asyncio.Event()

    async def sync_peer_stats(self) -> None:
        self.calls.append("sync_peer_stats")

    async def usage_snapshot(self) -> _UsageSnapshot:
        self.calls.append("usage_snapshot")
        rows = []
        for iface in self.interfaces:
            for peer in iface.get("peers") or []:
                email = str(peer.get("email") or "")
                incoming, outgoing = self.live.get(email, (0, 0))
                rows.append(_UsageClient(email, incoming, outgoing, str(peer.get("id") or "")))
        return _UsageSnapshot([_UsageInbound(rows)])

    async def list_interfaces(self) -> list[dict]:
        self.calls.append("list_interfaces")
        return self.interfaces

    async def batch_peers(self, interface_id, peers=None, *, mode="update"):
        self.calls.append(f"batch_peers:{interface_id}")
        self.batches.append((interface_id, list(peers or []), mode))
        if len(self.batches) == 1 and len(self.interfaces) > 1:
            await self.release.wait()
        else:
            self.release.set()
        return {"ok": True, "succeeded": len(peers or [])}


def _tunnel_interfaces() -> tuple[list[dict], dict[str, tuple[int, int]]]:
    interfaces = [
        {
            "id": "wg0",
            "peers": [
                {
                    "id": "spent",
                    "email": "spent@wg",
                    "is_enabled": True,
                    "volume": 1_000,
                    "_incoming": 100,
                    "_outgoing": 0,
                },
                {
                    "id": "ok",
                    "email": "ok@wg",
                    "is_enabled": True,
                    "volume": 5_000,
                    "_incoming": 100,
                    "_outgoing": 0,
                },
            ],
        },
        {
            "id": "wg1",
            "peers": [{
                "id": "spent-2",
                "email": "spent2@wg",
                "is_enabled": True,
                "volume": 500,
                "_incoming": 0,
                "_outgoing": 0,
            }],
        },
    ]
    live = {
        "spent@wg": (1_100, 0),
        "ok@wg": (200, 0),
        "spent2@wg": (500, 0),
    }
    return interfaces, live


def _assert_tunnel_quota(driver: _AsyncTunnel) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        count = asyncio.run(asyncio.wait_for(enforce_driver_quotas(driver), timeout=2))

    assert not any("never awaited" in str(item.message) for item in caught)
    assert count == 2
    assert driver.calls[:3] == ["sync_peer_stats", "usage_snapshot", "list_interfaces"]
    by_iface = {iface_id: peers for iface_id, peers, _mode in driver.batches}
    assert set(by_iface) == {"wg0", "wg1"}
    disabled = by_iface["wg0"][0]
    assert disabled["email"] == "spent@wg"
    assert disabled["is_enabled"] is False
    assert disabled["disabled_reason"] == "quota_exceeded"
    assert disabled["disabled_detail"]["remaining_bytes"] == 1_000
    assert disabled["disabled_detail"]["delta_bytes"] == 1_000
    assert disabled["disabled_detail"]["live_incoming"] == 1_100
    assert disabled["disabled_detail"]["baseline_incoming"] == 100
    assert all(peer["email"] != "ok@wg" for peer in by_iface["wg0"])
    assert by_iface["wg1"][0]["email"] == "spent2@wg"
    assert by_iface["wg1"][0]["disabled_detail"]["delta_bytes"] == 500


def test_wireguard_enforcer_awaits_async_list_interfaces():
    interfaces, live = _tunnel_interfaces()
    _assert_tunnel_quota(_AsyncTunnel("wireguard", interfaces, live))


def test_amnezia_enforcer_awaits_async_list_interfaces():
    interfaces, live = _tunnel_interfaces()
    _assert_tunnel_quota(_AsyncTunnel("amnezia", interfaces, live))


class _AsyncL2tp:
    key = "l2tp"

    def __init__(self):
        self.calls: list[str] = []
        self.batches: list[tuple] = []

    async def sync_user_stats(self) -> None:
        self.calls.append("sync_user_stats")

    async def usage_snapshot(self) -> _UsageSnapshot:
        self.calls.append("usage_snapshot")
        rows = [
            _UsageClient("spent@l2", 500, 0, "u1"),
            _UsageClient("companion@l2", 500, 0, "u2"),
        ]
        return _UsageSnapshot([_UsageInbound(rows)])

    async def list_servers(self) -> list[dict]:
        self.calls.append("list_servers")
        return [{
            "id": "l2tp-1",
            "users": [
                {
                    "id": "u1",
                    "email": "spent@l2",
                    "is_enabled": True,
                    "volume": 100,
                    "_incoming": 0,
                    "_outgoing": 0,
                },
                {
                    "id": "u2",
                    "email": "companion@l2",
                    "is_enabled": True,
                    "volume": 100,
                    "_incoming": 0,
                    "_outgoing": 0,
                    "linked_peer_id": "peer-1",
                },
            ],
        }]

    async def batch_users(self, server_id, users=None, *, mode="update"):
        self.calls.append("batch_users")
        self.batches.append((server_id, list(users or []), mode))
        return {"ok": True}


def test_l2tp_enforcer_awaits_async_list_servers():
    driver = _AsyncL2tp()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        assert asyncio.run(enforce_driver_quotas(driver)) == 1

    assert not any("never awaited" in str(item.message) for item in caught)
    assert driver.calls == ["sync_user_stats", "usage_snapshot", "list_servers", "batch_users"]
    _server_id, users, mode = driver.batches[0]
    assert mode == "update"
    assert [user["email"] for user in users] == ["spent@l2"]
    assert users[0]["disabled_reason"] == "quota_exceeded"
    assert users[0]["disabled_detail"]["delta_bytes"] == 500


class _Cores:
    def __init__(self, keys: list[str]):
        self._keys = keys

    def cores(self) -> list[str]:
        return list(self._keys)


class _Registry:
    def __init__(self, drivers: dict):
        self.settings = _Cores(list(drivers))
        self._drivers = drivers

    def get(self, key: str):
        return self._drivers[key]


def test_one_driver_failure_is_logged_and_does_not_block_the_other(caplog):
    interfaces, live = _tunnel_interfaces()
    amnezia = _AsyncTunnel("amnezia", interfaces, live)

    class _BrokenWireGuard(_AsyncTunnel):
        async def list_interfaces(self) -> list[dict]:
            self.calls.append("list_interfaces")
            raise RuntimeError("store locked")

    wireguard = _BrokenWireGuard("wireguard", interfaces, live)
    registry = _Registry({"wireguard": wireguard, "amnezia": amnezia})

    with caplog.at_level(logging.ERROR, logger="agent.quota"):
        count = asyncio.run(asyncio.wait_for(enforce_all(registry), timeout=2))

    assert count == 2
    assert "quota enforce failed core=wireguard" in caplog.text
    assert "store locked" in caplog.text
    assert {iface_id for iface_id, _peers, _mode in amnezia.batches} == {"wg0", "wg1"}
