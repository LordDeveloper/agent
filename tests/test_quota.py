import asyncio

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
