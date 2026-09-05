from agent.support.quota import (
    has_volume_quota,
    quota_exceeded,
    seed_stale_zero_baseline,
)


def test_unlimited_client_without_volume_field_is_not_enforced():
    client = {"is_enabled": True, "incoming": 999, "outgoing": 999}

    assert has_volume_quota(client) is False
    assert quota_exceeded(client, 10_000_000_000, 10_000_000_000) is False


def test_zero_remaining_disables_immediately():
    client = {
        "is_enabled": True,
        "volume": 0,
        "_incoming": 1_000,
        "_outgoing": 0,
    }

    assert quota_exceeded(client, 1_000, 0) is True


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
