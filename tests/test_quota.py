from agent.support.quota import (
    has_volume_quota,
    quota_exceeded,
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
