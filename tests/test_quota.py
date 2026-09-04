from agent.support.quota import has_volume_quota, quota_exceeded


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
