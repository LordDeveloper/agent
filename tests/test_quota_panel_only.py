from agent.config import AgentSettings
from agent.support.quota import (
    configure_quota_settings,
    has_volume_quota,
    quota_exceeded,
)


def _client_with_quota(remaining: int) -> dict:
    return {
        "volume": remaining,
        "_incoming": 0,
        "_outgoing": 0,
        "is_enabled": True,
    }


def test_has_volume_quota_honours_positive_volume_when_enforced():
    configure_quota_settings(AgentSettings(enforce_local_volume_quota=True))
    client = _client_with_quota(20 * 1024**3)

    assert has_volume_quota(client) is True
    assert quota_exceeded(client, 25 * 1024**3, 0) is True


def test_panel_only_mode_keeps_volume_field_but_skips_enforcement():
    configure_quota_settings(AgentSettings(enforce_local_volume_quota=False))
    client = _client_with_quota(20 * 1024**3)

    assert client["volume"] == 20 * 1024**3
    assert has_volume_quota(client) is False
    assert quota_exceeded(client, 100 * 1024**3, 0) is False
