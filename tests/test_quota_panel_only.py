import pytest

from agent.config import AgentSettings
from agent.support.quota import (
    configure_quota_settings,
    enforce_driver_quotas,
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


def test_volume_cutoff_defaults_to_the_panel():
    assert AgentSettings.model_fields["enforce_local_volume_quota"].default is False


class _WireGuard:
    key = "wireguard"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def sync_peer_stats(self) -> None:
        self.calls.append("sync_peer_stats")

    async def usage_snapshot(self):
        raise AssertionError("panel-owned quota must not read live counters")

    async def list_interfaces(self):
        raise AssertionError("panel-owned quota must not walk interfaces")

    async def batch_peers(self, interface_id, peers=None, *, mode="update"):
        raise AssertionError("panel-owned quota must not disable peers")


@pytest.mark.asyncio
async def test_wireguard_enforcer_does_not_disable_when_panel_owns_quota():
    configure_quota_settings(AgentSettings(enforce_local_volume_quota=False))
    driver = _WireGuard()

    assert await enforce_driver_quotas(driver) == 0
    assert driver.calls == []
