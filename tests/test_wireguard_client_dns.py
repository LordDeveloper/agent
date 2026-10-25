import asyncio
from pathlib import Path

from agent.drivers.wireguard import WireGuardDriver


class _DummyDriver(WireGuardDriver):
    def __init__(self):
        self.key = "wireguard"


def test_client_dns_is_public_when_ads_block_is_off(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.adguard.ADS_ENABLED_MARKER", tmp_path / "missing")
    driver = _DummyDriver()
    assert asyncio.run(driver._client_dns({"interface_address": "10.80.0.1"})) == "1.1.1.1"


def test_client_dns_uses_interface_gateway_when_ads_block_is_on(tmp_path, monkeypatch):
    marker = tmp_path / "ads-block-enabled"
    marker.write_text("enabled\n", encoding="utf-8")
    monkeypatch.setattr("agent.adguard.ADS_ENABLED_MARKER", marker)
    driver = _DummyDriver()
    assert asyncio.run(driver._client_dns({"interface_address": "10.80.0.1", "subnet": "10.80.0.0/24"})) == "10.80.0.1"
