from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agent.ads_block import (
    ads_block_ensure,
    ads_block_prerequisites,
    ads_block_status,
    ads_block_test,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_ads_block_status_reports_gateway_dns(monkeypatch):
    monkeypatch.setattr(
        'agent.ads_block.discover_vpn_interfaces',
        lambda runner=None: [{'name': 'wg0', 'gateway': '10.66.0.1', 'addresses': ['10.66.0.1/24']}],
    )
    monkeypatch.setattr(
        'agent.ads_block.ads_block_prerequisites',
        lambda runner=None: {
            'linux': True,
            'root': True,
            'adguard_installed': True,
            'adguard_active': True,
            'adguard_configured': True,
            'ads_enabled': False,
            'firewall_backend': 'nft',
            'vpn_interface_count': 1,
            'ready': True,
        },
    )
    monkeypatch.setattr('agent.ads_block.ADS_ENABLED_MARKER', Path('/tmp/netinja-ads-block-enabled'))

    payload = ads_block_status()
    assert payload['dns'] == '10.66.0.1'
    assert payload['listen_dns'] == '10.66.0.1'
    assert payload['ready'] is True


def test_ads_block_prerequisites_ready_when_adguard_firewall_and_vpn(monkeypatch):
    monkeypatch.setattr(
        'agent.ads_block.discover_vpn_interfaces',
        lambda runner=None: [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
    )
    monkeypatch.setattr('agent.ads_block.dns_leak_status', lambda runner=None: {'active': True})
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    monkeypatch.setattr('agent.ads_block.adguard_service_active', lambda runner=None: True)
    monkeypatch.setattr('agent.ads_block.sys.platform', 'linux')

    payload = ads_block_prerequisites()
    assert payload['ready'] is True
    assert payload['firewall_backend'] == 'nft'


def test_ads_block_test_detects_blocked_answer(monkeypatch):
    monkeypatch.setattr(
        'agent.ads_block.ads_block_status',
        lambda runner=None: {'dns': '10.80.0.1'},
    )
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: '/usr/bin/dig' if cmd == 'dig' else None)
    monkeypatch.setattr('agent.ads_block._require_linux', lambda: None)

    def fake_run(args, **kwargs):
        return _Result(stdout='0.0.0.0\n')

    monkeypatch.setattr('agent.ads_block.run', fake_run)

    payload = ads_block_test('doubleclick.net')
    assert payload['blocked'] is True
    assert payload['answer'] == '0.0.0.0'


def test_ads_block_ensure_writes_marker_and_configures_resolver(tmp_path, monkeypatch):
    marker = tmp_path / 'ads-block-enabled'
    list_path = tmp_path / 'ads-blocklist.txt'
    monkeypatch.setattr('agent.ads_block.ADS_ENABLED_MARKER', marker)
    monkeypatch.setattr('agent.ads_block.ADS_LIST_PATH', list_path)
    monkeypatch.setattr('agent.ads_block._require_linux', lambda: None)
    monkeypatch.setattr('agent.ads_block._require_root', lambda: None)
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    monkeypatch.setattr('agent.adguard.install_adguard_binary', lambda runner=None: True)
    monkeypatch.setattr(
        'agent.ads_block.discover_vpn_interfaces',
        lambda runner=None: [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
    )

    resolver_calls: list[dict] = []

    def fake_resolver(**kwargs):
        resolver_calls.append(kwargs)
        return {
            'ok': True,
            'resolver': {'restarted': True, 'listen_addresses': ['10.80.0.1']},
            'dnat': {'applied': True},
        }

    monkeypatch.setattr('agent.ads_block.ensure_vpn_dns_resolver', fake_resolver)
    monkeypatch.setattr(
        'agent.ads_block.ensure_adguard_service',
        lambda runner=None: {'active': True},
    )

    def fake_run(args, **kwargs):
        return _Result()

    payload = ads_block_ensure(runner=fake_run)

    assert marker.is_file()
    assert resolver_calls
    assert resolver_calls[0].get('block_ipv6') is False
    assert resolver_calls[0].get('filtering_enabled') is True
    assert payload['dns'] == '10.80.0.1'
    assert payload['resolver']['resolver']['listen_addresses'] == ['10.80.0.1']
