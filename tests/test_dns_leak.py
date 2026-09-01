from __future__ import annotations

import json
from types import SimpleNamespace

from agent.dns_leak import (
    NFT_TABLE,
    apply_script_path,
    discover_vpn_interfaces,
    dns_leak_apply,
    dns_leak_remove,
    dns_leak_status,
    ensure_vpn_dns_resolver,
    render_apply_script,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_discover_vpn_interfaces_filters_wireguard(monkeypatch):
    payload = [
        {
            'ifname': 'wg-de',
            'operstate': 'UP',
            'flags': ['UP'],
            'addr_info': [
                {'family': 'inet', 'local': '10.66.0.1', 'prefixlen': 24},
            ],
            'link_type': 'wireguard',
        },
        {
            'ifname': 'eth1',
            'operstate': 'UP',
            'flags': ['UP'],
            'addr_info': [
                {'family': 'inet', 'local': '203.0.113.8', 'prefixlen': 24},
            ],
            'link_type': 'ether',
        },
    ]

    def fake_run(args, **kwargs):
        assert args[:3] == ['ip', '-j', 'addr']
        return _Result(stdout=json.dumps(payload))

    monkeypatch.setattr('agent.support.host_interfaces.shutil.which', lambda cmd: '/sbin/ip' if cmd == 'ip' else None)
    rows = discover_vpn_interfaces(runner=fake_run)
    assert len(rows) == 1
    assert rows[0]['name'] == 'wg-de'
    assert rows[0]['gateway'] == '10.66.0.1'


def test_render_apply_script_contains_redirect_rules(monkeypatch):
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    script = render_apply_script(
        [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
    )
    assert 'wg0' in script
    assert '10.80.0.1:53' in script
    assert 'resolvectl dns "wg0" off' in script
    assert NFT_TABLE in script
    assert 'no-v6' not in script


def test_render_apply_script_can_block_ipv6(monkeypatch):
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    script = render_apply_script(
        [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
        block_ipv6=True,
    )
    assert 'no-v6' in script


def test_ensure_vpn_dns_resolver_configures_dnsmasq_and_dnat(tmp_path, monkeypatch):
    data_dir = tmp_path / 'data'
    monkeypatch.setenv('DATA_DIR', str(data_dir))
    monkeypatch.setattr('agent.dns_leak._require_linux', lambda: None)
    monkeypatch.setattr('agent.dns_leak._require_root', lambda: None)
    monkeypatch.setattr('agent.dns_leak._firewall_backend', lambda: 'nft')
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: '/usr/bin/' + cmd)

    def fake_run(args, **kwargs):
        return _Result()

    monkeypatch.setattr('agent.dns_leak.run', fake_run)
    monkeypatch.setattr('agent.dns_leak.ensure_dns_leak_unit', lambda script_path, runner=None: {'ok': True})
    monkeypatch.setattr('agent.dns_leak._ensure_dnsmasq', lambda interfaces, upstream=(): {'restarted': True})

    targets = [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}]
    result = ensure_vpn_dns_resolver(interfaces=targets, runner=fake_run, data_dir=data_dir)
    assert result['ok'] is True
    assert result['resolver']['restarted'] is True
    assert result['dnat'] is not None
    assert result['dnat']['applied'] is True
    assert apply_script_path(data_dir).is_file()


def test_dns_leak_apply_writes_script_and_runs(tmp_path, monkeypatch):
    data_dir = tmp_path / 'data'
    monkeypatch.setenv('DATA_DIR', str(data_dir))
    monkeypatch.setattr('agent.dns_leak._require_linux', lambda: None)
    monkeypatch.setattr('agent.dns_leak._require_root', lambda: None)
    monkeypatch.setattr('agent.dns_leak._firewall_backend', lambda: 'nft')
    monkeypatch.setattr(
        'agent.dns_leak._resolve_targets',
        lambda interfaces, runner=None: [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
    )

    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        return _Result()

    monkeypatch.setattr('agent.dns_leak.run', fake_run)
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: '/usr/bin/' + cmd)
    monkeypatch.setattr('agent.dns_leak.ensure_dns_leak_unit', lambda script_path, runner=None: {'ok': True})
    monkeypatch.setattr('agent.dns_leak._ensure_dnsmasq', lambda interfaces, upstream=(): {'installed': True})

    result = dns_leak_apply(with_dnsmasq=True, runner=fake_run)
    assert result['applied'] is True
    assert apply_script_path(data_dir).is_file()
    assert result['backend'] == 'nft'


def test_dns_leak_status_reports_table(monkeypatch):
    monkeypatch.setattr('agent.dns_leak._require_linux', lambda: None)
    monkeypatch.setattr('agent.dns_leak.discover_vpn_interfaces', lambda runner=None: [])
    monkeypatch.setattr('agent.dns_leak._nft_table_exists', lambda runner=None: True)
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: '/usr/bin/systemctl' if cmd == 'systemctl' else '/usr/sbin/nft')

    def fake_run(args, **kwargs):
        if args[:3] == ['systemctl', 'is-active']:
            return _Result(stdout='active\n')
        return _Result()

    monkeypatch.setattr('agent.dns_leak.run', fake_run)
    payload = dns_leak_status(runner=fake_run)
    assert payload['active'] is True
    assert payload['nft_table'] == NFT_TABLE


def test_dns_leak_remove_cleans_files(tmp_path, monkeypatch):
    script = apply_script_path(tmp_path)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text('#!/bin/sh\n', encoding='utf-8')
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    monkeypatch.setattr('agent.dns_leak._require_linux', lambda: None)
    monkeypatch.setattr('agent.dns_leak._require_root', lambda: None)
    monkeypatch.setattr('agent.dns_leak.UNIT_PATH', tmp_path / 'agent-dns-leak.service')
    monkeypatch.setattr('agent.dns_leak.DNSMASQ_DROPIN', tmp_path / 'dnsmasq.conf')
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: '/usr/bin/' + cmd)

    def fake_run(args, **kwargs):
        return _Result()

    monkeypatch.setattr('agent.dns_leak.run', fake_run)
    result = dns_leak_remove(runner=fake_run)
    assert result['removed'] is True
    assert not script.exists()


def test_cli_bbr_and_dns_leak_subcommands(capsys, monkeypatch):
    from agent.cli import main

    monkeypatch.setattr('agent.bbr.bbr_status', lambda: {'supported': True, 'enabled': False})
    assert main(['bbr', 'status']) == 0
    out = capsys.readouterr().out
    assert '"supported": true' in out

    monkeypatch.setattr(
        'agent.dns_leak.dns_leak_status',
        lambda: {'active': False, 'interfaces': []},
    )
    assert main(['dns-leak', 'status']) == 0
    out = capsys.readouterr().out
    assert '"active": false' in out

    monkeypatch.setattr(
        'agent.ads_block.ads_block_status',
        lambda runner=None: {'enabled': True, 'dns': '10.80.0.1', 'ready': True},
    )
    assert main(['ads-block', 'status']) == 0
    out = capsys.readouterr().out
    assert '"enabled": true' in out
