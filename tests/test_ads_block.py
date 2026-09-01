from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agent.ads_block import (
    ADS_DROPIN,
    ads_block_ensure,
    ads_block_prerequisites,
    ads_block_status,
    ads_block_test,
    parse_hosts_blocklist,
    refresh_ads_hosts_file,
    render_dnsmasq_ads_conf,
    write_ads_hosts_file,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_render_dnsmasq_ads_conf_blocks_suffix_domains(tmp_path):
    hosts_file = tmp_path / 'hosts'
    hosts_file.write_text('0.0.0.0 ads.example.net\n', encoding='utf-8')
    conf = render_dnsmasq_ads_conf(['doubleclick.net', 'ads.example.com'], hosts_file=hosts_file)
    assert f'addn-hosts={hosts_file}' in conf
    assert 'address=/doubleclick.net/0.0.0.0' in conf
    assert 'address=/ads.example.com/0.0.0.0' in conf


def test_parse_hosts_blocklist_skips_comments_and_localhost():
    text = '\n'.join(
        [
            '# comment',
            '0.0.0.0 doubleclick.net',
            '127.0.0.1 localhost',
            '0.0.0.0 tracker.example.com ads.example.com',
        ]
    )
    hosts = parse_hosts_blocklist(text)
    assert hosts == ['doubleclick.net', 'tracker.example.com', 'ads.example.com']


def test_refresh_ads_hosts_file_uses_cache(tmp_path, monkeypatch):
    hosts_path = tmp_path / 'ads-block-hosts'
    monkeypatch.setattr('agent.ads_block.ADS_HOSTS_PATH', hosts_path)
    write_ads_hosts_file(['cached.example'], path=hosts_path)
    payload = refresh_ads_hosts_file()
    assert payload['ok'] is True
    assert payload['refreshed'] is False
    assert payload['hosts'] == 1
    assert payload['source'] == 'cache'


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
            'dnsmasq_installed': True,
            'dnsmasq_active': True,
            'dnsmasq_dropin': True,
            'ads_dropin': False,
            'firewall_backend': 'nft',
            'vpn_interface_count': 1,
            'ready': True,
        },
    )
    monkeypatch.setattr('agent.ads_block.ADS_DROPIN', Path('/tmp/netinja-ads-block.conf'))
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: '/usr/sbin/dnsmasq' if cmd == 'dnsmasq' else None)

    payload = ads_block_status()
    assert payload['dns'] == '10.66.0.1'
    assert payload['listen_dns'] == '10.66.0.1'
    assert payload['ready'] is True


def test_ads_block_prerequisites_ready_when_dnsmasq_firewall_and_vpn(monkeypatch):
    monkeypatch.setattr(
        'agent.ads_block.discover_vpn_interfaces',
        lambda runner=None: [{'name': 'wg0', 'gateway': '10.80.0.1', 'addresses': ['10.80.0.1/24']}],
    )
    monkeypatch.setattr('agent.ads_block.dns_leak_status', lambda runner=None: {'active': True})
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    monkeypatch.setattr('agent.ads_block.dnsmasq_service_active', lambda runner=None: True)
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

    from agent.ads_block import ads_block_test

    payload = ads_block_test('doubleclick.net')
    assert payload['blocked'] is True
    assert payload['answer'] == '0.0.0.0'


def test_ads_block_ensure_writes_dropin_and_configures_resolver(tmp_path, monkeypatch):
    dropin = tmp_path / 'netinja-ads-block.conf'
    list_path = tmp_path / 'ads-blocklist.txt'
    monkeypatch.setattr('agent.ads_block.ADS_DROPIN', dropin)
    monkeypatch.setattr('agent.ads_block.ADS_LIST_PATH', list_path)
    monkeypatch.setattr('agent.ads_block._require_linux', lambda: None)
    monkeypatch.setattr('agent.ads_block._require_root', lambda: None)
    monkeypatch.setattr('agent.ads_block.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
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
        'agent.ads_block.refresh_ads_hosts_file',
        lambda **kwargs: {'ok': True, 'refreshed': False, 'hosts': 2, 'path': str(list_path), 'source': 'test'},
    )

    def fake_run(args, **kwargs):
        return _Result()

    payload = ads_block_ensure(runner=fake_run)

    assert dropin.is_file()
    assert 'address=/doubleclick.net/0.0.0.0' in dropin.read_text(encoding='utf-8')
    assert resolver_calls
    assert resolver_calls[0].get('block_ipv6') is False
    assert payload['dns'] == '10.80.0.1'
    assert payload['resolver']['resolver']['listen_addresses'] == ['10.80.0.1']
