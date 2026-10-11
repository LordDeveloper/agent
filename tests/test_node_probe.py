import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from agent.support import node_probe
from agent.support.node_probe import PROBE_TARGETS, _curl_probe


def test_probe_targets_prefer_literal_ip():
    assert PROBE_TARGETS[0][0].startswith('http://1.1.1.1')
    assert PROBE_TARGETS[1][0].startswith('http://1.0.0.1')
    assert len(PROBE_TARGETS) >= 4
    assert len(node_probe.PROBE_URLS) >= 8


def test_rotated_probe_targets_shifts_start():
    rotated = node_probe._rotated_probe_targets(1)
    assert rotated[0][0] == PROBE_TARGETS[1][0]
    assert rotated[-1][0] == PROBE_TARGETS[0][0]


def test_curl_probe_accepts_http_301(monkeypatch):
    def runner(args, **_kwargs):
        row = list(args)
        if row and row[0] == 'ip':
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        return SimpleNamespace(returncode=0, stdout='301 0.055', stderr='')

    monkeypatch.setattr(node_probe.shutil, 'which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(node_probe, '_resolve_ipv4_hosts', lambda hosts: ['1.1.1.1'])
    ok, message, latency = _curl_probe(interface='de', runner=runner)
    assert ok is True
    assert message == 'اتصال برقرار شد'
    assert latency == 55


def test_http_code_means_egress_includes_redirects():
    assert node_probe._http_code_means_egress(200)
    assert node_probe._http_code_means_egress(301)
    assert node_probe._http_code_means_egress(302)
    assert node_probe._http_code_means_egress(404)
    assert not node_probe._http_code_means_egress(0)


def test_curl_probe_continues_after_timeout(monkeypatch):
    calls: list[list[str]] = []

    def runner(args, **_kwargs):
        row = list(args)
        calls.append(row)
        if row and row[0] == 'ip':
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        url = row[-1] if row else ''
        if '1.1.1.1' in url:
            raise subprocess.TimeoutExpired(cmd=args, timeout=10)
        return SimpleNamespace(returncode=0, stdout='200 0.042', stderr='')

    monkeypatch.setattr(node_probe.shutil, 'which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(node_probe, '_resolve_ipv4_hosts', lambda hosts: ['1.1.1.1', '1.0.0.1', '8.8.8.8'])
    ok, message, latency = _curl_probe(interface='poland', runner=runner)
    assert ok is True
    assert message == 'اتصال برقرار شد'
    assert latency == 42
    curl_urls = [row[-1] for row in calls if row and row[0] == 'curl']
    assert any('1.1.1.1' in item for item in curl_urls)
    assert any('1.0.0.1' in item for item in curl_urls)
    assert any(row[:3] == ['ip', 'route', 'replace'] and 'poland' in row for row in calls)
    assert any(row[:3] == ['ip', 'route', 'del'] and 'poland' in row for row in calls)


def test_host_routes_skipped_for_ip_bind(monkeypatch):
    calls: list[list[str]] = []

    def runner(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout='200 0.01', stderr='')

    monkeypatch.setattr(node_probe.shutil, 'which', lambda name: f'/usr/bin/{name}')
    ok, _message, _latency = _curl_probe(interface='10.64.0.2', runner=runner)
    assert ok is True
    assert not any(row and row[0] == 'ip' for row in calls)


def test_is_mullvad_exit_skips_table_off(tmp_path, monkeypatch):
    from agent import dns_leak

    conf_dir = tmp_path / 'wireguard'
    conf_dir.mkdir()
    (conf_dir / 'poland.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.64.0.2/32\nTable = off\n',
        encoding='utf-8',
    )
    (conf_dir / 'pl.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.64.0.2/32\n\n'
        '[Peer]\nPublicKey=xyz\nEndpoint=1.2.3.4:51820\nAllowedIPs=0.0.0.0/0\n',
        encoding='utf-8',
    )
    (conf_dir / 'wg0.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.8.0.1/24\nListenPort=51820\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(dns_leak, '_wg_conf_dirs', lambda: [conf_dir])
    monkeypatch.setattr(dns_leak, '_mullvad_bound_ifaces', lambda *a, **k: {'sw'})

    assert dns_leak._is_mullvad_exit_interface('poland') is True
    assert dns_leak._is_mullvad_exit_interface('pl') is True  # exit-style: Endpoint, no ListenPort
    assert dns_leak._is_mullvad_exit_interface('sw') is True  # store binding
    assert dns_leak._is_vpn_interface({'name': 'poland', 'link_type': 'wireguard'}) is False
    assert dns_leak._is_vpn_interface({'name': 'pl', 'link_type': 'wireguard'}) is False
    assert dns_leak._is_vpn_interface({'name': 'sw', 'link_type': 'wireguard'}) is False
    assert dns_leak._is_vpn_interface({'name': 'wg0', 'link_type': 'wireguard'}) is True


def test_probe_outbound_missing_tag():
    result = node_probe.probe_outbound_tag('missing', [{'tag': 'direct', 'protocol': 'freedom'}])
    assert result['ok'] is False


def test_probe_region_node_requires_path():
    result = node_probe.probe_region_node(node_id=1, outbound_tag=None, exit_interface=None, outbounds=[])
    assert result['ok'] is False


def test_probe_exit_interface_missing():
    result = node_probe.probe_exit_interface('eth999')
    assert result['ok'] is False


@patch('agent.support.node_probe.shutil.which', return_value='/usr/bin/curl')
@patch('agent.support.node_probe.list_host_interfaces')
def test_probe_region_node_passes_when_any_check_succeeds(_interfaces, _which):
    _interfaces.return_value = [
        {'name': 'uk0', 'is_up': True, 'addresses': ['10.8.0.5/32']},
        {'name': 'de0', 'is_up': True, 'addresses': ['10.9.0.5/32']},
    ]

    calls: list[str | None] = []

    def fake_runner(cmd, **_kwargs):
        iface = None
        if '--interface' in cmd:
            iface = cmd[cmd.index('--interface') + 1]
        url = cmd[-1] if cmd else ''

        class Result:
            returncode = 0
            stdout = '200 0.256' if '1.1.1.1' in url or '1.0.0.1' in url else '204 0.256'
            stderr = ''

        calls.append(iface)
        if iface == 'uk0':
            return Result()
        return type('Result', (), {'returncode': 28, 'stdout': '', 'stderr': 'timeout'})()

    outbounds = [
        {
            'tag': 'deegress',
            'protocol': 'freedom',
            'sendThrough': '10.9.0.5',
        },
    ]

    result = node_probe.probe_region_node(
        node_id=7,
        outbound_tag='deegress',
        exit_interface='uk0',
        outbounds=outbounds,
        runner=fake_runner,
    )

    assert result['ok'] is True
    # Outbound already prefers exit_interface name — no duplicate exit curl.
    assert 'outbound' in result['checks']
    assert 'exit_interface' not in result['checks']
    assert result.get('latency_ms') == 256
    assert result['checks']['outbound'].get('latency_ms') == 256
    assert 'uk0' in calls


@patch('agent.support.node_probe.shutil.which', return_value='/usr/bin/curl')
def test_probe_region_node_skips_duplicate_exit_interface_check(_which):
    calls: list[str | None] = []

    def fake_runner(cmd, **_kwargs):
        url = cmd[-1] if cmd else ''

        class Result:
            returncode = 0
            stdout = '200 0.12' if '1.1.1.1' in url or '1.0.0.1' in url else '204 0.12'
            stderr = ''

        if '--interface' in cmd:
            calls.append(cmd[cmd.index('--interface') + 1])
        return Result()

    outbounds = [
        {
            'tag': 'ukegress',
            'protocol': 'freedom',
            'sendThrough': 'uk0',
        },
    ]

    result = node_probe.probe_region_node(
        node_id=7,
        outbound_tag='ukegress',
        exit_interface='uk0',
        outbounds=outbounds,
        runner=fake_runner,
    )

    assert result['ok'] is True
    assert 'outbound' in result['checks']
    assert 'exit_interface' not in result['checks']
    assert calls == ['uk0']


@patch('agent.support.node_probe.shutil.which', return_value='/usr/bin/curl')
@patch('agent.support.node_probe.list_host_interfaces')
def test_probe_prefers_exit_interface_over_shared_mullvad_ip(_interfaces, _which):
    """Mullvad exits share one Address — curl must bind iface name, not the IP."""
    shared = '10.64.0.2'
    _interfaces.return_value = [
        {'name': 'de', 'is_up': True, 'addresses': [f'{shared}/32']},
        {'name': 'se', 'is_up': True, 'addresses': [f'{shared}/32']},
        {'name': 'nl', 'is_up': True, 'addresses': [f'{shared}/32']},
    ]

    calls: list[str | None] = []

    def fake_runner(cmd, **_kwargs):
        iface = None
        if '--interface' in cmd:
            iface = cmd[cmd.index('--interface') + 1]
        calls.append(iface)
        url = cmd[-1] if cmd else ''

        class Result:
            returncode = 0 if iface == 'se' else 28
            stdout = '200 0.08' if iface == 'se' and ('1.1.1.1' in url or '1.0.0.1' in url) else ''
            stderr = '' if iface == 'se' else 'timeout'

        return Result()

    outbounds = [
        {
            'tag': 'region-node-se',
            'protocol': 'freedom',
            'sendThrough': shared,
        },
    ]

    result = node_probe.probe_region_node(
        node_id=3,
        outbound_tag='region-node-se',
        exit_interface='se',
        outbounds=outbounds,
        runner=fake_runner,
    )

    assert result['ok'] is True
    assert all(item == 'se' for item in calls if item)
    assert 'se' in calls
    # One curl via named iface is enough — duplicate exit_interface probe skipped.
    assert 'exit_interface' not in result['checks']
    assert result['checks']['outbound'].get('interface') == 'se'


@patch('agent.support.node_probe.shutil.which', return_value='/usr/bin/curl')
def test_curl_speed_mbps_binds_interface_name(_which, monkeypatch):
    seen = []

    def fake_runner(cmd, **_kwargs):
        seen.append(list(cmd))

        class Result:
            returncode = 0
            stdout = '200 1250000'
            stderr = ''

        return Result()

    monkeypatch.setattr(node_probe, '_resolve_ipv4_hosts', lambda hosts: ['1.2.3.4'])
    ok, message, mbps = node_probe.curl_speed_mbps(interface='us', runner=fake_runner)
    assert ok is True
    assert mbps == 10.0
    assert '10.0' in message or 'Mbps' in message
    curl_cmds = [row for row in seen if row and row[0] == 'curl']
    assert curl_cmds
    assert '--interface' in curl_cmds[0]
    assert curl_cmds[0][curl_cmds[0].index('--interface') + 1] == 'us'
    # Must not rewrite iface name to a shared tunnel IP.
    assert '10.' not in curl_cmds[0][curl_cmds[0].index('--interface') + 1]
    assert any(row[:3] == ['ip', 'route', 'replace'] and 'us' in row for row in seen)
