import subprocess
from types import SimpleNamespace

from agent.support.node_probe import PROBE_TARGETS, _curl_probe


def test_probe_targets_prefer_literal_ip():
    assert PROBE_TARGETS[0][0].startswith('http://1.1.1.1')
    assert PROBE_TARGETS[1][0].startswith('http://1.0.0.1')


def test_curl_probe_continues_after_timeout():
    calls: list[str] = []

    def runner(args, **_kwargs):
        url = args[-1]
        calls.append(url)
        if '1.1.1.1' in url:
            raise subprocess.TimeoutExpired(cmd=args, timeout=10)
        return SimpleNamespace(returncode=0, stdout='200 0.042', stderr='')

    ok, message, latency = _curl_probe(interface='poland', runner=runner)
    assert ok is True
    assert message == 'اتصال برقرار شد'
    assert latency == 42
    assert any('1.1.1.1' in item for item in calls)
    assert any('1.0.0.1' in item for item in calls)


def test_is_mullvad_exit_skips_table_off(tmp_path, monkeypatch):
    from agent import dns_leak

    conf_dir = tmp_path / 'wireguard'
    conf_dir.mkdir()
    (conf_dir / 'poland.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.64.0.2/32\nTable = off\n',
        encoding='utf-8',
    )
    (conf_dir / 'wg0.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.8.0.1/24\nListenPort=51820\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(dns_leak, '_wg_conf_path', lambda name: conf_dir / f'{name}.conf')

    assert dns_leak._is_mullvad_exit_interface('poland') is True
    assert dns_leak._is_vpn_interface({'name': 'poland', 'link_type': 'wireguard'}) is False
    assert dns_leak._is_vpn_interface({'name': 'wg0', 'link_type': 'wireguard'}) is True
