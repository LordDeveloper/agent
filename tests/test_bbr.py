from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.bbr import bbr_disable, bbr_enable, bbr_install, bbr_status


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_bbr_status_reads_sysctl(monkeypatch):
    monkeypatch.setattr('agent.bbr._require_linux', lambda: None)

    def fake_run(args, **kwargs):
        key = args[-1] if args[0] == 'sysctl' else ''
        if key == 'net.ipv4.tcp_available_congestion_control':
            return _Result(stdout='reno cubic bbr\n')
        if key == 'net.ipv4.tcp_congestion_control':
            return _Result(stdout='bbr\n')
        if key == 'net.core.default_qdisc':
            return _Result(stdout='fq\n')
        return _Result()

    monkeypatch.setattr('agent.bbr._module_loaded', lambda: True)
    monkeypatch.setattr('agent.bbr._run', fake_run)

    payload = bbr_status()
    assert payload['supported'] is True
    assert payload['enabled'] is True
    assert payload['current']['tcp_congestion_control'] == 'bbr'


def test_bbr_install_writes_files(tmp_path, monkeypatch):
    module_path = tmp_path / 'modules' / 'netinja-bbr.conf'
    sysctl_path = tmp_path / 'sysctl' / '99-netinja-bbr.conf'
    monkeypatch.setattr('agent.bbr.BBR_MODULE_PATH', module_path)
    monkeypatch.setattr('agent.bbr.BBR_SYSCTL_PATH', sysctl_path)
    monkeypatch.setattr('agent.bbr._require_linux', lambda: None)
    monkeypatch.setattr('agent.bbr._require_root', lambda: None)
    monkeypatch.setattr('agent.bbr._kernel_supports_bbr', lambda: True)
    monkeypatch.setattr('agent.bbr._load_module', lambda: {'loaded': True, 'modprobe': False})

    payload = bbr_install(apply=False)
    assert payload['installed'] is True
    assert 'tcp_bbr' in module_path.read_text(encoding='utf-8')
    assert 'net.ipv4.tcp_congestion_control=bbr' in sysctl_path.read_text(encoding='utf-8')


def test_bbr_enable_applies_settings(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return _Result()

    monkeypatch.setattr('agent.bbr._require_linux', lambda: None)
    monkeypatch.setattr('agent.bbr._require_root', lambda: None)
    monkeypatch.setattr('agent.bbr._run', fake_run)
    monkeypatch.setattr('agent.bbr._kernel_supports_bbr', lambda: True)
    monkeypatch.setattr('agent.bbr._load_module', lambda: {'loaded': True, 'modprobe': False})
    monkeypatch.setattr('agent.bbr._write_module_load', lambda: {'written': True})
    monkeypatch.setattr('agent.bbr._write_sysctl', lambda settings: {'written': True})
    monkeypatch.setattr('agent.bbr.bbr_status', lambda: {'enabled': True})

    result = bbr_enable()
    assert result['enabled'] is True
    assert any(args[:2] == ['sysctl', '-w'] for args in calls)


def test_bbr_disable_reverts_to_cubic(monkeypatch, tmp_path):
    sysctl_path = tmp_path / '99-netinja-bbr.conf'
    sysctl_path.write_text('net.ipv4.tcp_congestion_control=bbr\n', encoding='utf-8')
    monkeypatch.setattr('agent.bbr.BBR_SYSCTL_PATH', sysctl_path)
    monkeypatch.setattr('agent.bbr.BBR_MODULE_PATH', tmp_path / 'module.conf')
    monkeypatch.setattr('agent.bbr._require_linux', lambda: None)
    monkeypatch.setattr('agent.bbr._require_root', lambda: None)
    monkeypatch.setattr('agent.bbr._run', lambda args, **kwargs: _Result())
    monkeypatch.setattr(
        'agent.bbr.bbr_status',
        lambda: {'enabled': False, 'current': {'tcp_congestion_control': 'cubic'}},
    )

    result = bbr_disable()
    assert result['enabled'] is False
    assert not sysctl_path.exists()


def test_bbr_install_requires_root(monkeypatch):
    monkeypatch.setattr('agent.bbr._require_linux', lambda: None)
    with pytest.raises(Exception) as exc:
        bbr_install()
    assert 'root' in str(exc.value).lower()
