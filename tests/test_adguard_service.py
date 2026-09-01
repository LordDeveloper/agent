from __future__ import annotations

from types import SimpleNamespace

from agent.adguard import (
    ADGUARD_CONFIG,
    AGENT_ADGUARD_UNIT_PATH,
    ADGUARD_UNIT_MARKER,
    ensure_adguard_service,
    ensure_adguard_systemd_unit,
    render_adguard_config,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_render_adguard_config_binds_vpn_gateway_and_enables_filters():
    conf = render_adguard_config(['10.80.0.1'], filtering_enabled=True)
    assert "'10.80.0.1'" in conf
    assert 'filtering_enabled: true' in conf
    assert 'AdGuard DNS filter' in conf
    assert 'http:' in conf
    assert '127.0.0.1:3000' in conf


def test_render_adguard_config_can_disable_filtering():
    conf = render_adguard_config(['10.80.0.1'], filtering_enabled=False)
    assert 'filtering_enabled: false' in conf
    assert 'filters:\n  []' in conf


def test_ensure_adguard_systemd_unit_creates_agent_unit(tmp_path, monkeypatch):
    unit_path = tmp_path / 'agent-adguard.service'
    marker_path = tmp_path / 'adguard-systemd-unit'
    binary = tmp_path / 'AdGuardHome'
    binary.write_text('bin', encoding='utf-8')
    work_dir = tmp_path / 'work'
    work_dir.mkdir()

    monkeypatch.setattr('agent.adguard.AGENT_ADGUARD_UNIT_PATH', unit_path)
    monkeypatch.setattr('agent.adguard.ADGUARD_UNIT_MARKER', marker_path)
    monkeypatch.setattr('agent.adguard.ADGUARD_BINARY', binary)
    monkeypatch.setattr('agent.adguard.ADGUARD_WORK_DIR', work_dir)
    monkeypatch.setattr('agent.adguard.install_adguard_binary', lambda runner=None: True)
    monkeypatch.setattr(
        'agent.adguard.shutil.which',
        lambda cmd: str(binary) if cmd == 'AdGuardHome' else f'/usr/bin/{cmd}',
    )

    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return _Result()

    payload = ensure_adguard_systemd_unit(runner=fake_run)

    assert payload['ok'] is True
    assert payload['unit'] == 'agent-adguard'
    assert payload['created'] is True
    assert unit_path.is_file()
    assert 'AdGuardHome.yaml' in unit_path.read_text(encoding='utf-8')
    assert marker_path.is_file()
    assert any(args[:3] == ['systemctl', 'daemon-reload'] for args in calls)


def test_ensure_adguard_service_disables_resolved_stub_on_port_conflict(tmp_path, monkeypatch):
    dropin = tmp_path / 'resolved.conf.d' / 'netinja-adguard.conf'
    config = tmp_path / 'AdGuardHome.yaml'
    config.write_text('dns:\n  bind_hosts:\n    - 10.80.0.1\n', encoding='utf-8')
    marker = tmp_path / 'adguard-systemd-unit'
    marker.write_text('agent-adguard', encoding='utf-8')

    monkeypatch.setattr('agent.adguard.RESOLVED_STUB_DROPIN', dropin)
    monkeypatch.setattr('agent.adguard.ADGUARD_CONFIG', config)
    monkeypatch.setattr('agent.adguard.ADGUARD_BINARY', tmp_path / 'AdGuardHome')
    monkeypatch.setattr('agent.adguard.ADGUARD_UNIT_MARKER', marker)
    monkeypatch.setattr('agent.adguard.cleanup_legacy_dnsmasq', lambda runner=None: [])
    monkeypatch.setattr('agent.adguard.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    monkeypatch.setattr(
        'agent.adguard.ensure_adguard_systemd_unit',
        lambda runner=None: {'ok': True, 'unit': 'agent-adguard', 'created': False, 'installed': False},
    )
    monkeypatch.setattr(
        'agent.adguard.adguard_service_diagnostic',
        lambda runner=None: 'bind: address already in use',
    )

    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[:3] == ['systemctl', 'is-enabled', 'agent-adguard']:
            return _Result(stdout='enabled\n')
        return _Result()

    active_states = iter([False, False, False, True])

    def fake_active(*, runner=None):
        return next(active_states, True)

    monkeypatch.setattr('agent.adguard.adguard_service_active', fake_active)

    payload = ensure_adguard_service(runner=fake_run)

    assert payload['active'] is True
    assert 'disabled_resolved_stub_listener' in payload['actions']
    assert dropin.is_file()
    assert any(args[:3] == ['systemctl', 'restart', 'systemd-resolved'] for args in calls)


def test_ensure_adguard_service_does_not_touch_resolved_without_port_conflict(tmp_path, monkeypatch):
    dropin = tmp_path / 'resolved.conf.d' / 'netinja-adguard.conf'
    config = tmp_path / 'AdGuardHome.yaml'
    config.write_text('dns:\n  bind_hosts:\n    - 10.80.0.1\n', encoding='utf-8')

    monkeypatch.setattr('agent.adguard.RESOLVED_STUB_DROPIN', dropin)
    monkeypatch.setattr('agent.adguard.ADGUARD_CONFIG', config)
    monkeypatch.setattr('agent.adguard.ADGUARD_BINARY', tmp_path / 'AdGuardHome')
    monkeypatch.setattr('agent.adguard.ADGUARD_UNIT_MARKER', tmp_path / 'adguard-systemd-unit')
    (tmp_path / 'adguard-systemd-unit').write_text('agent-adguard', encoding='utf-8')
    monkeypatch.setattr('agent.adguard.cleanup_legacy_dnsmasq', lambda runner=None: [])
    monkeypatch.setattr('agent.adguard.shutil.which', lambda cmd: f'/usr/bin/{cmd}')
    monkeypatch.setattr(
        'agent.adguard.ensure_adguard_systemd_unit',
        lambda runner=None: {'ok': True, 'unit': 'agent-adguard', 'created': False, 'installed': False},
    )

    def fake_run(args, **kwargs):
        if args[:3] == ['systemctl', 'is-enabled', 'agent-adguard']:
            return _Result(stdout='enabled\n')
        if args[:2] == ['journalctl', '-u']:
            return _Result(stdout='-- No entries --\n')
        if args[:3] == ['systemctl', 'status', 'agent-adguard']:
            return _Result(stdout='Active: inactive (dead)\n')
        return _Result()

    monkeypatch.setattr('agent.adguard.adguard_service_active', lambda runner=None: False)

    payload = ensure_adguard_service(runner=fake_run)

    assert payload['active'] is False
    assert 'disabled_resolved_stub_listener' not in payload['actions']
    assert not dropin.is_file()
