from __future__ import annotations

from types import SimpleNamespace

from agent.dns_leak import ensure_dnsmasq_service


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = '', stderr: str = ''):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_ensure_dnsmasq_service_disables_resolved_stub_on_port_conflict(tmp_path, monkeypatch):
    dropin = tmp_path / 'resolved.conf.d' / 'netinja-dnsmasq.conf'
    monkeypatch.setattr('agent.dns_leak.RESOLVED_STUB_DROPIN', dropin)
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: f'/usr/bin/{cmd}')

    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[:3] == ['systemctl', 'is-active', 'dnsmasq']:
            return _Result(stdout='inactive\n')
        if args[:3] == ['systemctl', 'is-enabled', 'dnsmasq']:
            return _Result(stdout='enabled\n')
        if args[:2] == ['dnsmasq', '--test']:
            return _Result()
        if args[:2] == ['journalctl', '-u']:
            return _Result(stdout='failed to create listening socket for port 53\n')
        return _Result()

    active_states = iter([False, False, False, True])

    def fake_active(*, runner=None):
        return next(active_states, True)

    monkeypatch.setattr('agent.dns_leak.dnsmasq_service_active', fake_active)

    payload = ensure_dnsmasq_service(runner=fake_run)

    assert payload['active'] is True
    assert 'disabled_resolved_stub_listener' in payload['actions']
    assert dropin.is_file()
    assert any(args[:3] == ['systemctl', 'restart', 'systemd-resolved'] for args in calls)


def test_ensure_dnsmasq_service_does_not_touch_resolved_without_port_conflict(tmp_path, monkeypatch):
    dropin = tmp_path / 'resolved.conf.d' / 'netinja-dnsmasq.conf'
    monkeypatch.setattr('agent.dns_leak.RESOLVED_STUB_DROPIN', dropin)
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: f'/usr/bin/{cmd}')

    def fake_run(args, **kwargs):
        if args[:3] == ['systemctl', 'is-enabled', 'dnsmasq']:
            return _Result(stdout='enabled\n')
        if args[:2] == ['dnsmasq', '--test']:
            return _Result()
        if args[:2] == ['journalctl', '-u']:
            return _Result(stdout='-- No entries --\n')
        if args[:3] == ['systemctl', 'status', 'dnsmasq']:
            return _Result(stdout='Active: inactive (dead)\n')
        return _Result()

    monkeypatch.setattr('agent.dns_leak.dnsmasq_service_active', lambda runner=None: False)

    payload = ensure_dnsmasq_service(runner=fake_run)

    assert payload['active'] is False
    assert 'disabled_resolved_stub_listener' not in payload['actions']
    assert not dropin.is_file()


def test_ensure_dnsmasq_service_unmasks_dnsmasq(tmp_path, monkeypatch):
    dropin = tmp_path / 'resolved.conf.d' / 'netinja-dnsmasq.conf'
    monkeypatch.setattr('agent.dns_leak.RESOLVED_STUB_DROPIN', dropin)
    monkeypatch.setattr('agent.dns_leak.shutil.which', lambda cmd: f'/usr/bin/{cmd}')

    calls: list[list[str]] = []
    enabled_states = iter(['masked', 'enabled'])

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[:3] == ['systemctl', 'is-enabled', 'dnsmasq']:
            return _Result(stdout=next(enabled_states) + '\n')
        if args[:3] == ['systemctl', 'is-active', 'dnsmasq']:
            return _Result(stdout='inactive\n')
        if args[:2] == ['dnsmasq', '--test']:
            return _Result()
        if args[:2] == ['journalctl', '-u']:
            return _Result(stdout='-- No entries --\n')
        if args[:3] == ['systemctl', 'status', 'dnsmasq']:
            return _Result(stdout='Loaded: masked\nActive: inactive (dead)\n')
        return _Result()

    active_calls = {'count': 0}

    def fake_active(*, runner=None):
        active_calls['count'] += 1
        return active_calls['count'] > 4

    monkeypatch.setattr('agent.dns_leak.dnsmasq_service_active', fake_active)

    payload = ensure_dnsmasq_service(runner=fake_run)

    assert 'unmasked_dnsmasq' in payload['actions']
    assert any(args[:3] == ['systemctl', 'unmask', 'dnsmasq'] for args in calls)
    assert 'disabled_resolved_stub_listener' not in payload['actions']
