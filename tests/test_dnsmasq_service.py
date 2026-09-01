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
        if args[:2] == ['dnsmasq', '--test']:
            return _Result()
        if args[:2] == ['journalctl', '-u']:
            return _Result(stdout='failed to create listening socket for port 53\n')
        return _Result()

    monkeypatch.setattr('agent.dns_leak.run', fake_run)
    monkeypatch.setattr('agent.dns_leak.dnsmasq_service_active', lambda runner=None: False)

    active_states = iter([False, True])

    def fake_active(*, runner=None):
        return next(active_states)

    monkeypatch.setattr('agent.dns_leak.dnsmasq_service_active', fake_active)

    payload = ensure_dnsmasq_service(runner=fake_run)

    assert payload['active'] is True
    assert 'disabled_resolved_stub_listener' in payload['actions']
    assert dropin.is_file()
    assert any(args[:3] == ['systemctl', 'restart', 'systemd-resolved'] for args in calls)
