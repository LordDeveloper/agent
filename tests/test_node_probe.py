from unittest.mock import patch

from agent.support import node_probe


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

        class Result:
            returncode = 0
            stdout = '204'
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
    assert 'exit_interface' in result['checks']
    assert 'outbound' in result['checks']


@patch('agent.support.node_probe.shutil.which', return_value='/usr/bin/curl')
def test_probe_region_node_skips_duplicate_exit_interface_check(_which):
    calls: list[str | None] = []

    def fake_runner(cmd, **_kwargs):
        class Result:
            returncode = 0
            stdout = '204'
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
