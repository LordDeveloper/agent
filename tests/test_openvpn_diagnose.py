from agent.db import Store
from agent.support.openvpn_diagnose import diagnose_user_address


class _Result:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_diagnose_reports_missing_user(tmp_path):
    store = Store(tmp_path / 'agent.db')
    report = diagnose_user_address(store, 'openvpn', '10.8.0.5', runner=lambda *a, **k: _Result())
    assert report['found'] is False
    assert report['summary']['healthy'] is False
    assert report['issues'][0]['code'] == 'USER_NOT_FOUND'


def test_diagnose_finds_user_and_flags_down_unit(tmp_path):
    store = Store(tmp_path / 'agent.db')
    store.put_doc(
        'openvpn',
        'server',
        '1',
        {
            'id': 1,
            'name': 'ovpn-1',
            'subnet': '10.8.0.0/24',
            'listen_port': 1194,
            'tun_dev': 'ovpn1',
            'users': [
                {
                    'id': 'u1',
                    'email': 'u1@test',
                    'username': 'alice',
                    'password': 'pass',
                    'address': '10.8.0.5',
                    'is_enabled': True,
                    'exit_interface': 'eth0',
                }
            ],
        },
    )

    def runner(args, timeout=10):
        if args[:3] == ['systemctl', 'is-active', 'openvpn-server@ovpn-1.service']:
            return _Result(stdout='inactive\n')
        if args[:3] == ['ip', '-j', 'link'] or (len(args) >= 4 and args[0] == 'ip' and args[1] == 'link'):
            return _Result(stdout='[]')
        if args[:2] == ['ip', '-4'] or (args[:3] == ['ip', 'route', 'get']):
            return _Result()
        return _Result()

    report = diagnose_user_address(
        store,
        'openvpn',
        '10.8.0.5',
        runner=runner,
        sessions={},
    )
    assert report['found'] is True
    assert report['summary']['match_count'] == 1
    codes = {issue['code'] for match in report['matches'] for issue in match['issues']}
    assert 'OPENVPN_UNIT_DOWN' in codes
    assert 'NOT_ONLINE' in codes
