from agent.db import Store
from agent.support.l2tp_diagnose import diagnose_user_address


class _Result:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_diagnose_reports_missing_user(tmp_path):
    store = Store(tmp_path / 'agent.db')
    report = diagnose_user_address(store, 'l2tp', '10.90.128.50', runner=lambda *a, **k: _Result())
    assert report['found'] is False
    assert report['summary']['healthy'] is False


def test_diagnose_finds_user(tmp_path):
    store = Store(tmp_path / 'agent.db')
    store.put_doc(
        'l2tp',
        'server',
        '1',
        {
            'id': 1,
            'name': 'l2tp-1',
            'subnet': '10.90.0.0/16',
            'listen_port': 1701,
            'ipsec_psk': 'secret',
            'users': [
                {
                    'id': 'u1',
                    'email': 'u1@test',
                    'username': 'alice',
                    'password': 'pass',
                    'address': '10.90.128.50',
                    'is_enabled': True,
                }
            ],
        },
    )

    def runner(args, timeout=10):
        if args[:3] == ['systemctl', 'is-active', 'xl2tpd']:
            return _Result(stdout='inactive\n')
        if args[:3] == ['systemctl', 'is-active', 'strongswan-starter']:
            return _Result(stdout='inactive\n')
        if args[:3] == ['ip', '-j', 'addr']:
            return _Result(stdout='[]')
        return _Result()

    report = diagnose_user_address(store, 'l2tp', '10.90.128.50', runner=runner)
    assert report['found'] is True
    assert report['summary']['match_count'] == 1
    codes = {issue['code'] for match in report['matches'] for issue in match['issues']}
    assert 'XL2TPD_DOWN' in codes
