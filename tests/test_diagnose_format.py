from agent.support.diagnose_format import ascii_table, format_diagnose_report


def test_ascii_table_renders_headers_and_rows():
    rendered = ascii_table(['Check', 'Result'], [['peer_enabled', 'OK']])
    assert 'Check' in rendered
    assert 'peer_enabled' in rendered
    assert 'OK' in rendered
    assert rendered.startswith('┌')


def test_format_xray_client_diagnose_report():
    report = {
        'success': True,
        'found': True,
        'core': 'xray',
        'key': 'abc123',
        'email': 'abc123',
        'inbound_id': None,
        'summary': {
            'healthy': False,
            'issue_count': 1,
            'warning_count': 1,
            'match_count': 1,
        },
        'matches': [
            {
                'healthy': False,
                'inbound_tag': 'vless-in',
                'email': 'abc123',
                'inbound': {'tag': 'vless-in', 'port': 443, 'protocol': 'vless'},
                'client': {
                    'id': '11111111-1111-1111-1111-111111111111',
                    'email': 'abc123',
                    'is_enabled': True,
                    'flow': 'xtls-rprx-vision',
                },
                'live': {'online': False, 'is_enabled': True, 'ips': []},
                'checks': [
                    {'name': 'client_enabled', 'ok': True},
                    {'name': 'online_now', 'ok': False},
                ],
                'issues': [
                    {
                        'level': 'warning',
                        'code': 'CLIENT_OFFLINE',
                        'message': 'Client is enabled on Xray but has no active online session right now',
                    }
                ],
            }
        ],
    }

    rendered = format_diagnose_report(report, use_color=False)

    assert 'Agent diagnose — Xray client' in rendered
    assert 'abc123' in rendered
    assert 'vless-in' in rendered
    assert 'Checks' in rendered
    assert 'client_enabled' in rendered
    assert 'Issues' in rendered
    assert 'CLIENT_OFFLINE' in rendered


def test_format_l2tp_user_diagnose_shows_username():
    report = {
        'success': True,
        'found': True,
        'core': 'l2tp',
        'address': '10.164.128.2',
        'summary': {
            'healthy': True,
            'issue_count': 0,
            'warning_count': 1,
            'match_count': 1,
        },
        'matches': [
            {
                'healthy': True,
                'address': '10.164.128.2',
                'server': {'id': 12, 'name': 'wg-l2tp-12', 'subnet': '10.164.0.0/16'},
                'user': {
                    'id': 'peer-1',
                    'email': 'user@example.com',
                    'username': 'u_e123916e',
                    'address': '10.164.128.2',
                    'linked_peer_id': 'peer-1',
                    'is_enabled': True,
                    'online': False,
                },
                'live': None,
                'routing': {'exit_interface': None},
                'checks': [
                    {'name': 'credentials_present', 'ok': True},
                    {'name': 'ppp_session', 'ok': False},
                ],
                'issues': [
                    {
                        'level': 'warning',
                        'code': 'NOT_ONLINE',
                        'message': 'No active PPP session for [10.164.128.2]',
                    }
                ],
            }
        ],
    }

    rendered = format_diagnose_report(report, use_color=False)

    assert 'l2tp peer' in rendered
    assert 'Username:' in rendered
    assert 'u_e123916e' in rendered
    assert 'Linked peer:' in rendered
    assert 'wg-l2tp-12' in rendered
