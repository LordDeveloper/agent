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


def test_format_peer_not_found_report():
    report = {
        'success': True,
        'found': False,
        'core': 'wireguard',
        'address': '10.80.0.99',
        'cidr': '10.80.0.99/32',
        'matches': [],
        'issues': [
            {
                'level': 'error',
                'code': 'PEER_NOT_FOUND',
                'message': 'No peer with address [10.80.0.99] found in wireguard store',
            }
        ],
        'summary': {
            'healthy': False,
            'issue_count': 1,
            'warning_count': 0,
            'match_count': 0,
        },
    }

    rendered = format_diagnose_report(report, use_color=False)

    assert 'wireguard peer' in rendered
    assert '10.80.0.99' in rendered
    assert 'Found: no' in rendered
    assert 'PEER_NOT_FOUND' in rendered
