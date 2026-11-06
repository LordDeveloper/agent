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
                'id': '90c10bb2-ea51-492a-84c5-cfcef6aeaa55',
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
    assert 'id:' in rendered
    assert '90c10bb2-ea51-492a-84c5-cfcef6aeaa55' in rendered
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
    assert 'Bandwidth' in rendered
    assert 'UNLIMITED' in rendered


def test_format_wireguard_peer_diagnose_shows_bandwidth_states():
    base = {
        'success': True,
        'found': True,
        'core': 'wireguard',
        'address': '10.90.68.108',
        'summary': {'healthy': True, 'issue_count': 0, 'warning_count': 0, 'match_count': 1},
    }

    def render(bandwidth: dict, routing: dict | None = None) -> str:
        report = {
            **base,
            'matches': [{
                'address': '10.90.68.108',
                'interface': {'name': 'wg9a440050'},
                'peer': {'email': 'BOZIfQ', 'is_enabled': True, 'address': '10.90.68.108'},
                'live': {'is_up': True},
                'routing': routing or {'exit_interface': 'de', 'status': 'pending', 'verified': False},
                'bandwidth': bandwidth,
                'checks': [{'name': 'peer_enabled', 'ok': True}],
            }],
        }
        return format_diagnose_report(report, use_color=False)

    active = render({
        'configured': True,
        'download_mbps': 5,
        'upload_mbps': 5,
        'status': 'active',
        'method': 'htb_ifb',
        'interface': 'wg9a440050',
        'download_class': 'njbw-4793',
        'upload_class': 'njbw-4793',
        'objects': {
            'download_class': True,
            'download_filter': True,
            'upload_class': True,
            'upload_filter': True,
            'ingress_redirect': True,
        },
        'verified': True,
        'last_reconcile_at': 1762346301,
    })
    assert 'Bandwidth' in active
    assert 'Configured:    yes' in active
    assert 'Download:      5 Mbps' in active
    assert 'Upload:        5 Mbps' in active
    assert 'Status:        ACTIVE' in active
    assert 'HTB / IFB' in active
    assert 'wg9a440050' in active
    assert 'njbw-4793' in active
    assert 'Download filter: yes' in active
    assert 'Upload filter: yes' in active
    assert 'Ingress redirect: yes' in active
    assert 'Kernel verified: yes' in active
    assert 'PENDING' in active
    assert 'peer_enabled' in active

    unlimited = render({'configured': False, 'status': 'unlimited'})
    assert 'Configured:    no' in unlimited
    assert 'UNLIMITED' in unlimited
    assert 'Error:' not in unlimited

    failed = render({
        'configured': True,
        'download_mbps': 1,
        'upload_mbps': 1,
        'status': 'error',
        'interface': 'wg9a440050',
        'verified': False,
        'objects': {
            'download_class': True,
            'download_filter': False,
            'upload_class': True,
            'upload_filter': False,
            'ingress_redirect': False,
        },
        'details': {
            'download_filter': {
                'interface': 'wg9a440050',
                'parent': '1:0',
                'protocol': 'ip',
                'priority': 10,
                'classid': '1:1419',
                'match': 'ip dst 10.90.68.108/32',
                'observed': 'no u32 filter with that destination and flowid',
            },
        },
        'last_error': 'filter for 10.90.68.108 missing on wg9a440050 parent 1:',
    })
    assert 'Status:        ERROR' in failed
    assert 'Download filter: no' in failed
    assert 'Kernel verified: no' in failed
    assert 'parent 1:0' in failed
    assert 'protocol ip' in failed
    assert 'prio 10' in failed
    assert 'classid 1:1419' in failed
    assert 'ip dst 10.90.68.108/32' in failed
    assert 'no u32 filter' in failed
