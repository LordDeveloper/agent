from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.support import record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.support.openvpn_config import (
    instance_name_for_server,
    parse_status_v2,
    tun_dev_for_server,
)
from agent.support.openvpn_ip import assert_openvpn_address
from agent.support.peer_diagnose import (
    _iface_link,
    _ip_rules_for_source,
    _issue,
    _nat_status,
    _read_sysctl,
    _route_lookup_from,
    _route_table,
    normalize_peer_host,
)
from agent.support.peer_egress import peer_source_cidr, rule_pref_for_addr, table_id_for_interface
from agent.support.process import run

Runner = Callable[..., Any]

_SERVER_KIND = 'server'
_SYSTEM_SERVER_ROOT = Path('/etc/openvpn/server')
_RUNTIME_STATUS_ROOT = Path('/run/openvpn-server')


def find_users_by_address(store: Store, core: str, address: str) -> list[dict[str, Any]]:
    host = normalize_peer_host(address)
    if not host:
        return []

    rows: list[dict[str, Any]] = []
    for server in store.list_docs(core, _SERVER_KIND):
        for user in server.get('users') or []:
            if not isinstance(user, dict):
                continue
            user_host = normalize_peer_host(user.get('address'))
            if user_host != host:
                continue
            rows.append(
                {
                    'server': {
                        'id': server.get('id'),
                        'name': server.get('name'),
                        'listen_port': server.get('listen_port'),
                        'subnet': server.get('subnet'),
                        'tun_dev': tun_dev_for_server(server),
                        'instance': instance_name_for_server(server),
                    },
                    'user': user,
                    'server_doc': server,
                }
            )
    return rows


def _run_cmd(runner: Runner, args: list[str], *, timeout: float = 10.0) -> dict[str, Any]:
    try:
        result = runner(args, timeout=timeout)
    except TypeError:
        result = runner(args)
    except Exception as exc:
        return {'ok': False, 'stdout': '', 'stderr': str(exc), 'returncode': -1}

    return {
        'ok': int(getattr(result, 'returncode', 1)) == 0,
        'stdout': str(getattr(result, 'stdout', '') or ''),
        'stderr': str(getattr(result, 'stderr', '') or ''),
        'returncode': int(getattr(result, 'returncode', 1)),
    }


def _service_active(runner: Runner, unit: str) -> bool:
    dump = _run_cmd(runner, ['systemctl', 'is-active', unit])
    return dump.get('stdout', '').strip() == 'active'


def _status_log_paths(server: dict[str, Any]) -> list[Path]:
    instance = instance_name_for_server(server)
    return [
        _RUNTIME_STATUS_ROOT / f'status-{instance}.log',
        _SYSTEM_SERVER_ROOT / instance / 'openvpn-status.log',
    ]


def collect_openvpn_sessions(
    servers: list[dict[str, Any]],
    *,
    status_reader: Callable[[Path], str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Map virtual IP / username -> live OpenVPN CLIENT_LIST row."""
    sessions: dict[str, dict[str, Any]] = {}
    reader = status_reader or (lambda path: path.read_text(encoding='utf-8', errors='ignore'))

    for server in servers:
        if not isinstance(server, dict):
            continue
        text = ''
        for status_path in _status_log_paths(server):
            try:
                if not status_path.is_file():
                    continue
                text = reader(status_path)
            except OSError:
                continue
            if str(text or '').strip():
                break
        if not str(text or '').strip():
            continue

        tun = tun_dev_for_server(server)
        for row in parse_status_v2(str(text)):
            username = str(row.get('username') or '').strip()
            vip = normalize_peer_host(row.get('virtual_address'))
            live = {
                'username': username,
                'real_address': row.get('real_address'),
                'virtual_address': vip,
                'bytes_received': int(row.get('bytes_received') or 0),
                'bytes_sent': int(row.get('bytes_sent') or 0),
                'interface': tun,
                'is_up': True,
                'online': True,
                'server_id': server.get('id'),
            }
            if username:
                sessions[f'user:{username}'] = live
            if vip:
                sessions[vip] = live

    return sessions


def _live_for_user(
    sessions: dict[str, dict[str, Any]],
    *,
    host: str,
    username: str,
) -> dict[str, Any] | None:
    if username:
        by_user = sessions.get(f'user:{username}')
        if by_user:
            return by_user
    return sessions.get(host)


def diagnose_user_match(
    *,
    core: str,
    host: str,
    server: dict[str, Any],
    user: dict[str, Any],
    server_doc: dict[str, Any],
    runner: Runner,
    sessions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    enabled = record_is_enabled(user)
    checks.append({'name': 'user_enabled', 'ok': enabled})
    if not enabled:
        issues.append(
            _issue(
                'error',
                'USER_DISABLED',
                explain_disabled(user),
                disabled_reason=user.get('disabled_reason'),
            )
        )

    subnet = str(server.get('subnet') or server_doc.get('subnet') or '')
    try:
        assert_openvpn_address(subnet, host)
        checks.append({'name': 'address_in_subnet', 'ok': True, 'subnet': subnet})
    except Exception as exc:
        checks.append({'name': 'address_in_subnet', 'ok': False, 'subnet': subnet})
        issues.append(_issue('error', 'ADDRESS_RANGE_INVALID', str(exc)))

    username = str(user.get('username') or '').strip()
    password = str(user.get('password') or '').strip()
    checks.append({'name': 'credentials_present', 'ok': bool(username and password)})
    if not username or not password:
        issues.append(
            _issue('error', 'CREDENTIALS_MISSING', 'OpenVPN username or password is missing in store')
        )

    instance = str(server.get('instance') or instance_name_for_server(server_doc))
    unit = f'openvpn-server@{instance}.service'
    unit_up = _service_active(runner, unit)
    checks.append({'name': 'openvpn_unit_active', 'ok': unit_up, 'unit': unit})
    if not unit_up:
        issues.append(
            _issue(
                'error',
                'OPENVPN_UNIT_DOWN',
                f'OpenVPN unit [{unit}] is not active',
                unit=unit,
            )
        )

    tun = str(server.get('tun_dev') or tun_dev_for_server(server_doc))
    tun_link = _iface_link(runner, tun)
    checks.append({'name': 'tun_interface_up', 'ok': bool(tun_link.get('is_up')), 'interface': tun})
    if unit_up and not tun_link.get('is_up'):
        issues.append(
            _issue(
                'error',
                'TUN_INTERFACE_DOWN',
                f'TUN interface [{tun}] is down or missing',
                interface=tun,
            )
        )

    ccd_path = _SYSTEM_SERVER_ROOT / instance / 'ccd' / username if username else None
    ccd_ok = bool(ccd_path and ccd_path.is_file()) if username else False
    checks.append(
        {
            'name': 'ccd_present',
            'ok': ccd_ok if enabled and username else True,
            'path': str(ccd_path) if ccd_path else None,
        }
    )
    if enabled and username and not ccd_ok:
        issues.append(
            _issue(
                'warning',
                'CCD_MISSING',
                f'CCD file missing for [{username}] under [{instance}]',
                path=str(ccd_path),
            )
        )

    live_sessions = sessions if sessions is not None else collect_openvpn_sessions([server_doc])
    live = _live_for_user(live_sessions, host=host, username=username)
    checks.append({'name': 'openvpn_session', 'ok': live is not None and live.get('is_up')})
    if live is None:
        issues.append(_issue('warning', 'NOT_ONLINE', f'No active OpenVPN session for [{host}]'))
    elif not live.get('is_up'):
        issues.append(_issue('warning', 'SESSION_DOWN', 'OpenVPN session present but marked down'))

    cidr = peer_source_cidr(user.get('address')) or f'{host}/32'
    exit_iface = str(user.get('exit_interface') or '').strip() or None
    expected_table = table_id_for_interface(exit_iface) if exit_iface else None
    expected_pref = rule_pref_for_addr(host)
    ip_rules = _ip_rules_for_source(runner, cidr)
    routing: dict[str, Any] = {
        'exit_interface': exit_iface,
        'cidr': cidr,
        'expected_table': expected_table,
        'expected_rule_pref': expected_pref,
        'ip_rules': ip_rules,
        'policy_route': None,
        'simulated_egress': None,
        'tun_interface': tun,
        'tun_link': tun_link,
    }

    if exit_iface:
        exit_link = _iface_link(runner, exit_iface)
        routing['exit_link'] = exit_link
        checks.append({'name': 'exit_interface_up', 'ok': bool(exit_link.get('is_up'))})
        if not exit_link.get('is_up'):
            issues.append(
                _issue(
                    'error',
                    'EXIT_INTERFACE_DOWN',
                    f'Exit interface [{exit_iface}] is down or missing',
                )
            )

        table = table_id_for_interface(exit_iface)
        routes = _route_table(runner, table)
        has_default = any(line.startswith('default') for line in routes)
        routing['policy_route'] = {'table': table, 'routes': routes, 'has_default': has_default}
        checks.append({'name': 'policy_table_default', 'ok': has_default})
        if not has_default:
            issues.append(
                _issue(
                    'error',
                    'POLICY_ROUTE_MISSING',
                    f'No default route in policy table {table} for exit [{exit_iface}]',
                    table=table,
                )
            )

        table_text = str(table)
        has_rule = any(
            str(row.get('table') or row.get('lookup') or '')
            in {table_text, f'table {table_text}', f'lookup {table_text}'}
            or f'lookup {table_text}' in str(row.get('raw') or '')
            for row in ip_rules
        )
        if not has_rule and ip_rules:
            has_rule = True
        checks.append({'name': 'ip_rule_present', 'ok': has_rule})
        if not has_rule:
            issues.append(
                _issue(
                    'error',
                    'IP_RULE_MISSING',
                    f'No ip rule steering traffic from {cidr} to table {table}',
                    table=table,
                )
            )

        nat = _nat_status(runner, exit_iface)
        routing['nat'] = nat
        checks.append({'name': 'exit_nat', 'ok': bool(nat.get('masquerade'))})
        if not nat.get('masquerade'):
            issues.append(
                _issue('error', 'NAT_MISSING', f'No MASQUERADE for exit interface [{exit_iface}]')
            )

        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, tun)
    else:
        issues.append(
            _issue(
                'warning',
                'EXIT_INTERFACE_UNSET',
                'OpenVPN user has no exit_interface — traffic uses main routing table only',
            )
        )
        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, tun)

    ip_forward = _read_sysctl('/proc/sys/net/ipv4/ip_forward')
    checks.append({'name': 'ip_forward', 'ok': ip_forward == '1'})
    if ip_forward != '1':
        issues.append(_issue('error', 'IP_FORWARD_DISABLED', 'net.ipv4.ip_forward is not enabled'))

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')

    return {
        'core': core,
        'address': host,
        'cidr': cidr,
        'server': server,
        'user': {
            'id': user.get('id'),
            'email': user.get('email'),
            'username': username,
            'address': user.get('address'),
            'exit_interface': exit_iface,
            'is_enabled': enabled,
            'online': user.get('online'),
            'incoming': user.get('incoming'),
            'outgoing': user.get('outgoing'),
        },
        'live': live,
        'routing': routing,
        'checks': checks,
        'issues': issues,
        'healthy': error_count == 0,
        'issue_counts': {'error': error_count, 'warning': warning_count},
    }


def diagnose_user_address(
    store: Store,
    core: str,
    address: str,
    *,
    runner: Runner | None = None,
    sessions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    execute = runner or run
    host = normalize_peer_host(address)
    if not host:
        raise ValueError('address is required')

    rows = find_users_by_address(store, core, host)
    if not rows:
        issue = _issue('error', 'USER_NOT_FOUND', f'No OpenVPN user with address [{host}] in store')
        return {
            'success': True,
            'found': False,
            'core': core,
            'address': host,
            'matches': [],
            'issues': [issue],
            'summary': {'healthy': False, 'issue_count': 1, 'warning_count': 0, 'match_count': 0},
        }

    live_sessions = sessions
    if live_sessions is None:
        live_sessions = collect_openvpn_sessions([row['server_doc'] for row in rows])

    matches = [
        diagnose_user_match(
            core=core,
            host=host,
            server=row['server'],
            user=row['user'],
            server_doc=row['server_doc'],
            runner=execute,
            sessions=live_sessions,
        )
        for row in rows
    ]

    issue_count = sum(m['issue_counts']['error'] for m in matches)
    warning_count = sum(m['issue_counts']['warning'] for m in matches)
    healthy = issue_count == 0 and all(m.get('healthy') for m in matches)

    return {
        'success': True,
        'found': True,
        'core': core,
        'address': host,
        'matches': matches,
        'summary': {
            'healthy': healthy,
            'issue_count': issue_count,
            'warning_count': warning_count,
            'match_count': len(matches),
        },
    }
