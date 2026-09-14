from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.support import record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.support.l2tp_ip import assert_l2tp_address, is_l2tp_host
from agent.support.peer_diagnose import (
    _iface_link,
    _issue,
    _nat_status,
    _read_sysctl,
    normalize_peer_host,
)
from agent.support.process import run

Runner = Callable[..., Any]

_SERVER_KIND = 'server'
_ONLINE_SECONDS = 180


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


def _collect_ppp_sessions(runner: Runner) -> dict[str, dict[str, Any]]:
    """Map client IP -> session info from PPP interfaces."""
    dump = _run_cmd(runner, ['ip', '-j', 'addr', 'show'])
    sessions: dict[str, dict[str, Any]] = {}
    if not dump['ok'] or not dump['stdout'].strip():
        return sessions

    try:
        rows = json.loads(dump['stdout'])
    except json.JSONDecodeError:
        return sessions

    if not isinstance(rows, list):
        return sessions

    now = int(time.time())
    for iface in rows:
        if not isinstance(iface, dict):
            continue
        ifname = str(iface.get('ifname') or '')
        if not ifname.startswith('ppp'):
            continue
        operstate = str(iface.get('operstate') or '').upper()
        is_up = operstate == 'UP'
        client_ip = None
        for addr in iface.get('addr_info') or []:
            if not isinstance(addr, dict):
                continue
            peer = str(addr.get('peer') or addr.get('address') or '').split('/', 1)[0].strip()
            local = str(addr.get('local') or '').split('/', 1)[0].strip()
            if peer and peer != local:
                client_ip = peer
                break
        if not client_ip:
            continue
        sessions[client_ip] = {
            'interface': ifname,
            'operstate': operstate,
            'is_up': is_up,
            'online': is_up,
        }

        stats_path = f'/sys/class/net/{ifname}/statistics'
        try:
            rx = int(Path(f'{stats_path}/rx_bytes').read_text(encoding='utf-8').strip())
            tx = int(Path(f'{stats_path}/tx_bytes').read_text(encoding='utf-8').strip())
        except OSError:
            rx = tx = 0
        sessions[client_ip]['incoming'] = rx
        sessions[client_ip]['outgoing'] = tx
        sessions[client_ip]['seen_at'] = now

    return sessions


def diagnose_user_match(
    *,
    core: str,
    host: str,
    server: dict[str, Any],
    user: dict[str, Any],
    runner: Runner,
    ppp_sessions: dict[str, dict[str, Any]] | None = None,
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

    subnet = str(server.get('subnet') or '')
    try:
        assert_l2tp_address(subnet, host)
        checks.append({'name': 'address_in_l2tp_range', 'ok': True})
    except Exception as exc:
        checks.append({'name': 'address_in_l2tp_range', 'ok': False})
        issues.append(_issue('error', 'ADDRESS_RANGE_INVALID', str(exc)))

    username = str(user.get('username') or '').strip()
    password = str(user.get('password') or '').strip()
    checks.append({'name': 'credentials_present', 'ok': bool(username and password)})
    if not username or not password:
        issues.append(_issue('error', 'CREDENTIALS_MISSING', 'L2TP username or password is missing in store'))

    xl2tpd_up = _service_active(runner, 'xl2tpd')
    ipsec_up = _service_active(runner, 'strongswan-starter') or _service_active(runner, 'ipsec')
    checks.append({'name': 'xl2tpd_active', 'ok': xl2tpd_up})
    checks.append({'name': 'ipsec_active', 'ok': ipsec_up})
    if not xl2tpd_up:
        issues.append(_issue('error', 'XL2TPD_DOWN', 'xl2tpd service is not active'))
    if not ipsec_up:
        issues.append(_issue('warning', 'IPSEC_DOWN', 'strongSwan/ipsec service is not active'))

    sessions = ppp_sessions if ppp_sessions is not None else _collect_ppp_sessions(runner)
    live = sessions.get(host)
    checks.append({'name': 'ppp_session', 'ok': live is not None and live.get('is_up')})
    if live is None:
        issues.append(_issue('warning', 'NOT_ONLINE', f'No active PPP session for [{host}]'))
    elif not live.get('is_up'):
        issues.append(_issue('warning', 'PPP_DOWN', f'PPP interface [{live.get("interface")}] is down'))

    exit_iface = str(user.get('exit_interface') or '').strip() or None
    routing: dict[str, Any] = {'exit_interface': exit_iface}
    if exit_iface:
        exit_link = _iface_link(runner, exit_iface)
        routing['exit_link'] = exit_link
        nat = _nat_status(runner, exit_iface)
        routing['nat'] = nat
        checks.append({'name': 'exit_nat', 'ok': bool(nat.get('masquerade'))})
        if not nat.get('masquerade'):
            issues.append(
                _issue('error', 'NAT_MISSING', f'No MASQUERADE for exit interface [{exit_iface}]')
            )

    ip_forward = _read_sysctl('/proc/sys/net/ipv4/ip_forward')
    checks.append({'name': 'ip_forward', 'ok': ip_forward == '1'})
    if ip_forward != '1':
        issues.append(_issue('error', 'IP_FORWARD_DISABLED', 'net.ipv4.ip_forward is not enabled'))

    linked = str(user.get('linked_peer_id') or '').strip()
    if linked:
        checks.append({'name': 'linked_peer_id', 'ok': True, 'linked_peer_id': linked})

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')

    return {
        'core': core,
        'address': host,
        'server': server,
        'user': {
            'id': user.get('id'),
            'email': user.get('email'),
            'username': username,
            'address': user.get('address'),
            'linked_peer_id': user.get('linked_peer_id'),
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
    ppp_sessions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    execute = runner or run
    host = normalize_peer_host(address)
    if not host:
        raise ValueError('address is required')

    try:
        import ipaddress

        ip = ipaddress.ip_address(host)
        if not is_l2tp_host(ip):
            issue = _issue(
                'error',
                'ADDRESS_NOT_L2TP_RANGE',
                f'Address [{host}] is not in the L2TP slice (third octet >= 128)',
            )
            return {
                'success': True,
                'found': False,
                'core': core,
                'address': host,
                'matches': [],
                'issues': [issue],
                'summary': {'healthy': False, 'issue_count': 1, 'warning_count': 0, 'match_count': 0},
            }
    except ValueError:
        pass

    rows = find_users_by_address(store, core, host)
    if not rows:
        issue = _issue('error', 'USER_NOT_FOUND', f'No L2TP user with address [{host}] in store')
        return {
            'success': True,
            'found': False,
            'core': core,
            'address': host,
            'matches': [],
            'issues': [issue],
            'summary': {'healthy': False, 'issue_count': 1, 'warning_count': 0, 'match_count': 0},
        }

    sessions = ppp_sessions
    if sessions is None:
        sessions = _collect_ppp_sessions(execute)

    matches = [
        diagnose_user_match(
            core=core,
            host=host,
            server=row['server'],
            user=row['user'],
            runner=execute,
            ppp_sessions=sessions,
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
