from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.support import record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.support.l2tp_ip import assert_l2tp_address, is_l2tp_host, matching_l2tp_subnet
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
_IFACE_KIND = 'interface'
_ONLINE_SECONDS = 180
_PEER_CORES = ('wireguard', 'amnezia')


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


def find_users_by_linked_peer_id(store: Store, core: str, linked_peer_id: str) -> list[dict[str, Any]]:
    linked = str(linked_peer_id or '').strip()
    if not linked:
        return []

    rows: list[dict[str, Any]] = []
    for server in store.list_docs(core, _SERVER_KIND):
        for user in server.get('users') or []:
            if not isinstance(user, dict):
                continue
            if str(user.get('linked_peer_id') or '').strip() != linked:
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


def find_linked_peer(store: Store, linked_peer_id: str) -> dict[str, Any] | None:
    """Resolve WireGuard/Amnezia peer referenced by L2TP companion linked_peer_id."""
    linked = str(linked_peer_id or '').strip()
    if not linked:
        return None

    for peer_core in _PEER_CORES:
        for iface in store.list_docs(peer_core, _IFACE_KIND):
            if not isinstance(iface, dict):
                continue
            for peer in iface.get('peers') or []:
                if not isinstance(peer, dict):
                    continue
                peer_id = str(peer.get('id') or '').strip()
                peer_email = str(peer.get('email') or '').strip()
                if linked not in {peer_id, peer_email}:
                    continue
                return {
                    'core': peer_core,
                    'found': True,
                    'id': peer_id,
                    'email': peer_email,
                    'address': normalize_peer_host(peer.get('address')),
                    'allowed_ips': peer.get('allowed_ips'),
                    'public_key': peer.get('public_key'),
                    'exit_interface': peer.get('exit_interface'),
                    'is_enabled': record_is_enabled(peer),
                    'online': bool(peer.get('online')),
                    'incoming': peer.get('incoming'),
                    'outgoing': peer.get('outgoing'),
                    'interface': {
                        'id': iface.get('id'),
                        'name': iface.get('name'),
                        'listen_port': iface.get('listen_port'),
                        'subnet': iface.get('subnet'),
                    },
                }

    return {
        'found': False,
        'id': linked,
        'core': None,
        'address': None,
        'exit_interface': None,
        'is_enabled': None,
        'online': None,
        'interface': None,
    }


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
        flags = {str(flag).upper() for flag in (iface.get('flags') or [])}
        # PPP often reports operstate UNKNOWN while the session is fully usable.
        is_up = operstate == 'UP' or 'UP' in flags or operstate in {'UNKNOWN', ''}
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
        # Only mark online when we actually have a peer address (session negotiated).
        if not is_up and client_ip:
            is_up = True
        sessions[client_ip] = {
            'interface': ifname,
            'operstate': operstate or 'UNKNOWN',
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
    store: Store | None = None,
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
    sibling_subnets: list[str] = []
    if store is not None:
        for row in store.list_docs(core, _SERVER_KIND):
            raw = str((row or {}).get('subnet') or '').strip()
            if raw:
                sibling_subnets.append(raw)
    if subnet and subnet not in sibling_subnets:
        sibling_subnets.insert(0, subnet)

    try:
        assert_l2tp_address(subnet, host)
        checks.append({'name': 'address_in_l2tp_range', 'ok': True, 'subnet': subnet})
    except Exception as exc:
        matched = matching_l2tp_subnet(host, sibling_subnets)
        l2tp_shaped = False
        try:
            l2tp_shaped = is_l2tp_host(ipaddress.ip_address(host))
        except ValueError:
            l2tp_shaped = False
        if matched:
            checks.append(
                {
                    'name': 'address_in_l2tp_range',
                    'ok': True,
                    'subnet': matched,
                    'server_subnet': subnet,
                }
            )
            issues.append(
                _issue(
                    'warning',
                    'ADDRESS_SUBNET_DRIFT',
                    f'L2TP address [{host}] is in [{matched}] but server subnet is [{subnet}]',
                    address=host,
                    server_subnet=subnet,
                    matched_subnet=matched,
                )
            )
        elif l2tp_shaped:
            checks.append({'name': 'address_in_l2tp_range', 'ok': True, 'subnet': None})
            issues.append(
                _issue(
                    'warning',
                    'ADDRESS_SUBNET_DRIFT',
                    f'L2TP address [{host}] is a valid L2TP host but outside server subnet [{subnet}]',
                    address=host,
                    server_subnet=subnet,
                )
            )
        else:
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

    try:
        from agent.ops import charon_ctl_ready, stroke_plugin_present

        stroke_ok = stroke_plugin_present()
        ctl_ok = charon_ctl_ready()
    except Exception:
        stroke_ok = False
        ctl_ok = False
    checks.append({'name': 'ipsec_stroke_plugin', 'ok': stroke_ok})
    checks.append({'name': 'ipsec_charon_ctl', 'ok': ctl_ok})
    if not stroke_ok:
        issues.append(
            _issue(
                'error',
                'IPSEC_STROKE_MISSING',
                'strongSwan stroke plugin missing — ipsec.conf never loads (NO_PROP for all clients)',
            )
        )
    elif not ctl_ok:
        issues.append(
            _issue(
                'error',
                'IPSEC_CHARON_CTL_MISSING',
                '/var/run/charon.ctl missing — starter cannot load L2TP-PSK; restart strongswan after installing libcharon-extra-plugins',
            )
        )

    sessions = ppp_sessions if ppp_sessions is not None else _collect_ppp_sessions(runner)
    live = sessions.get(host)
    checks.append({'name': 'ppp_session', 'ok': live is not None and live.get('is_up')})
    if live is None:
        issues.append(_issue('warning', 'NOT_ONLINE', f'No active PPP session for [{host}]'))
    elif not live.get('is_up'):
        issues.append(_issue('warning', 'PPP_DOWN', f'PPP interface [{live.get("interface")}] is down'))

    linked = str(user.get('linked_peer_id') or '').strip()
    linked_peer: dict[str, Any] | None = None
    if linked and store is not None:
        linked_peer = find_linked_peer(store, linked)
        found = bool(linked_peer and linked_peer.get('found'))
        checks.append(
            {
                'name': 'linked_peer_found',
                'ok': found,
                'linked_peer_id': linked,
                'linked_core': (linked_peer or {}).get('core'),
                'linked_address': (linked_peer or {}).get('address'),
            }
        )
        if not found:
            issues.append(
                _issue(
                    'error',
                    'LINKED_PEER_MISSING',
                    f'No WireGuard/Amnezia peer with id/email [{linked}]',
                    linked_peer_id=linked,
                )
            )
    elif linked:
        checks.append({'name': 'linked_peer_id', 'ok': True, 'linked_peer_id': linked})
    else:
        checks.append({'name': 'linked_peer_id', 'ok': True, 'linked_peer_id': None})

    cidr = peer_source_cidr(user.get('address')) or f'{host}/32'
    exit_iface = str(user.get('exit_interface') or '').strip() or None
    linked_exit = None
    if isinstance(linked_peer, dict) and linked_peer.get('found'):
        linked_exit = str(linked_peer.get('exit_interface') or '').strip() or None
        if linked_exit and not exit_iface:
            exit_iface = linked_exit

    expected_table = table_id_for_interface(exit_iface) if exit_iface else None
    expected_pref = rule_pref_for_addr(host)
    ip_rules = _ip_rules_for_source(runner, cidr)
    routing: dict[str, Any] = {
        'exit_interface': exit_iface,
        'linked_exit_interface': linked_exit,
        'exit_matches_linked': (
            (exit_iface == linked_exit)
            if (exit_iface and linked_exit)
            else None
        ),
        'cidr': cidr,
        'expected_table': expected_table,
        'expected_rule_pref': expected_pref,
        'ip_rules': ip_rules,
        'policy_route': None,
        'simulated_egress': None,
    }

    if linked_exit and exit_iface and exit_iface != linked_exit:
        checks.append({'name': 'exit_matches_linked', 'ok': False})
        issues.append(
            _issue(
                'warning',
                'EXIT_MISMATCH_LINKED',
                f'L2TP exit [{exit_iface}] differs from linked peer exit [{linked_exit}]',
                l2tp_exit=exit_iface,
                linked_exit=linked_exit,
            )
        )
    elif linked_exit and exit_iface:
        checks.append({'name': 'exit_matches_linked', 'ok': True})

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

        ppp_if = str((live or {}).get('interface') or '').strip() or None
        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, ppp_if)
    else:
        issues.append(
            _issue(
                'warning',
                'EXIT_INTERFACE_UNSET',
                'L2TP user has no exit_interface — traffic uses main routing table only',
            )
        )
        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, None)

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
            'linked_peer_id': linked or user.get('linked_peer_id'),
            'exit_interface': exit_iface,
            'is_enabled': enabled,
            'online': user.get('online'),
            'incoming': user.get('incoming'),
            'outgoing': user.get('outgoing'),
        },
        'linked_peer': linked_peer,
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
            store=store,
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
