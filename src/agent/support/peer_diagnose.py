from __future__ import annotations

import ipaddress
import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.support import record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.support.peer_egress import peer_source_cidr, rule_pref_for_addr, table_id_for_interface
from agent.support.process import run

Runner = Callable[..., Any]

_ONLINE_HANDSHAKE_SECONDS = 180
_IFACE_KIND = 'interface'
_MASQ_PREFIX = 'netinja-egress-'


def normalize_peer_host(value: Any) -> str:
    text = str(value or '').strip()
    if not text:
        return ''
    return text.split('/', 1)[0].strip()


def allowed_ips_cover_host(allowed_ips: str, host: str) -> bool:
    """Return True when host is contained in one of the comma-separated allowed_ips entries."""
    host = normalize_peer_host(host)
    if not host:
        return False
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    for part in str(allowed_ips or '').split(','):
        token = part.strip()
        if not token:
            continue
        try:
            if '/' in token:
                if host_ip in ipaddress.ip_network(token, strict=False):
                    return True
            elif ipaddress.ip_address(token) == host_ip:
                return True
        except ValueError:
            continue

    return False


def allowed_ips_lists_match(store_allowed: str, live_allowed: str, host: str) -> bool:
    store_ok = allowed_ips_cover_host(store_allowed, host)
    live_ok = allowed_ips_cover_host(live_allowed, host)
    if not store_ok or not live_ok:
        return False
    return str(store_allowed or '').strip() == str(live_allowed or '').strip()


def find_peers_by_address(store: Store, core: str, address: str) -> list[dict[str, Any]]:
    host = normalize_peer_host(address)
    if not host:
        return []

    rows: list[dict[str, Any]] = []
    for iface in store.list_docs(core, _IFACE_KIND):
        for peer in iface.get('peers') or []:
            peer_host = normalize_peer_host(peer.get('address'))
            if peer_host != host:
                continue
            rows.append(
                {
                    'interface': {
                        'id': iface.get('id'),
                        'name': iface.get('name'),
                        'listen_port': iface.get('listen_port'),
                        'subnet': iface.get('subnet'),
                        'public_key': iface.get('public_key'),
                    },
                    'peer': peer,
                    'iface_doc': iface,
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

    returncode = int(getattr(result, 'returncode', 1))
    return {
        'ok': returncode == 0,
        'stdout': str(getattr(result, 'stdout', '') or ''),
        'stderr': str(getattr(result, 'stderr', '') or ''),
        'returncode': returncode,
    }


def _read_sysctl(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding='utf-8').strip()
    except OSError:
        return None


def _parse_wg_dump(stdout: str) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """Return (interface_row, peers_by_public_key)."""
    lines = [line for line in str(stdout or '').splitlines() if line.strip()]
    if not lines:
        return None, {}

    iface_row: dict[str, Any] | None = None
    if len(lines[0].split('\t')) >= 2:
        parts = lines[0].split('\t')
        iface_row = {
            'private_key': parts[0],
            'public_key': parts[1],
            'listen_port': parts[2] if len(parts) > 2 else None,
        }

    peers: dict[str, dict[str, Any]] = {}
    now = int(time.time())
    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) < 7:
            continue
        public_key = parts[0]
        allowed_ips = parts[3] if len(parts) > 3 else ''
        endpoint = parts[2] if len(parts) > 2 else ''
        try:
            handshake_at = int(parts[4] or 0)
            transfer_rx = int(parts[5] or 0)
            transfer_tx = int(parts[6] or 0)
        except ValueError:
            continue

        seconds_since = (now - handshake_at) if handshake_at > 0 else None
        peers[public_key] = {
            'public_key': public_key,
            'allowed_ips': allowed_ips,
            'endpoint': endpoint,
            'handshake_at': handshake_at,
            'transfer_rx': transfer_rx,
            'transfer_tx': transfer_tx,
            'seconds_since_handshake': seconds_since,
            'online': handshake_at > 0 and (now - handshake_at) < _ONLINE_HANDSHAKE_SECONDS,
        }
    return iface_row, peers


def _ip_rules_for_source(runner: Runner, cidr: str) -> list[dict[str, Any]]:
    host = normalize_peer_host(cidr)
    dump = _run_cmd(runner, ['ip', '-j', 'rule'])
    rows: list[dict[str, Any]] = []
    if dump['ok'] and dump['stdout'].strip():
        try:
            parsed = json.loads(dump['stdout'])
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            for row in parsed:
                if not isinstance(row, dict):
                    continue
                src = str(row.get('src') or row.get('from') or '').strip()
                if host and src and host not in src and src not in cidr:
                    continue
                rows.append(
                    {
                        'src': src or host,
                        'table': row.get('table') or row.get('lookup'),
                        'pref': row.get('pref') or row.get('priority'),
                        'raw': json.dumps(row, ensure_ascii=False),
                    }
                )
            if rows:
                return rows

    text_dump = _run_cmd(runner, ['ip', 'rule', 'show'])
    for line in text_dump.get('stdout', '').splitlines():
        raw = line.strip()
        if not raw or host not in raw:
            continue
        table = None
        pref = None
        if 'lookup' in raw:
            table = raw.split('lookup', 1)[1].strip().split()[0]
        if 'pref' in raw:
            try:
                pref = int(raw.split('pref', 1)[1].strip().split()[0])
            except (IndexError, ValueError):
                pref = None
        rows.append({'src': host, 'table': table, 'pref': pref, 'raw': raw})
    return rows


def _route_table(runner: Runner, table: int | str) -> list[str]:
    dump = _run_cmd(runner, ['ip', '-4', 'route', 'show', 'table', str(table)])
    if not dump['ok']:
        return []
    return [line.strip() for line in dump['stdout'].splitlines() if line.strip()]


def _route_lookup_from(
    runner: Runner,
    dest: str,
    source: str,
    iif: str | None,
) -> dict[str, Any]:
    args = ['ip', 'route', 'get', dest, 'from', source]
    if iif:
        args.extend(['iif', iif])
    dump = _run_cmd(runner, args)
    return {'ok': dump['ok'], 'raw': dump['stdout'].strip()}


def _iface_link(runner: Runner, name: str) -> dict[str, Any]:
    dump = _run_cmd(runner, ['ip', '-j', 'link', 'show', name])
    if dump['ok'] and dump['stdout'].strip():
        try:
            rows = json.loads(dump['stdout'])
        except json.JSONDecodeError:
            rows = []
        row = rows[0] if isinstance(rows, list) and rows else {}
        flags = {str(flag) for flag in (row.get('flags') or [])}
        operstate = str(row.get('operstate') or '').upper()
        is_up = operstate == 'UP' or 'UP' in flags
        return {
            'name': name,
            'operstate': operstate,
            'flags': sorted(flags),
            'is_up': is_up,
            'state': 'UP' if is_up else operstate or 'DOWN',
        }

    text_dump = _run_cmd(runner, ['ip', 'link', 'show', name])
    raw = text_dump.get('stdout', '')
    is_up = 'state UP' in raw or ',UP,' in raw or '<UP,' in raw
    return {'name': name, 'is_up': is_up, 'state': 'UP' if is_up else 'DOWN', 'raw': raw.strip()}


def _nat_status(runner: Runner, iface: str) -> dict[str, Any]:
    comment = f'{_MASQ_PREFIX}{iface}'
    if shutil.which('nft'):
        dump = _run_cmd(runner, ['nft', 'list', 'table', 'inet', 'netinja_egress'])
        if not dump['ok']:
            dump = _run_cmd(runner, ['nft', 'list', 'ruleset'])
        text = dump.get('stdout', '')
        patterns = (
            f'oifname "{iface}" masquerade',
            f'oifname {iface} masquerade',
            comment,
        )
        masq = any(pattern in text for pattern in patterns)
        return {
            'backend': 'nft',
            'masquerade': masq,
            'details': 'netinja_egress postrouting masquerade present' if masq else '',
        }

    for cmd in ('iptables', 'iptables-legacy'):
        if not shutil.which(cmd):
            continue
        dump = _run_cmd(runner, [cmd, '-t', 'nat', '-S', 'POSTROUTING'])
        text = dump.get('stdout', '')
        masq = f'-o {iface}' in text and 'MASQUERADE' in text
        details = f'{cmd} POSTROUTING MASQUERADE with comment {comment}' if comment in text else (
            f'{cmd} POSTROUTING MASQUERADE (no comment)' if masq else ''
        )
        return {'backend': cmd, 'masquerade': masq, 'details': details}

    return {'backend': None, 'masquerade': False, 'details': ''}


def _issue(level: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {'level': level, 'code': code, 'message': message}
    row.update(extra)
    return row


def diagnose_peer_match(
    *,
    core: str,
    host: str,
    cidr: str,
    iface: dict[str, Any],
    peer: dict[str, Any],
    runner: Runner,
    peer_dump_fn: Callable[[str], dict[str, dict[str, Any]]] | None = None,
    interface_is_up_fn: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    iface_name = str(iface.get('name') or '').strip()
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    enabled = record_is_enabled(peer)
    checks.append({'name': 'peer_enabled', 'ok': enabled})
    if not enabled:
        issues.append(
            _issue(
                'error',
                'PEER_DISABLED',
                explain_disabled(peer),
                disabled_reason=peer.get('disabled_reason'),
                disabled_at=peer.get('disabled_at'),
                disabled_detail=peer.get('disabled_detail'),
            )
        )

    wg_up = interface_is_up_fn(iface_name) if interface_is_up_fn and iface_name else None
    if wg_up is False:
        issues.append(
            _issue('error', 'INTERFACE_DOWN', f'WireGuard interface [{iface_name}] is not up')
        )
    checks.append({'name': 'interface_up', 'ok': wg_up is not False, 'interface': iface_name})

    live_peers: dict[str, dict[str, Any]] = {}
    live_iface: dict[str, Any] | None = None
    if peer_dump_fn and iface_name:
        live_peers = peer_dump_fn(iface_name) or {}
    elif iface_name and shutil.which('wg'):
        dump = _run_cmd(runner, ['wg', 'show', iface_name, 'dump'])
        if dump['ok']:
            live_iface, parsed = _parse_wg_dump(dump['stdout'])
            live_peers = parsed

    pub = str(peer.get('public_key') or '').strip()
    live = live_peers.get(pub) if pub else None
    if pub and live is None:
        for candidate in live_peers.values():
            allowed = str(candidate.get('allowed_ips') or '')
            if allowed_ips_cover_host(allowed, host):
                live = candidate
                break

    checks.append({'name': 'peer_in_live_wg', 'ok': live is not None})
    if live is None:
        issues.append(
            _issue(
                'error',
                'PEER_NOT_IN_LIVE_WG',
                f'Peer public key not present on live interface [{iface_name}]',
                public_key=(pub[:16] + '...') if pub else None,
            )
        )
    else:
        store_allowed = str(peer.get('allowed_ips') or f'{host}/32')
        live_allowed = str(live.get('allowed_ips') or '')
        live_pub = str(live.get('public_key') or '').strip()
        allowed_ok = allowed_ips_lists_match(store_allowed, live_allowed, host)
        checks.append(
            {
                'name': 'allowed_ips_match',
                'ok': allowed_ok,
                'store': store_allowed,
                'live': live_allowed,
            }
        )
        if not allowed_ok:
            issues.append(
                _issue(
                    'warning',
                    'ALLOWED_IPS_MISMATCH',
                    'Store allowed_ips differs from live WireGuard peer',
                    store=store_allowed,
                    live=live_allowed,
                )
            )
        if pub and live_pub and live_pub != pub:
            issues.append(
                _issue(
                    'error',
                    'PEER_KEY_MISMATCH',
                    'Store public_key differs from live WireGuard peer (stale peer on interface?)',
                    store_public_key=(pub[:16] + '...') if pub else None,
                    live_public_key=(live_pub[:16] + '...') if live_pub else None,
                )
            )

        handshake_at = int(live.get('handshake_at') or 0)
        if handshake_at <= 0:
            issues.append(
                _issue('warning', 'NO_HANDSHAKE', 'No recent WireGuard handshake recorded')
            )
        else:
            seconds_ago = live.get('seconds_since_handshake')
            if seconds_ago is None:
                seconds_ago = int(time.time()) - handshake_at
            online = live.get('online')
            if online is None:
                online = int(seconds_ago) < _ONLINE_HANDSHAKE_SECONDS
            live['online'] = online
            live['seconds_since_handshake'] = seconds_ago
            if not online:
                issues.append(
                    _issue(
                        'warning',
                        'STALE_HANDSHAKE',
                        f'Last handshake is older than {_ONLINE_HANDSHAKE_SECONDS} seconds',
                        seconds_since_handshake=seconds_ago,
                    )
                )

    exit_iface = str(peer.get('exit_interface') or '').strip() or None
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
                _issue(
                    'error',
                    'NAT_MISSING',
                    f'No MASQUERADE rule found for exit interface [{exit_iface}]',
                )
            )

        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, iface_name or None)
    else:
        issues.append(
            _issue(
                'warning',
                'EXIT_INTERFACE_UNSET',
                'Peer has no exit_interface — traffic uses main routing table only',
            )
        )
        routing['simulated_egress'] = _route_lookup_from(runner, '1.1.1.1', host, iface_name or None)

    ip_forward = _read_sysctl('/proc/sys/net/ipv4/ip_forward')
    host_info = {
        'ip_forward': ip_forward,
        'ip_forward_enabled': ip_forward == '1',
    }
    checks.append({'name': 'ip_forward', 'ok': host_info['ip_forward_enabled']})
    if ip_forward != '1':
        issues.append(
            _issue('error', 'IP_FORWARD_DISABLED', 'net.ipv4.ip_forward is not enabled')
        )

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')

    return {
        'core': core,
        'address': host,
        'cidr': cidr,
        'interface': iface,
        'peer': {
            'id': peer.get('id'),
            'email': peer.get('email'),
            'address': peer.get('address'),
            'allowed_ips': peer.get('allowed_ips'),
            'public_key': peer.get('public_key'),
            'exit_interface': peer.get('exit_interface'),
            'is_enabled': enabled,
            'online': peer.get('online'),
            'handshake_at': peer.get('handshake_at'),
            'endpoint': peer.get('endpoint'),
            'incoming': peer.get('incoming'),
            'outgoing': peer.get('outgoing'),
        },
        'live': live,
        'live_interface': live_iface,
        'routing': routing,
        'host': host_info,
        'checks': checks,
        'issues': issues,
        'healthy': error_count == 0,
        'issue_counts': {'error': error_count, 'warning': warning_count},
    }


def diagnose_peer_address(
    store: Store,
    core: str,
    address: str,
    *,
    runner: Runner | None = None,
    peer_dump_fn: Callable[[str], dict[str, dict[str, Any]]] | None = None,
    interface_is_up_fn: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    execute = runner or run
    host = normalize_peer_host(address)
    if not host:
        raise ValueError('address is required')

    cidr = peer_source_cidr(address) or f'{host}/32'
    rows = find_peers_by_address(store, core, host)
    if not rows:
        issue = _issue(
            'error',
            'PEER_NOT_FOUND',
            f'No peer with address [{host}] found in {core} store',
        )
        return {
            'success': True,
            'found': False,
            'core': core,
            'address': host,
            'cidr': cidr,
            'matches': [],
            'issues': [issue],
            'summary': {
                'healthy': False,
                'issue_count': 1,
                'warning_count': 0,
                'match_count': 0,
            },
        }

    matches = [
        diagnose_peer_match(
            core=core,
            host=host,
            cidr=cidr,
            iface=row['interface'],
            peer=row['peer'],
            runner=execute,
            peer_dump_fn=peer_dump_fn,
            interface_is_up_fn=interface_is_up_fn,
        )
        for row in rows
    ]

    issue_count = sum(match['issue_counts']['error'] for match in matches)
    warning_count = sum(match['issue_counts']['warning'] for match in matches)
    healthy = issue_count == 0 and all(match.get('healthy') for match in matches)

    return {
        'success': True,
        'found': True,
        'core': core,
        'address': host,
        'cidr': cidr,
        'matches': matches,
        'summary': {
            'healthy': healthy,
            'issue_count': issue_count,
            'warning_count': warning_count,
            'match_count': len(matches),
        },
    }
