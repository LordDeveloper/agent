from __future__ import annotations

import ipaddress
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.support import record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.asyncutil import gather_independent, maybe_await
from agent.support.peer_egress import (
    device_from_route_text,
    nft_has_peer_snat,
    peer_source_cidr,
    public_exit_ipv4,
    rule_pref_for_addr,
    table_id_for_interface,
)
from agent.support.process import run_dump

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


async def find_peers_by_address(store: Store, core: str, address: str) -> list[dict[str, Any]]:
    host = normalize_peer_host(address)
    if not host:
        return []

    rows: list[dict[str, Any]] = []
    for iface in await store.list_docs(core, _IFACE_KIND):
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


async def _run_cmd(runner: Runner | None, args: list[str], *, timeout: float = 10.0) -> dict[str, Any]:
    return await run_dump(runner, args, timeout=timeout)


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


async def _ip_rules_for_source(runner: Runner | None, cidr: str) -> list[dict[str, Any]]:
    host = normalize_peer_host(cidr)
    dump = await _run_cmd(runner, ['ip', '-j', 'rule'])
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

    text_dump = await _run_cmd(runner, ['ip', 'rule', 'show'])
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


async def _route_table(runner: Runner | None, table: int | str) -> list[str]:
    dump = await _run_cmd(runner, ['ip', '-4', 'route', 'show', 'table', str(table)])
    if not dump['ok']:
        return []
    return [line.strip() for line in dump['stdout'].splitlines() if line.strip()]


async def _route_lookup_from(
    runner: Runner | None,
    dest: str,
    source: str,
    iif: str | None,
) -> dict[str, Any]:
    args = ['ip', 'route', 'get', dest, 'from', source]
    if iif:
        args.extend(['iif', iif])
    dump = await _run_cmd(runner, args)
    return {'ok': dump['ok'], 'raw': dump['stdout'].strip()}


async def _iface_link(runner: Runner | None, name: str) -> dict[str, Any]:
    dump = await _run_cmd(runner, ['ip', '-j', 'link', 'show', name])
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

    text_dump = await _run_cmd(runner, ['ip', 'link', 'show', name])
    raw = text_dump.get('stdout', '')
    is_up = 'state UP' in raw or ',UP,' in raw or '<UP,' in raw
    return {'name': name, 'is_up': is_up, 'state': 'UP' if is_up else 'DOWN', 'raw': raw.strip()}


async def _check_peer_snat(
    runner: Runner | None,
    cidr: str,
    value: Any,
    checks: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    routing: dict[str, Any],
) -> None:
    address = public_exit_ipv4(value)
    if not address:
        return

    found = False
    if shutil.which('nft'):
        dump = await _run_cmd(runner, ['nft', 'list', 'ruleset'])
        found = nft_has_peer_snat(dump['stdout'], cidr, address)

    for binary in ('iptables', 'iptables-legacy'):
        if found or not shutil.which(binary):
            continue
        dump = await _run_cmd(runner, [binary, '-t', 'nat', '-S', 'POSTROUTING'])
        src = re.escape(cidr.split('/', 1)[0])
        dst = re.escape(address)
        pattern = rf"^-A POSTROUTING .*?-s {src}(?:/32)? .*?-j SNAT --to-source {dst}(?:\s|$)"
        found = re.search(pattern, dump['stdout'], re.MULTILINE) is not None

    routing['exit_ipv4'] = address
    routing['snat'] = {'source': cidr, 'to': address, 'present': found}
    checks.append({'name': 'exit_snat', 'ok': found, 'source': cidr, 'to': address})
    if not found:
        issues.append(_issue('error', 'SNAT_MISSING', f'No SNAT rule found for {cidr} to {address}'))


async def _nat_status(runner: Runner | None, iface: str) -> dict[str, Any]:
    comment = f'{_MASQ_PREFIX}{iface}'
    if shutil.which('nft'):
        dump = await _run_cmd(runner, ['nft', 'list', 'table', 'inet', 'netinja_egress'])
        if not dump['ok']:
            dump = await _run_cmd(runner, ['nft', 'list', 'ruleset'])
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
        dump = await _run_cmd(runner, [cmd, '-t', 'nat', '-S', 'POSTROUTING'])
        text = dump.get('stdout', '')
        masq = f'-o {iface}' in text and 'MASQUERADE' in text
        details = f'{cmd} POSTROUTING MASQUERADE with comment {comment}' if comment in text else (
            f'{cmd} POSTROUTING MASQUERADE (no comment)' if masq else ''
        )
        return {'backend': cmd, 'masquerade': masq, 'details': details}

    return {'backend': None, 'masquerade': False, 'details': ''}


def _iface_token(line: str, iface: str) -> bool:
    if not iface:
        return False
    return re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(iface)}(?![A-Za-z0-9_.-])', line) is not None


def _line_direction(line: str, iface: str, *, incoming: bool) -> bool:
    if not _iface_token(line, iface):
        return False
    if incoming:
        return (
            f'iifname "{iface}"' in line
            or f'iifname {iface}' in line
            or f'-i {iface}' in line
        )
    return (
        f'oifname "{iface}"' in line
        or f'oifname {iface}' in line
        or f'-o {iface}' in line
    )


def _firewall_covers_main_table(text: str, egress: str, tunnel: str) -> dict[str, bool]:
    """True when the dumped rules NAT egress and accept both directions.

    A route lookup is not enough: the decrypted packet still has to be forwarded
    and, when the source is a tunnel address, translated on the way out.
    """
    nat = False
    forward = False
    returning = False
    for raw in str(text or '').splitlines():
        line = raw.strip()
        lower = line.lower()
        if not line or line.startswith('#') or line.startswith('table ') or line.startswith('chain '):
            continue
        if egress and _line_direction(line, egress, incoming=False) and (
            'masquerade' in lower or 'MASQUERADE' in line
        ):
            nat = True
        if tunnel and 'accept' in lower and _line_direction(line, tunnel, incoming=True):
            forward = True
        if tunnel and 'accept' in lower and _line_direction(line, tunnel, incoming=False):
            returning = True
        if egress and 'accept' in lower and _line_direction(line, egress, incoming=False):
            forward = True
        if (
            egress
            and 'accept' in lower
            and _line_direction(line, egress, incoming=True)
            and 'established' in lower
        ):
            returning = True
    return {'nat': nat, 'forward': forward, 'return': returning}


async def _firewall_text(runner: Runner | None) -> tuple[str, str | None]:
    if shutil.which('nft'):
        dump = await _run_cmd(runner, ['nft', 'list', 'table', 'inet', 'netinja_egress'])
        if not dump['ok']:
            dump = await _run_cmd(runner, ['nft', 'list', 'ruleset'])
        return str(dump.get('stdout') or ''), 'nft'
    for cmd in ('iptables', 'iptables-legacy'):
        if not shutil.which(cmd):
            continue
        nat = await _run_cmd(runner, [cmd, '-t', 'nat', '-S', 'POSTROUTING'])
        forward = await _run_cmd(runner, [cmd, '-S', 'FORWARD'])
        return f"{nat.get('stdout') or ''}\n{forward.get('stdout') or ''}", cmd
    return '', None


async def _live_forward_observed(runner: Runner | None, host: str) -> bool:
    """True only when conntrack has seen a reply for this peer, not merely a route."""
    if not host or not shutil.which('conntrack'):
        return False
    dump = await _run_cmd(runner, ['conntrack', '-L', '-s', host])
    text = str(dump.get('stdout') or '')
    for line in text.splitlines():
        if host not in line:
            continue
        if 'ESTABLISHED' in line or 'ASSURED' in line:
            return True
    return False


def _path_verification(
    *,
    route_lookup: bool,
    firewall_checked: bool,
    live: bool,
    summary: str,
) -> dict[str, Any]:
    if live:
        scope = 'live_traffic'
    elif firewall_checked:
        scope = 'firewall_rules'
    else:
        scope = 'route_lookup'
    return {
        'route_lookup_performed': route_lookup,
        'route_lookup_only': not firewall_checked and not live,
        'firewall_rules_checked': firewall_checked,
        'live_traffic_observed': live,
        'scope': scope,
        'summary': summary,
    }


def _issue(level: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {'level': level, 'code': code, 'message': message}
    row.update(extra)
    return row


async def diagnose_peer_match(
    *,
    core: str,
    host: str,
    cidr: str,
    iface: dict[str, Any],
    peer: dict[str, Any],
    runner: Runner | None,
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

    wg_up = await maybe_await(interface_is_up_fn(iface_name)) if interface_is_up_fn and iface_name else None
    if wg_up is False:
        issues.append(
            _issue('error', 'INTERFACE_DOWN', f'WireGuard interface [{iface_name}] is not up')
        )
    checks.append({'name': 'interface_up', 'ok': wg_up is not False, 'interface': iface_name})

    live_peers: dict[str, dict[str, Any]] = {}
    live_iface: dict[str, Any] | None = None
    if peer_dump_fn and iface_name:
        live_peers = await maybe_await(peer_dump_fn(iface_name)) or {}
    elif iface_name and shutil.which('wg'):
        dump = await _run_cmd(runner, ['wg', 'show', iface_name, 'dump'])
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
    ip_rules = await _ip_rules_for_source(runner, cidr)
    routing: dict[str, Any] = {
        'exit_interface': exit_iface,
        'cidr': cidr,
        'expected_table': expected_table,
        'expected_rule_pref': expected_pref,
        'ip_rules': ip_rules,
        'policy_route': None,
        'simulated_egress': None,
    }

    await _check_peer_snat(runner, cidr, peer.get('exit_ipv4'), checks, issues, routing)

    if exit_iface:
        exit_link = await _iface_link(runner, exit_iface)
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
        routes = await _route_table(runner, table)
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

        nat = await _nat_status(runner, exit_iface)
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

        routing['simulated_egress'] = await _route_lookup_from(runner, '1.1.1.1', host, iface_name or None)
        observed = await _live_forward_observed(runner, host)
        routing['path_verification'] = _path_verification(
            route_lookup=True,
            firewall_checked=True,
            live=observed,
            summary=(
                'Policy routing and the NAT rule were checked, and conntrack shows an established flow for this peer.'
                if observed
                else 'Policy routing and the NAT rule were checked. Live forwarded traffic was not observed; '
                'the route lookup alone does not prove packets leave the host.'
            ),
        )
    else:
        issues.append(
            _issue(
                'warning',
                'EXIT_INTERFACE_UNSET',
                'Peer has no exit_interface. Traffic stays on the main routing table and still needs '
                'FORWARD plus SNAT on the live default device.',
            )
        )
        routing['simulated_egress'] = await _route_lookup_from(runner, '1.1.1.1', host, iface_name or None)
        egress = device_from_route_text(str((routing['simulated_egress'] or {}).get('raw') or ''))
        if egress and iface_name and egress == iface_name:
            egress = None
        routing['main_egress'] = egress
        observed = await _live_forward_observed(runner, host)
        if not egress:
            routing['path_verification'] = _path_verification(
                route_lookup=True,
                firewall_checked=False,
                live=observed,
                summary=(
                    'Only an ip route lookup was performed. It did not name an egress device, so NAT and FORWARD were not checked.'
                    if not observed
                    else 'Conntrack shows an established flow. The route lookup did not name an egress device, so the firewall rules were not checked.'
                ),
            )
            if not observed:
                issues.append(
                    _issue(
                        'warning',
                        'EGRESS_PATH_UNVERIFIED',
                        'Route lookup did not identify an egress device. NAT and FORWARD were not verified.',
                    )
                )
        else:
            text, backend = await _firewall_text(runner)
            covered = _firewall_covers_main_table(text, egress, iface_name)
            routing['nat'] = {
                'backend': backend,
                'masquerade': covered['nat'],
                'details': f'{backend} masquerade for {egress}' if covered['nat'] and backend else '',
            }
            routing['forward'] = {
                'backend': backend,
                'from_tunnel': covered['forward'],
                'established_return': covered['return'],
            }
            checks.append({'name': 'exit_nat', 'ok': covered['nat'], 'interface': egress})
            checks.append({'name': 'forward_out', 'ok': covered['forward'], 'interface': egress})
            checks.append({'name': 'forward_return', 'ok': covered['return'], 'interface': egress})
            if not covered['nat']:
                issues.append(
                    _issue(
                        'error',
                        'NAT_MISSING',
                        f'No MASQUERADE rule for main-table egress [{egress}]. '
                        'Decrypted WireGuard packets keep their tunnel source and replies never return.',
                        interface=egress,
                    )
                )
            if not covered['forward']:
                issues.append(
                    _issue(
                        'error',
                        'FORWARD_MISSING',
                        f'No FORWARD accept from the tunnel toward egress [{egress}].',
                        interface=egress,
                    )
                )
            if not covered['return']:
                issues.append(
                    _issue(
                        'error',
                        'RETURN_PATH_MISSING',
                        f'No ESTABLISHED return rule from [{egress}] back toward the tunnel.',
                        interface=egress,
                    )
                )
            routing['path_verification'] = _path_verification(
                route_lookup=True,
                firewall_checked=True,
                live=observed,
                summary=(
                    'NAT, FORWARD, and the established return path were checked, and conntrack shows an established flow.'
                    if observed
                    else 'NAT, FORWARD, and the established return path were checked against the firewall rules. '
                    'That is not the same as observing a live packet; conntrack had no established flow for this peer.'
                ),
            )

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
    from agent.support.bandwidth import diagnose_bandwidth

    bandwidth = await diagnose_bandwidth(peer, interface=iface_name or None, kind='tunnel')
    rule_check = next((row for row in checks if row.get('name') == 'ip_rule_present'), None)
    from agent.support.egress_tasks import describe_routing

    routing.update(describe_routing(
        peer.get('id'),
        verified=None if rule_check is None else bool(rule_check.get('ok')),
    ))

    return {
        'core': core,
        'address': host,
        'cidr': cidr,
        'interface': iface,
        'bandwidth': bandwidth,
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


async def diagnose_peer_address(
    store: Store,
    core: str,
    address: str,
    *,
    runner: Runner | None = None,
    peer_dump_fn: Callable[[str], dict[str, dict[str, Any]]] | None = None,
    interface_is_up_fn: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    host = normalize_peer_host(address)
    if not host:
        raise ValueError('address is required')

    cidr = peer_source_cidr(address) or f'{host}/32'
    rows = await find_peers_by_address(store, core, host)
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

    matches = await gather_independent(
        *(
            diagnose_peer_match(
                core=core,
                host=host,
                cidr=cidr,
                iface=row['interface'],
                peer=row['peer'],
                runner=runner,
                peer_dump_fn=peer_dump_fn,
                interface_is_up_fn=interface_is_up_fn,
            )
            for row in rows
        )
    )

    for match, row in zip(matches, rows):
        companion = await _find_l2tp_companion(store, row.get('peer') or {})
        if companion is not None:
            match['l2tp_companion'] = companion
            if companion.get('found'):
                match.setdefault('checks', []).append(
                    {
                        'name': 'l2tp_companion',
                        'ok': True,
                        'linked_peer_id': companion.get('linked_peer_id'),
                        'l2tp_address': companion.get('address'),
                        'exit_interface': companion.get('exit_interface'),
                    }
                )

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


async def _find_l2tp_companion(store: Store, peer: dict[str, Any]) -> dict[str, Any] | None:
    """Attach L2TP companion summary when diagnosing a WireGuard/Amnezia peer."""
    peer_id = str(peer.get('id') or '').strip()
    peer_email = str(peer.get('email') or '').strip()
    if not peer_id and not peer_email:
        return None

    try:
        from agent.support.l2tp_diagnose import find_users_by_linked_peer_id
    except Exception:
        return None

    for key in (peer_id, peer_email):
        if not key:
            continue
        rows = await find_users_by_linked_peer_id(store, 'l2tp', key)
        if not rows:
            continue
        row = rows[0]
        user = row.get('user') or {}
        server = row.get('server') or {}
        return {
            'found': True,
            'id': user.get('id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'address': normalize_peer_host(user.get('address')),
            'linked_peer_id': user.get('linked_peer_id') or key,
            'exit_interface': user.get('exit_interface'),
            'is_enabled': record_is_enabled(user),
            'online': bool(user.get('online')),
            'server_id': server.get('id'),
            'server_name': server.get('name'),
            'server_subnet': server.get('subnet'),
        }

    return None
