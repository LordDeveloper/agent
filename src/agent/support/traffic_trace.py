"""Read-only traffic-path trace for Diagnose.

Configured hops come from stored config. Observed hops come from live
interface, policy-routing, or WireGuard dumps. Kernel route lookups are
labeled separately and are not captured packets or verified exit IPs.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from typing import Any, Callable

from agent.support.client_diagnose import (
    _find_client_in_inbound,
    _find_config_client,
    _find_config_clients_by_key,
)
from agent.support.process import run_dump
from agent.support.routing_test import _as_list, test_routing_rules

_IFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,14}$')
_SECRET_KEYS = {
    'password',
    'passwd',
    'secret',
    'privatekey',
    'private_key',
    'encryptionkey',
    'encryption_key',
    'psk',
    'ipsec_psk',
    'tls_crypt',
    'ca_crt',
}
_CMD_TIMEOUT = 5.0
_MAX_HOPS = 12


def _issue_messages(report: dict[str, Any]) -> list[str]:
    messages: list[str] = []
    for issue in report.get('issues') or []:
        if isinstance(issue, dict) and issue.get('message'):
            messages.append(str(issue['message']))
    return messages


def _summary(found: bool, matches: list[dict[str, Any]], limitations: list[str]) -> dict[str, Any]:
    return {
        'healthy': found and not limitations,
        'issue_count': 0 if found else 1,
        'warning_count': len(limitations),
        'match_count': len(matches),
    }


def _hop(step: int, role: str, basis: str, summary: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        'step': step,
        'role': role,
        'basis': basis,
        'summary': str(summary).strip()[:240],
    }
    for key, value in extra.items():
        if value in (None, '', [], {}):
            continue
        if str(key).lower() in _SECRET_KEYS:
            continue
        row[key] = value
    return row


def _is_global(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split('/')[0])
    except ValueError:
        return False
    return bool(ip.is_global)


def _parse_route_get(raw: str) -> dict[str, str]:
    text = str(raw or '').strip()
    found: dict[str, str] = {}
    for key in ('dev', 'src', 'via', 'table'):
        match = re.search(rf'\b{key}\s+(\S+)', text)
        if match:
            found[key] = match.group(1)
    return found


async def _run(args: list[str]) -> dict[str, Any]:
    if args and not shutil.which(args[0]):
        return {'ok': False, 'stdout': '', 'stderr': f'{args[0]} not available', 'returncode': 127}
    return await run_dump(None, args, timeout=_CMD_TIMEOUT)


async def _observe_iface(name: str) -> dict[str, Any]:
    iface = str(name or '').strip()
    if not iface or not _IFACE_RE.match(iface):
        return {'name': iface, 'available': False, 'detail': 'interface name missing or rejected'}

    result: dict[str, Any] = {'name': iface, 'available': True, 'addresses': [], 'endpoints': []}
    addr = await _run(['ip', '-j', 'addr', 'show', 'dev', iface])
    if not addr['ok']:
        result['available'] = False
        result['detail'] = (addr.get('stderr') or 'ip addr failed').strip()[:180]
        return result

    try:
        rows = json.loads(addr.get('stdout') or '[]')
    except json.JSONDecodeError:
        rows = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            for item in row.get('addr_info') or []:
                if not isinstance(item, dict):
                    continue
                local = str(item.get('local') or '').strip()
                if local:
                    result['addresses'].append(local)

    wg = await _run(['wg', 'show', iface, 'dump'])
    if wg['ok']:
        endpoints: list[str] = []
        for line in str(wg.get('stdout') or '').splitlines()[1:]:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            endpoint = str(parts[2] or '').strip()
            if endpoint and endpoint != '(none)':
                endpoints.append(endpoint)
        result['endpoints'] = list(dict.fromkeys(endpoints))[:6]
    return result


def parse_destination(value: str | None) -> dict[str, Any]:
    """Split an optional ``host``, ``ip``, ``host:port``, or ``[ipv6]:port``."""
    text = str(value or "").strip()
    if not text:
        return {}
    if any(ch.isspace() for ch in text) or len(text) > 253:
        raise ValueError("destination must be a host or ip, optionally with a port")

    host = text
    port: int | None = None
    if text.startswith("["):
        end = text.find("]")
        if end <= 1:
            raise ValueError("destination must be a host or ip, optionally with a port")
        host = text[1:end]
        rest = text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ValueError("destination must be a host or ip, optionally with a port")
            port = _port(rest[1:])
    elif text.count(":") == 1:
        host, _, raw_port = text.partition(":")
        port = _port(raw_port)
    elif text.count(":") > 1:
        host = text

    host = host.strip().rstrip(".")
    if not host or any(ch in host for ch in " /\\\"'`;$|&"):
        raise ValueError("destination must be a host or ip, optionally with a port")

    try:
        ipaddress.ip_address(host)
        parsed: dict[str, Any] = {"ip": host}
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("destination must be a host or ip, optionally with a port")
        parsed = {"domain": host.lower()}
    if port is not None:
        parsed["port"] = port
    return parsed


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("destination port is invalid") from exc
    if port < 1 or port > 65535:
        raise ValueError("destination port is invalid")
    return port


def classify_public_exit(
    *,
    probe_ip: str | None,
    iface_addresses: list[str],
    bound_iface: str | None,
    probe_error: str | None = None,
) -> dict[str, Any]:
    """A verified exit is a probed global address that is not the bound interface itself.

    Host NIC names and addresses configured on the selected interface are never
    reported as a verified public exit.
    """
    iface = str(bound_iface or "").strip()
    ip = str(probe_ip or "").strip()
    configured = set()
    for item in iface_addresses:
        text = str(item or "").split("/")[0].strip()
        if text:
            configured.add(text)

    def unverified(detail: str, **extra: Any) -> dict[str, Any]:
        row: dict[str, Any] = {"ip": None, "basis": "UNVERIFIED", "detail": detail}
        row.update(extra)
        return row

    if not iface:
        return unverified(
            probe_error
            or "No outbound interface is bound. The host default route is not a verified exit."
        )
    if iface == "eth0" or iface.startswith(("eth", "ens", "eno", "enp")):
        shown = f" Probe returned {ip}." if ip else ""
        return unverified(
            f"Interface [{iface}] is a host NIC, not a remote exit.{shown} Reported as UNVERIFIED.",
            probe_ip=ip or None,
        )
    if not ip:
        return unverified(probe_error or f"Public-IP probe through [{iface}] failed.")
    if not _is_global(ip):
        return unverified(f"Probe through [{iface}] returned non-global address {ip}.")
    if ip in configured:
        return unverified(
            f"Probe through [{iface}] returned {ip}, which is an address on that interface, not a remote exit."
        )
    return {
        "ip": ip,
        "basis": "verified",
        "detail": f"IPv4 probe through [{iface}] returned {ip}.",
    }


def _public_exit(addresses: list[str], *, nat: bool | None, tunnel: bool) -> dict[str, Any]:
    globals_ = [item for item in addresses if _is_global(item)]
    if tunnel or not globals_:
        return {
            'ip': None,
            'basis': 'unavailable',
            'detail': (
                'No externally confirmed exit IP. Tunnel or non-global interface addresses '
                'are not the public exit.'
            ),
        }
    detail = (
        f'Interface has global address {globals_[0]}. This is the address observed on the '
        'interface, not an externally confirmed exit IP.'
    )
    if nat:
        detail += ' MASQUERADE is present, so upstream NAT can still rewrite it.'
    return {'ip': None, 'basis': 'unavailable', 'detail': detail, 'interface_global': globals_[0]}


def _endpoint_rows(settings: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for key in ('servers', 'vnext', 'peers'):
        items = settings.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            address = str(item.get('address') or item.get('endpoint') or '').strip()
            port = item.get('port')
            if address and port not in (None, '') and ':' not in address:
                rows.append(f'{address}:{port}')
            elif address:
                rows.append(address)
    redirect = str(settings.get('redirect') or '').strip()
    if redirect:
        rows.append(f'redirect {redirect}')
    return rows[:6]


def _outbound_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for outbound in config.get('outbounds') or []:
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get('tag') or '').strip()
        if tag:
            found[tag] = outbound
    return found


def _next_tag(outbound: dict[str, Any]) -> str:
    proxy = outbound.get('proxySettings') if isinstance(outbound.get('proxySettings'), dict) else {}
    tag = str(proxy.get('tag') or '').strip()
    if tag:
        return tag
    stream = outbound.get('streamSettings') if isinstance(outbound.get('streamSettings'), dict) else {}
    sockopt = stream.get('sockopt') if isinstance(stream.get('sockopt'), dict) else {}
    return str(sockopt.get('dialerProxy') or '').strip()


def _describe_outbound(outbound: dict[str, Any]) -> str:
    protocol = str(outbound.get('protocol') or 'unknown')
    settings = outbound.get('settings') if isinstance(outbound.get('settings'), dict) else {}
    parts = [protocol]
    endpoints = _endpoint_rows(settings)
    if endpoints:
        parts.append('endpoint ' + ', '.join(endpoints))
    send_through = str(outbound.get('sendThrough') or '').strip()
    if send_through:
        parts.append(f'sendThrough {send_through}')
    stream = outbound.get('streamSettings') if isinstance(outbound.get('streamSettings'), dict) else {}
    sockopt = stream.get('sockopt') if isinstance(stream.get('sockopt'), dict) else {}
    interface = str(sockopt.get('interface') or '').strip()
    if interface:
        parts.append(f'interface {interface}')
    method = str(settings.get('method') or '').strip()
    if not method:
        servers = settings.get('servers')
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            method = str(servers[0].get('method') or '').strip()
    if method:
        parts.append(f'method {method}')
    return ' · '.join(parts)


async def _append_outbound_chain(
    hops: list[dict[str, Any]],
    limitations: list[str],
    outbound_by_tag: dict[str, dict[str, Any]],
    tag: str,
    *,
    balancers: dict[str, Any],
) -> tuple[str | None, str]:
    seen: set[str] = set()
    current = tag
    bound_iface: str | None = None
    protocol = ''
    while current and len(hops) < _MAX_HOPS:
        if current in seen:
            limitations.append(f'Outbound chain loops at [{current}].')
            break
        seen.add(current)
        outbound = outbound_by_tag.get(current)
        if outbound is None:
            if current in balancers:
                break
            limitations.append(f'Outbound [{current}] is not in the config.')
            break
        protocol = str(outbound.get('protocol') or '')
        hops.append(_hop(
            len(hops) + 1,
            'outbound',
            'configured',
            f'{current}: {_describe_outbound(outbound)}',
            protocol=protocol,
            tag=current,
        ))
        stream = outbound.get('streamSettings') if isinstance(outbound.get('streamSettings'), dict) else {}
        sockopt = stream.get('sockopt') if isinstance(stream.get('sockopt'), dict) else {}
        interface = str(sockopt.get('interface') or '').strip()
        if interface:
            bound_iface = interface
        nxt = _next_tag(outbound)
        if nxt:
            current = nxt
            continue
        break

    if tag in balancers and not outbound_by_tag.get(tag):
        selector = balancers.get(tag)
        names = ', '.join(str(item) for item in selector) if isinstance(selector, list) else str(selector or '-')
        hops.append(_hop(
            len(hops) + 1,
            'balancer',
            'configured',
            f'Balancer [{tag}] selectors: {names or "-"}. The selected member is not known statically.',
            tag=tag,
        ))
        limitations.append(f'Balancer [{tag}] chooses a member at runtime; that choice was not observed.')
    return bound_iface, protocol


def _routing_decision(
    rules: list[dict[str, Any]],
    attrs: dict[str, Any],
    *,
    config_path: str | None,
    binary_path: str | None,
) -> tuple[dict[str, Any], list[str]]:
    result = test_routing_rules(rules, attrs, config_path=config_path, binary_path=binary_path)
    has_destination = bool(str(attrs.get('domain') or attrs.get('ip') or '').strip())
    if has_destination:
        limitations = [
            'Destination-dependent rules were tested with the supplied host, address, and port.',
        ]
    else:
        limitations = [
            'No destination was supplied, so domain, IP, and destination-port rules were not tested. '
            'A rule that also matches those fields is not counted as a client match.',
        ]
    for warning in result.get('warnings') or []:
        text = str(warning).strip()
        if text and text not in limitations:
            limitations.append(text)
    return result, limitations


async def _probe_public_ip(iface: str) -> tuple[str | None, str | None]:
    if not iface or not _IFACE_RE.match(iface):
        return None, "interface name missing or rejected"
    errors: list[str] = []
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        result = await _run(
            ["curl", "-4", "--interface", iface, "--max-time", "8", "-fsS", url]
        )
        text = str(result.get("stdout") or "").strip().split()
        candidate = text[0] if text else ""
        if result.get("ok") and _is_global(candidate):
            return candidate, None
        detail = str(result.get("stderr") or result.get("stdout") or "probe failed").strip()
        errors.append(detail[:160])
    return None, errors[-1] if errors else "public IP probe failed"


async def _kernel_egress(
    hops: list[dict[str, Any]],
    limitations: list[str],
    iface: str | None,
    destination_ip: str | None,
) -> dict[str, Any]:
    observed = await _observe_iface(iface or '')
    if iface:
        if observed.get('available'):
            addresses = ', '.join(observed.get('addresses') or []) or '-'
            hops.append(_hop(
                len(hops) + 1,
                'interface',
                'observed',
                f'{iface} addresses {addresses}',
                interface=iface,
            ))
            endpoints = observed.get('endpoints') or []
            if len(endpoints) == 1:
                hops.append(_hop(
                    len(hops) + 1,
                    'relay',
                    'observed',
                    f'WireGuard peer endpoint {endpoints[0]} on {iface}. This is the tunnel peer, not a verified public exit IP.',
                    endpoint=endpoints[0],
                ))
            elif len(endpoints) > 1:
                hops.append(_hop(
                    len(hops) + 1,
                    'relay',
                    'observed',
                    f'{iface} has {len(endpoints)} WireGuard endpoints ({", ".join(endpoints)}). Which peer forwards this config was not determined.',
                ))
                limitations.append(f'Multiple WireGuard peers on [{iface}]; the forwarding peer was not determined.')
        else:
            limitations.append(f'Interface [{iface}] could not be read ({observed.get("detail") or "unavailable"}).')

    target = str(destination_ip or '').strip()
    observed_route = ''
    if target:
        route_args = ['ip', 'route', 'get', target]
        if iface and _IFACE_RE.match(iface):
            route_args.extend(['oif', iface])
        route = await _run(route_args)
        if route['ok'] and str(route.get('stdout') or '').strip():
            observed_route = str(route['stdout']).strip().splitlines()[0][:180]
            parsed = _parse_route_get(observed_route)
            hops.append(_hop(
                len(hops) + 1,
                'kernel-route',
                'kernel-lookup',
                f'ip route get {target} → {observed_route}. Lookup only; not a captured packet.',
                dev=parsed.get('dev'),
                src=parsed.get('src'),
                destination=target,
            ))
        else:
            limitations.append(f'Kernel route lookup for {target} failed, so the egress device was not observed.')
    else:
        limitations.append(
            'No destination IP was supplied, so the kernel path for this client was not looked up. '
            'Pass destination to test a specific address.'
        )

    addresses = list(observed.get('addresses') or [])
    return {
        'addresses': addresses,
        'route': observed_route,
        'endpoints': list(observed.get('endpoints') or []),
    }


def _rules_for_user(rules: list[dict[str, Any]], email: str) -> list[dict[str, Any]]:
    wanted = email.strip().lower()
    found: list[dict[str, Any]] = []
    if not wanted:
        return found
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        users = [item.lower() for item in _as_list(rule.get('user'))]
        if wanted in users:
            found.append(rule)
    return found


async def trace_xray_client(
    driver: Any,
    client_key: str,
    inbound_id: str | int | None = None,
    destination: str | None = None,
) -> dict[str, Any]:
    key = str(client_key or '').strip()
    if not key:
        raise ValueError('client key is required')

    config = await driver.read_config()
    scope = str(inbound_id).strip() if inbound_id is not None and str(inbound_id).strip() else None
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if scope:
        for inbound in config.get('inbounds') or []:
            if not isinstance(inbound, dict):
                continue
            tag = str(inbound.get('tag') or '').strip()
            ident = inbound.get('id')
            if ident is None and hasattr(driver, 'id_from_tag'):
                ident = driver.id_from_tag(tag)
            if scope not in {tag, str(ident or '')}:
                continue
            client = _find_client_in_inbound(inbound, key)
            if client is None:
                continue
            pairs.append((client, inbound))
        if not pairs:
            found_client, summary = _find_config_client(config, scope, scope, key)
            if found_client is not None and isinstance(summary, dict):
                for inbound in config.get('inbounds') or []:
                    if str(inbound.get('tag') or '') == str(summary.get('tag') or ''):
                        pairs.append((found_client, inbound))
                        break
    else:
        located = _find_config_clients_by_key(config, key)
        by_tag = {
            str(inbound.get('tag') or ''): inbound
            for inbound in config.get('inbounds') or []
            if isinstance(inbound, dict)
        }
        for client, summary in located:
            inbound = by_tag.get(str(summary.get('tag') or ''))
            if isinstance(inbound, dict):
                pairs.append((client, inbound))

    if not pairs:
        limitations = [f'Client [{key}] was not found in the Xray config.']
        return {
            'kind': 'trace',
            'success': True,
            'found': False,
            'core': 'xray',
            'key': key,
            'inbound_id': scope,
            'matches': [],
            'limitations': limitations,
            'summary': _summary(False, [], limitations),
        }

    try:
        destination_attrs = parse_destination(destination)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    rules = []
    routing = config.get('routing') if isinstance(config.get('routing'), dict) else {}
    raw_rules = routing.get('rules') if isinstance(routing, dict) else None
    if isinstance(raw_rules, list):
        rules = [row for row in raw_rules if isinstance(row, dict)]
    config_rules = list(rules)
    list_rules = getattr(driver, 'list_rules', None)
    runtime_rules: list[dict[str, Any]] | None = None
    runtime_error = ''
    if callable(list_rules):
        try:
            listed = await list_rules()
            if isinstance(listed, list) and listed:
                runtime_rules = [row for row in listed if isinstance(row, dict)]
        except Exception as exc:  # noqa: BLE001
            runtime_error = str(exc) or exc.__class__.__name__
    runtime_has_users = bool(
        runtime_rules and any(_as_list(row.get('user')) for row in runtime_rules)
    )
    # A runtime summary that omits users cannot decide a client match.
    match_rules = runtime_rules if runtime_has_users and runtime_rules is not None else config_rules
    outbound_by_tag = _outbound_map(config)
    balancers: dict[str, Any] = {}
    for row in routing.get('balancers') or []:
        if isinstance(row, dict) and row.get('tag'):
            balancers[str(row['tag'])] = row.get('selector')
    config_path = str(getattr(getattr(driver, 'settings', None), 'xray', None).config or '') if getattr(driver, 'settings', None) else None
    binary_path = None
    binary = getattr(driver, '_binary', None)
    if callable(binary):
        binary_path = binary()

    matches: list[dict[str, Any]] = []
    for client, inbound in pairs:
        tag = str(inbound.get('tag') or '').strip()
        protocol = str(inbound.get('protocol') or '').strip()
        port = inbound.get('port')
        listen = str(inbound.get('listen') or '0.0.0.0')
        email = str(client.get('email') or key)
        stream = inbound.get('streamSettings') if isinstance(inbound.get('streamSettings'), dict) else {}
        network = str(stream.get('network') or '').strip()
        hops: list[dict[str, Any]] = [_hop(
            1,
            'inbound',
            'configured',
            f'{protocol or "unknown"} listen {listen}:{port} tag {tag or "-"}'
            + (f' network {network}' if network else ''),
            protocol=protocol,
            listen=listen,
            port=port,
            tag=tag,
        )]
        user_rules = _rules_for_user(config_rules, email)
        user_labels = []
        for rule in user_rules[:6]:
            label = str(rule.get('tag') or rule.get('ruleTag') or '-')
            target = str(rule.get('outboundTag') or rule.get('balancerTag') or '-')
            user_labels.append(f'{label} → {target}')
        hops.append(_hop(
            len(hops) + 1,
            'configured-rules',
            'configured',
            (
                f'{len(user_rules)} routing rule(s) list user {email}'
                + (f': {"; ".join(user_labels)}' if user_labels else '.')
            ),
        ))
        if runtime_error:
            limitations_seed = [f'Running Xray rule list could not be read ({runtime_error}). Config rules were used.']
        elif runtime_rules is not None and not runtime_has_users:
            limitations_seed = [
                'The running Xray rule list omitted users, so the client match used config.json and does not prove those users are loaded.',
            ]
        elif runtime_has_users and runtime_rules is not None and len(runtime_rules) != len(config_rules):
            limitations_seed = [
                f'Running Xray has {len(runtime_rules)} rules; config.json has {len(config_rules)}. The match below uses the running rules.',
            ]
        else:
            limitations_seed = []
        attrs = {
            'inboundTag': tag,
            'protocol': protocol,
            'user': email,
            'network': network or None,
            'domain': destination_attrs.get('domain'),
            'ip': destination_attrs.get('ip'),
            'port': destination_attrs.get('port'),
        }
        decision, limitations = _routing_decision(
            match_rules,
            attrs,
            config_path=config_path or None,
            binary_path=binary_path,
        )
        limitations = limitations_seed + limitations
        outbound_tag = str(decision.get('outboundTag') or '').strip()
        selection = 'matched' if decision.get('matched') else 'fallback'
        balancer_tag = ''
        if decision.get('matched') and isinstance(decision.get('rule'), dict):
            rule = decision['rule']
            label = str(rule.get('tag') or f"rule#{decision.get('index')}")
            target = outbound_tag or str(rule.get('balancerTag') or '')
            hops.append(_hop(
                len(hops) + 1,
                'routing-match',
                'configured',
                f'Matched rule {label} → outbound {target or "unspecified"}.',
                rule=label,
                outbound=outbound_tag or None,
            ))
        else:
            first = next(iter(outbound_by_tag), '')
            outbound_tag = first
            if user_rules:
                summary = (
                    f'No rule matched user {email} for this destination. '
                    f'{len(user_rules)} configured rule(s) list this user but did not match. '
                    f'Fallback outbound is [{first or "-"}].'
                )
            else:
                summary = (
                    f'No routing rule lists user {email}. '
                    f'Xray falls through to the first outbound [{first or "-"}].'
                )
            hops.append(_hop(
                len(hops) + 1,
                'routing-match',
                'configured',
                summary,
                outbound=first or None,
            ))
            limitations.append('The fallback outbound is not a matched client route.')

        if not outbound_tag and decision.get('matched'):
            balancer_tag = str((decision.get('rule') or {}).get('balancerTag') or '')
        bound_iface = None
        final_protocol = ''
        if outbound_tag:
            bound_iface, final_protocol = await _append_outbound_chain(
                hops,
                limitations,
                outbound_by_tag,
                outbound_tag,
                balancers=balancers,
            )
        elif balancer_tag:
            _iface, final_protocol = await _append_outbound_chain(
                hops,
                limitations,
                outbound_by_tag,
                balancer_tag,
                balancers=balancers,
            )
            bound_iface = _iface

        kernel = {'addresses': [], 'route': '', 'endpoints': []}
        if final_protocol in {'blackhole', 'dns'}:
            public_exit = {
                'ip': None,
                'basis': 'UNVERIFIED',
                'detail': f'Outbound protocol [{final_protocol}] does not forward traffic to a network egress.',
            }
        else:
            kernel = await _kernel_egress(
                hops,
                limitations,
                bound_iface,
                str(destination_attrs.get('ip') or ''),
            )
            if bound_iface and final_protocol == 'freedom':
                probe_ip, probe_error = await _probe_public_ip(bound_iface)
            else:
                probe_ip, probe_error = None, (
                    'The selected outbound has no interface binding, so the public exit was not probed.'
                    if not bound_iface
                    else f'Outbound protocol [{final_protocol or "unknown"}] was not probed for a public IP.'
                )
            public_exit = classify_public_exit(
                probe_ip=probe_ip,
                iface_addresses=list(kernel.get('addresses') or []),
                bound_iface=bound_iface if selection == 'matched' else None,
                probe_error=probe_error,
            )
            if selection != 'matched':
                public_exit = {
                    'ip': None,
                    'basis': 'UNVERIFIED',
                    'detail': 'No client routing rule matched, so the fallback path was not treated as a verified exit.',
                }
        matches.append({
            'address': email,
            'email': email,
            'inbound': {'tag': tag, 'port': port, 'protocol': protocol, 'listen': listen},
            'routing': {
                'configured_user_rules': len(user_rules),
                'matched': selection == 'matched',
                'selection': selection,
                'rules_source': 'runtime' if runtime_has_users else 'config',
                'selected_outbound': outbound_tag or None,
                'interface': bound_iface,
                'kernel_route': kernel.get('route') or None,
                'destination': destination_attrs or None,
            },
            'hops': hops[:_MAX_HOPS],
            'limitations': limitations[:8],
            'public_exit': public_exit,
        })

    flat_limits = matches[0]['limitations'] if len(matches) == 1 else []
    return {
        'kind': 'trace',
        'success': True,
        'found': True,
        'core': 'xray',
        'key': key,
        'email': str(matches[0].get('email') or ''),
        'inbound_id': scope,
        'matches': matches,
        'limitations': flat_limits,
        'summary': _summary(True, matches, flat_limits),
    }


def _listener_summary(core: str, match: dict[str, Any]) -> dict[str, Any]:
    iface = match.get('interface') if isinstance(match.get('interface'), dict) else {}
    server = match.get('server') if isinstance(match.get('server'), dict) else {}
    routing = match.get('routing') if isinstance(match.get('routing'), dict) else {}
    name = str(iface.get('name') or server.get('name') or server.get('id') or '-')
    port = iface.get('listen_port') or server.get('listen_port')
    proto = str(server.get('proto') or core)
    tun = str(server.get('tun_dev') or routing.get('tun_interface') or '').strip()
    return {'name': name, 'port': port, 'protocol': proto, 'tun': tun}


async def _hops_from_peer_match(core: str, match: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    routing = match.get('routing') if isinstance(match.get('routing'), dict) else {}
    listener = _listener_summary(core, match)
    entity = match.get('peer') if isinstance(match.get('peer'), dict) else {}
    if not entity and isinstance(match.get('user'), dict):
        entity = match['user']
    address = str(match.get('address') or entity.get('address') or '-')
    hops: list[dict[str, Any]] = [_hop(
        1,
        'inbound',
        'configured',
        f'{listener["protocol"]} {listener["name"]} port {listener["port"] or "-"}'
        + (f' tun {listener["tun"]}' if listener['tun'] else '')
        + f' client {address}',
        protocol=listener['protocol'],
        port=listener['port'],
        listen=listener['name'],
    )]
    limitations: list[str] = []
    exit_iface = str(routing.get('exit_interface') or entity.get('exit_interface') or '').strip()
    if exit_iface:
        hops.append(_hop(
            len(hops) + 1,
            'routing',
            'configured',
            f'Intended exit interface [{exit_iface}] from stored policy routing. This is not a captured packet.',
            interface=exit_iface,
        ))
    else:
        limitations.append('No exit interface is stored. Traffic is intended to follow the main routing table only.')

    rules = [row for row in (routing.get('ip_rules') or []) if isinstance(row, dict)]
    if rules:
        shown = []
        for rule in rules[:4]:
            shown.append(f'src {rule.get("src") or "-"} → table {rule.get("table") or "-"} pref {rule.get("pref") or "-"}')
        hops.append(_hop(
            len(hops) + 1,
            'policy-rule',
            'observed',
            '; '.join(shown),
        ))
    else:
        limitations.append('No policy rule for this source was observed.')

    policy = routing.get('policy_route') if isinstance(routing.get('policy_route'), dict) else {}
    routes = [str(line) for line in (policy.get('routes') or []) if str(line).strip()]
    if routes:
        hops.append(_hop(
            len(hops) + 1,
            'route-table',
            'observed',
            f'table {policy.get("table") or "-"}: ' + ' | '.join(routes[:4]),
        ))
    elif exit_iface:
        limitations.append(f'Policy table for [{exit_iface}] was not observed.')

    egress = routing.get('simulated_egress') if isinstance(routing.get('simulated_egress'), dict) else {}
    raw = str(egress.get('raw') or '').strip()
    parsed = _parse_route_get(raw)
    if raw:
        hops.append(_hop(
            len(hops) + 1,
            'egress',
            'kernel-lookup',
            f'ip route get → {raw[:180]}. Lookup only; not a captured packet.',
            dev=parsed.get('dev'),
            src=parsed.get('src'),
        ))
        if exit_iface and parsed.get('dev') and parsed.get('dev') != exit_iface:
            limitations.append(
                f'Kernel lookup selected dev {parsed["dev"]}, which differs from configured exit [{exit_iface}].'
            )
    else:
        limitations.append('Kernel route lookup was not available, so the forwarding device was not observed.')

    nat = routing.get('nat') if isinstance(routing.get('nat'), dict) else {}
    if nat:
        hops.append(_hop(
            len(hops) + 1,
            'nat',
            'observed',
            f'MASQUERADE {"present" if nat.get("masquerade") else "not found"}'
            + (f' ({nat.get("details")})' if nat.get('details') else ''),
        ))

    observed = await _observe_iface(exit_iface)
    if exit_iface and observed.get('available'):
        addresses = ', '.join(observed.get('addresses') or []) or '-'
        hops.append(_hop(
            len(hops) + 1,
            'interface',
            'observed',
            f'{exit_iface} addresses {addresses}',
            interface=exit_iface,
        ))
        endpoints = observed.get('endpoints') or []
        if len(endpoints) == 1:
            hops.append(_hop(
                len(hops) + 1,
                'relay',
                'observed',
                f'Tunnel peer endpoint {endpoints[0]}. Not a verified public exit IP.',
                endpoint=endpoints[0],
            ))
        elif len(endpoints) > 1:
            limitations.append(f'{exit_iface} has multiple tunnel peers; the forwarding peer was not determined.')
    elif exit_iface:
        limitations.append(f'Exit interface [{exit_iface}] could not be read ({observed.get("detail") or "unavailable"}).')

    linked = match.get('linked_peer') if isinstance(match.get('linked_peer'), dict) else {}
    if linked.get('found'):
        hops.append(_hop(
            len(hops) + 1,
            'linked-peer',
            'configured',
            f'Linked {linked.get("core") or "peer"} {linked.get("id") or "-"} '
            f'exit {linked.get("exit_interface") or "-"}.',
        ))

    addresses = list(observed.get('addresses') or [])
    if parsed.get('src'):
        addresses.append(parsed['src'])
    tunnel = bool(observed.get('endpoints')) or exit_iface.startswith(('wg', 'awg', 'tun', 'ppp'))
    public_exit = _public_exit(addresses, nat=bool(nat.get('masquerade')) if nat else None, tunnel=tunnel)
    return hops[:_MAX_HOPS], limitations[:8], public_exit


async def trace_stored_peer(
    store: Any,
    core: str,
    address: str,
    *,
    peer_dump_fn: Callable[..., Any] | None = None,
    interface_is_up_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    name = str(core or '').strip().lower()
    if name in {'wireguard', 'amnezia'}:
        from agent.support.peer_diagnose import diagnose_peer_address

        report = await diagnose_peer_address(
            store,
            name,
            address,
            peer_dump_fn=peer_dump_fn,
            interface_is_up_fn=interface_is_up_fn,
        )
    elif name == 'l2tp':
        from agent.support.l2tp_diagnose import diagnose_user_address

        report = await diagnose_user_address(store, name, address)
    elif name == 'openvpn':
        from agent.support.openvpn_diagnose import diagnose_user_address

        report = await diagnose_user_address(store, name, address)
    else:
        raise ValueError(f'Core [{name}] does not support trace')

    matches: list[dict[str, Any]] = []
    for match in report.get('matches') or []:
        if not isinstance(match, dict):
            continue
        hops, limitations, public_exit = await _hops_from_peer_match(name, match)
        matches.append({
            'address': match.get('address'),
            'hops': hops,
            'limitations': limitations,
            'public_exit': public_exit,
        })

    limitations = _issue_messages(report) if not matches else []
    report['kind'] = 'trace'
    report['matches'] = matches
    report['limitations'] = limitations
    report['summary'] = _summary(bool(report.get('found')), matches, limitations)
    return report
