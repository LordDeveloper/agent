"""Connectivity probes for region server nodes (exit interface / Xray outbound)."""

from __future__ import annotations

import ipaddress
import shutil
from typing import Any, Callable

from agent.errors import AgentError
from agent.support.host_interfaces import list_host_interfaces
from agent.support.process import run

Runner = Callable[..., Any]

# Multiple targets improve reachability from restricted networks.
PROBE_TARGETS: tuple[tuple[str, frozenset[int]], ...] = (
    ('http://connectivitycheck.gstatic.com/generate_204', frozenset({204})),
    ('http://1.1.1.1/cdn-cgi/trace', frozenset({200})),
    ('http://cp.cloudflare.com/cdn-cgi/trace', frozenset({200})),
)
PROBE_TIMEOUT = 8


def _runner(runner: Runner | None) -> Runner:
    return runner or run


def _interface_row(name: str, *, runner: Runner | None = None) -> dict[str, Any] | None:
    target = str(name or '').strip()
    if not target:
        return None
    for row in list_host_interfaces(runner=runner):
        if str(row.get('name') or '').strip() == target:
            return row
    return None


def _interface_addresses(name: str, *, runner: Runner | None = None) -> set[str]:
    row = _interface_row(name, runner=runner)
    if row is None:
        return set()

    addresses: set[str] = set()
    for item in row.get('addresses') or []:
        text = str(item or '').strip()
        if not text:
            continue
        if '/' in text:
            try:
                addresses.add(str(ipaddress.ip_interface(text).ip))
            except ValueError:
                addresses.add(text.split('/', 1)[0])
        else:
            addresses.add(text)

    return addresses


def _resolve_curl_bind(target: str | None, *, runner: Runner | None = None) -> str | None:
    bind = str(target or '').strip()
    if not bind:
        return None

    try:
        ipaddress.ip_address(bind)
        return bind
    except ValueError:
        pass

    row = _interface_row(bind, runner=runner)
    if row is None:
        return bind

    if row.get('is_up') is False:
        return bind

    return bind


def _bind_targets_equivalent(left: str | None, right: str | None, *, runner: Runner | None = None) -> bool:
    a = str(left or '').strip()
    b = str(right or '').strip()
    if not a or not b:
        return False
    if a == b:
        return True

    try:
        a_ip = str(ipaddress.ip_address(a))
    except ValueError:
        a_ip = None

    try:
        b_ip = str(ipaddress.ip_address(b))
    except ValueError:
        b_ip = None

    if a_ip and b_ip:
        return a_ip == b_ip

    if a_ip and _interface_addresses(b, runner=runner) == {a_ip}:
        return True

    if b_ip and _interface_addresses(a, runner=runner) == {b_ip}:
        return True

    return False


def _curl_probe(*, interface: str | None = None, runner: Runner | None = None) -> tuple[bool, str]:
    execute = _runner(runner)
    if not shutil.which('curl'):
        return False, 'curl در Agent موجود نیست'

    bind = _resolve_curl_bind(interface, runner=runner)
    errors: list[str] = []

    for url, ok_codes in PROBE_TARGETS:
        cmd = [
            'curl',
            '-4',
            '--max-time',
            str(PROBE_TIMEOUT),
            '-sS',
            '-o',
            '/dev/null',
            '-w',
            '%{http_code}',
            url,
        ]
        if bind:
            cmd[1:1] = ['--interface', bind]

        result = execute(cmd, check=False, timeout=PROBE_TIMEOUT + 4)
        raw_code = getattr(result, 'returncode', 1)
        code = int(raw_code if raw_code is not None else 1)
        body = (getattr(result, 'stdout', '') or '').strip()
        stderr = (getattr(result, 'stderr', '') or '').strip()

        if code == 0:
            try:
                http_code = int(body or '0')
            except ValueError:
                http_code = 0
            if http_code in ok_codes:
                return True, 'اتصال برقرار شد'
            errors.append(f'HTTP {http_code or "?"}')
            continue

        errors.append(stderr or f'curl exit {code}')

    detail = errors[-1] if errors else 'اتصال برقرار نشد'
    return False, detail


def _tcp_probe(host: str, port: int, *, timeout: float = 5.0) -> tuple[bool, str]:
    import socket

    host = str(host or '').strip()
    if not host or port <= 0:
        return False, 'آدرس/پورت نامعتبر'
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, 'TCP متصل شد'
    except OSError as exc:
        return False, str(exc) or 'TCP ناموفق'


def _find_outbound(tag: str, outbounds: list[dict[str, Any]]) -> dict[str, Any] | None:
    needle = str(tag or '').strip()
    if not needle:
        return None
    for row in outbounds:
        if not isinstance(row, dict):
            continue
        if str(row.get('tag') or '').strip() == needle:
            return row
    return None


def _outbound_server(outbound: dict[str, Any]) -> tuple[str, int] | None:
    settings = outbound.get('settings')
    if not isinstance(settings, dict):
        return None
    vnext = settings.get('vnext')
    if isinstance(vnext, list) and vnext:
        row = vnext[0] if isinstance(vnext[0], dict) else {}
        address = str(row.get('address') or '').strip()
        port = int(row.get('port') or 0)
        if address and port > 0:
            return address, port
    servers = settings.get('servers')
    if isinstance(servers, list) and servers:
        row = servers[0] if isinstance(servers[0], dict) else {}
        address = str(row.get('address') or '').strip()
        port = int(row.get('port') or 0)
        if address and port > 0:
            return address, port
    return None


def _resolve_bind_interface(outbound: dict[str, Any]) -> str:
    send_through = str(outbound.get('sendThrough') or '').strip()
    if send_through:
        return send_through
    stream = outbound.get('streamSettings')
    if isinstance(stream, dict):
        sockopt = stream.get('sockopt')
        if isinstance(sockopt, dict):
            iface = str(sockopt.get('interface') or '').strip()
            if iface:
                return iface
    return ''


def _should_skip_exit_interface_check(
    outbound_tag: str | None,
    exit_interface: str | None,
    outbounds: list[dict[str, Any]],
    *,
    runner: Runner | None = None,
) -> bool:
    tag = str(outbound_tag or '').strip()
    iface = str(exit_interface or '').strip()
    if not tag or not iface:
        return False

    outbound = _find_outbound(tag, outbounds)
    if outbound is None:
        return False

    protocol = str(outbound.get('protocol') or '').strip().lower()
    if protocol != 'freedom':
        return False

    bind = _resolve_bind_interface(outbound)
    return _bind_targets_equivalent(bind, iface, runner=runner)


def probe_exit_interface(name: str, *, runner: Runner | None = None) -> dict[str, Any]:
    iface = str(name or '').strip()
    if not iface:
        return {'ok': False, 'message': 'exit_interface تنظیم نشده'}

    row = _interface_row(iface, runner=runner)
    if row is None:
        return {'ok': False, 'message': f'اینترفیس {iface} یافت نشد'}
    if row.get('is_up') is False:
        return {'ok': False, 'message': f'اینترفیس {iface} down است'}

    ok, message = _curl_probe(interface=iface, runner=runner)
    return {'ok': ok, 'message': message, 'interface': iface}


def probe_outbound_tag(
    tag: str,
    outbounds: list[dict[str, Any]],
    *,
    fallback_interface: str | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    needle = str(tag or '').strip()
    if not needle:
        return {'ok': False, 'message': 'outbound_tag تنظیم نشده'}

    outbound = _find_outbound(needle, outbounds)
    if outbound is None:
        return {'ok': False, 'message': f'اوتباند {needle} در Agent یافت نشد'}

    protocol = str(outbound.get('protocol') or '').strip().lower()
    bind_iface = _resolve_bind_interface(outbound) or str(fallback_interface or '').strip()

    if protocol == 'blackhole':
        return {'ok': False, 'message': 'اوتباند blackhole است'}

    if protocol == 'freedom':
        if not bind_iface:
            return {'ok': False, 'message': 'اوتباند freedom بدون sendThrough/interface قابل تست نیست'}
        ok, message = _curl_probe(interface=bind_iface, runner=runner)
        return {
            'ok': ok,
            'message': message,
            'protocol': protocol,
            'interface': bind_iface,
        }

    if protocol in {'dns', 'loopback'}:
        return {'ok': True, 'message': f'اوتباند {protocol} — بدون تست egress', 'protocol': protocol}

    endpoint = _outbound_server(outbound)
    if endpoint is not None:
        host, port = endpoint
        ok, message = _tcp_probe(host, port)
        return {
            'ok': ok,
            'message': message,
            'protocol': protocol,
            'endpoint': f'{host}:{port}',
        }

    return {'ok': False, 'message': f'اوتباند {protocol} قابل تست نیست', 'protocol': protocol}


def probe_region_node(
    *,
    node_id: int | str,
    outbound_tag: str | None = None,
    exit_interface: str | None = None,
    outbounds: list[dict[str, Any]] | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    outcomes: list[bool] = []
    messages: list[str] = []
    outbounds = outbounds or []

    outbound_tag = str(outbound_tag or '').strip() or None
    exit_interface = str(exit_interface or '').strip() or None

    if outbound_tag:
        checks['outbound'] = probe_outbound_tag(
            outbound_tag,
            outbounds,
            fallback_interface=exit_interface,
            runner=runner,
        )
        outcomes.append(bool(checks['outbound'].get('ok')))
        message = str(checks['outbound'].get('message') or '').strip()
        if message:
            messages.append(message)

    if exit_interface and not _should_skip_exit_interface_check(
        outbound_tag,
        exit_interface,
        outbounds,
        runner=runner,
    ):
        checks['exit_interface'] = probe_exit_interface(exit_interface, runner=runner)
        outcomes.append(bool(checks['exit_interface'].get('ok')))
        message = str(checks['exit_interface'].get('message') or '').strip()
        if message:
            messages.append(message)

    if not outcomes:
        return {
            'id': node_id,
            'ok': False,
            'message': 'هیچ مسیر خروجی برای این نود تنظیم نشده',
            'checks': checks,
        }

    ok = any(outcomes)
    failure_messages = [
        str(check.get('message') or '').strip()
        for check in checks.values()
        if isinstance(check, dict) and not check.get('ok')
    ]

    return {
        'id': node_id,
        'ok': ok,
        'message': 'ترافیک از این نود عبور می‌کند' if ok else (failure_messages[0] if failure_messages else 'ناموفق'),
        'checks': checks,
    }


def probe_region_nodes(
    nodes: list[dict[str, Any]],
    outbounds: list[dict[str, Any]] | None = None,
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    if not isinstance(nodes, list) or not nodes:
        raise AgentError('VALIDATION_ERROR', 'nodes list is required')

    rows: list[dict[str, Any]] = []
    for item in nodes:
        if not isinstance(item, dict):
            continue
        node_id = item.get('id')
        if node_id is None:
            continue
        rows.append(
            probe_region_node(
                node_id=node_id,
                outbound_tag=item.get('outbound_tag'),
                exit_interface=item.get('exit_interface'),
                outbounds=outbounds,
                runner=runner,
            )
        )

    passed = sum(1 for row in rows if row.get('ok'))
    return {
        'ok': True,
        'nodes': rows,
        'summary': {
            'total': len(rows),
            'passed': passed,
            'failed': len(rows) - passed,
        },
    }
