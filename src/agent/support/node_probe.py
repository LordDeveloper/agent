"""Connectivity probes for region server nodes (exit interface / Xray outbound)."""

from __future__ import annotations

import ipaddress
import shutil
import socket
from typing import Any, Callable

from agent.errors import AgentError
from agent.support.host_interfaces import list_host_interfaces
from agent.support.process import run

Runner = Callable[..., Any]

PROBE_URL = 'http://cp.cloudflare.com/cdn-cgi/trace'
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


def _curl_probe(*, interface: str | None = None, runner: Runner | None = None) -> tuple[bool, str]:
    execute = _runner(runner)
    if not shutil.which('curl'):
        return False, 'curl در Agent موجود نیست'

    cmd = [
        'curl',
        '-4',
        '--max-time',
        str(PROBE_TIMEOUT),
        '--fail',
        '-s',
        '-o',
        '/dev/null',
        PROBE_URL,
    ]
    if interface:
        cmd[1:1] = ['--interface', interface]

    result = execute(cmd, check=False, timeout=PROBE_TIMEOUT + 4)
    code = int(getattr(result, 'returncode', 1) or 1)
    if code == 0:
        return True, 'اتصال برقرار شد'
    stderr = (getattr(result, 'stderr', '') or '').strip()
    return False, stderr or f'curl exit {code}'


def _tcp_probe(host: str, port: int, *, timeout: float = 5.0) -> tuple[bool, str]:
    host = str(host or '').strip()
    if not host or port <= 0:
        return False, 'آدرس/پورت نامعتبر'
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, 'TCP متصل شد'
    except OSError as exc:
        return False, str(exc) or 'TCP ناموفق'


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


def probe_outbound_tag(tag: str, outbounds: list[dict[str, Any]], *, runner: Runner | None = None) -> dict[str, Any]:
    needle = str(tag or '').strip()
    if not needle:
        return {'ok': False, 'message': 'outbound_tag تنظیم نشده'}

    outbound = None
    for row in outbounds:
        if not isinstance(row, dict):
            continue
        if str(row.get('tag') or '').strip() == needle:
            outbound = row
            break

    if outbound is None:
        return {'ok': False, 'message': f'اوتباند {needle} در Agent یافت نشد'}

    protocol = str(outbound.get('protocol') or '').strip().lower()
    bind_iface = _resolve_bind_interface(outbound)

    if protocol == 'blackhole':
        return {'ok': False, 'message': 'اوتباند blackhole است'}

    if protocol == 'freedom':
        ok, message = _curl_probe(interface=bind_iface or None, runner=runner)
        return {
            'ok': ok,
            'message': message,
            'protocol': protocol,
            'interface': bind_iface or None,
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
    failures: list[str] = []
    configured = 0
    outbounds = outbounds or []

    outbound_tag = str(outbound_tag or '').strip() or None
    exit_interface = str(exit_interface or '').strip() or None

    if outbound_tag:
        configured += 1
        checks['outbound'] = probe_outbound_tag(outbound_tag, outbounds, runner=runner)
        if not checks['outbound'].get('ok'):
            failures.append(checks['outbound'].get('message') or 'outbound ناموفق')

    if exit_interface:
        configured += 1
        checks['exit_interface'] = probe_exit_interface(exit_interface, runner=runner)
        if not checks['exit_interface'].get('ok'):
            failures.append(checks['exit_interface'].get('message') or 'exit_interface ناموفق')

    if configured == 0:
        return {
            'id': node_id,
            'ok': False,
            'message': 'هیچ مسیر خروجی برای این نود تنظیم نشده',
            'checks': checks,
        }

    ok = len(failures) == 0
    return {
        'id': node_id,
        'ok': ok,
        'message': 'ترافیک از این نود عبور می‌کند' if ok else (failures[0] if failures else 'ناموفق'),
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
