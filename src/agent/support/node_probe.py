"""Connectivity probes for region server nodes (exit interface / Xray outbound)."""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from agent.errors import AgentError
from agent.support.host_interfaces import list_host_interfaces
from agent.support.process import run

Runner = Callable[..., Any]

# IP-literal targets ONLY. Hostname probes + ads-block/resolvectl on exit ifaces
# can hang getaddrinfo longer than the panel HTTP timeout, which surfaces as
# "اتصال شبکه به Agent برقرار نشد" for that region node.
PROBE_TARGETS: tuple[tuple[str, frozenset[int]], ...] = (
    ('http://1.1.1.1/cdn-cgi/trace', frozenset({200})),
    ('http://1.0.0.1/cdn-cgi/trace', frozenset({200})),
    ('http://8.8.8.8/', frozenset({200, 301, 302, 404})),
    ('http://8.8.4.4/', frozenset({200, 301, 302, 404})),
    ('http://9.9.9.9/', frozenset({200, 301, 302, 404})),
    ('http://208.67.222.222/', frozenset({200, 301, 302, 404})),
)
PROBE_TIMEOUT = 3
CONNECT_TIMEOUT = 2
BIND_ERROR_CODES = frozenset({45, 55})

# Small Cloudflare download used to rank Mullvad relays by real egress throughput.
# Bind by WireGuard interface NAME — never by tunnel IP (shared across exits).
SPEED_TEST_URL = 'https://speed.cloudflare.com/__down?bytes=2000000'
SPEED_CONNECT_TIMEOUT = 4
SPEED_MAX_TIME = 12

# Mullvad exits use Table=off: peer traffic works via policy routing, but host
# curl --interface needs a temporary /32 via that device. Lock per destination so
# parallel probes can proceed on distinct IPs without thrashing the same route.
_probe_route_locks_guard = threading.Lock()
_probe_route_locks: dict[str, threading.Lock] = {}


def _route_lock_for(dest: str) -> threading.Lock:
    key = str(dest or '').strip() or '*'
    with _probe_route_locks_guard:
        lock = _probe_route_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _probe_route_locks[key] = lock
        return lock


def _rotated_probe_targets(start_index: int = 0) -> list[tuple[str, frozenset[int]]]:
    targets = list(PROBE_TARGETS)
    if not targets:
        return []
    offset = int(start_index or 0) % len(targets)
    if offset <= 0:
        return targets
    return targets[offset:] + targets[:offset]


def _runner(runner: Runner | None) -> Runner:
    return runner or run


def _url_host(url: str) -> str | None:
    try:
        host = urlparse(str(url or '')).hostname
    except ValueError:
        return None
    text = str(host or '').strip()
    return text or None


def _resolve_ipv4_hosts(hosts: list[str]) -> list[str]:
    resolved: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        text = str(host or '').strip()
        if not text:
            continue
        try:
            ip = str(ipaddress.ip_address(text))
            if ':' in ip:
                continue
            if ip not in seen:
                seen.add(ip)
                resolved.append(ip)
            continue
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(text, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        for info in infos:
            addr = str(info[4][0] if info and info[4] else '').strip()
            if not addr or addr in seen:
                continue
            seen.add(addr)
            resolved.append(addr)
    return resolved


def _ip_route_replace_dev(dest: str, iface: str, *, runner: Runner) -> bool:
    result = runner(
        ['ip', 'route', 'replace', f'{dest}/32', 'dev', iface],
        check=False,
        timeout=5,
    )
    code = getattr(result, 'returncode', 1)
    return int(0 if code is None else code) == 0


def _ip_route_del_dev(dest: str, iface: str, *, runner: Runner) -> None:
    runner(
        ['ip', 'route', 'del', f'{dest}/32', 'dev', iface],
        check=False,
        timeout=5,
    )


@contextmanager
def _host_routes_for_iface(
    iface: str | None,
    destinations: list[str],
    *,
    runner: Runner | None = None,
) -> Iterator[None]:
    """Install temporary /32 routes so curl --interface works with Table=off WG."""
    bind = str(iface or '').strip()
    execute = _runner(runner)
    if not bind or _looks_like_ip(bind) or not shutil.which('ip'):
        yield
        return

    hosts = _resolve_ipv4_hosts(destinations)
    if not hosts:
        yield
        return

    # Acquire destination locks in sorted order to avoid deadlocks across threads.
    ordered = sorted(set(hosts))
    locks = [_route_lock_for(dest) for dest in ordered]
    for lock in locks:
        lock.acquire()
    installed: list[str] = []
    try:
        for dest in ordered:
            try:
                if _ip_route_replace_dev(dest, bind, runner=execute):
                    installed.append(dest)
            except Exception:
                continue
        yield
    finally:
        for dest in installed:
            try:
                _ip_route_del_dev(dest, bind, runner=execute)
            except Exception:
                pass
        for lock in reversed(locks):
            lock.release()


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


def _parse_curl_write_out(body: str) -> tuple[int, int | None]:
    parts = (body or '').strip().split()
    if not parts:
        return 0, None

    try:
        http_code = int(parts[0])
    except ValueError:
        http_code = 0

    latency_ms: int | None = None
    if len(parts) >= 2:
        try:
            latency_ms = max(1, int(round(float(parts[1]) * 1000)))
        except ValueError:
            latency_ms = None

    return http_code, latency_ms


def _curl_probe(
    *,
    interface: str | None = None,
    runner: Runner | None = None,
    start_index: int = 0,
) -> tuple[bool, str, int | None]:
    execute = _runner(runner)
    if not shutil.which('curl'):
        return False, 'curl در Agent موجود نیست', None

    bind = _resolve_curl_bind(interface, runner=runner)
    errors: list[str] = []
    per_try_timeout = PROBE_TIMEOUT + CONNECT_TIMEOUT + 2
    targets = _rotated_probe_targets(start_index)

    # Install one /32 at a time so parallel probes on different IPs can overlap.
    for url, ok_codes in targets:
        host = _url_host(url)
        with _host_routes_for_iface(bind, [host] if host else [], runner=execute):
            cmd = [
                'curl',
                '-4',
                '--connect-timeout',
                str(CONNECT_TIMEOUT),
                '--max-time',
                str(PROBE_TIMEOUT),
                '-sS',
                '-o',
                '/dev/null',
                '-w',
                '%{http_code} %{time_total}',
                url,
            ]
            if bind:
                cmd[1:1] = ['--interface', bind]

            try:
                result = execute(cmd, check=False, timeout=per_try_timeout)
            except subprocess.TimeoutExpired:
                errors.append(f'timeout after {per_try_timeout}s ({url})')
                continue
            except OSError as exc:
                errors.append(str(exc) or 'curl OSError')
                continue

            raw_code = getattr(result, 'returncode', 1)
            code = int(raw_code if raw_code is not None else 1)
            body = (getattr(result, 'stdout', '') or '').strip()
            stderr = (getattr(result, 'stderr', '') or '').strip()

            if code == 0:
                http_code, latency_ms = _parse_curl_write_out(body)
                if http_code in ok_codes:
                    return True, 'اتصال برقرار شد', latency_ms
                errors.append(f'HTTP {http_code or "?"}')
                continue

            errors.append(stderr or f'curl exit {code}')
            if code in BIND_ERROR_CODES or 'bind' in stderr.lower() or 'interface' in stderr.lower():
                break

    detail = errors[-1] if errors else 'اتصال برقرار نشد'
    return False, detail, None


def _parse_curl_speed(body: str) -> tuple[int, float | None]:
    parts = (body or '').strip().split()
    if not parts:
        return 0, None
    try:
        http_code = int(parts[0])
    except ValueError:
        http_code = 0
    speed_bps: float | None = None
    if len(parts) >= 2:
        try:
            speed_bps = max(0.0, float(parts[1]))
        except ValueError:
            speed_bps = None
    return http_code, speed_bps


def curl_speed_mbps(
    *,
    interface: str | None = None,
    runner: Runner | None = None,
    url: str = SPEED_TEST_URL,
) -> tuple[bool, str, float | None]:
    """Measure download Mbps through a named interface via curl --interface.

    Mullvad exits share one tunnel Address (same private key). Binding by IP is
    ambiguous; always pass the WireGuard interface name (e.g. ``us``, ``de``).
    """
    execute = _runner(runner)
    if not shutil.which('curl'):
        return False, 'curl در Agent موجود نیست', None

    # Keep the iface name as-is — do not resolve to the shared tunnel IP.
    bind = str(interface or '').strip()
    if not bind:
        return False, 'نام اینترفیس مشخص نیست', None

    host = _url_host(url)
    destinations = [host] if host else []
    cmd = [
        'curl',
        '-4',
        '--interface',
        bind,
        '--connect-timeout',
        str(SPEED_CONNECT_TIMEOUT),
        '--max-time',
        str(SPEED_MAX_TIME),
        '-sS',
        '-o',
        '/dev/null',
        '-w',
        '%{http_code} %{speed_download}',
        url,
    ]
    with _host_routes_for_iface(bind, destinations, runner=execute):
        try:
            result = execute(cmd, check=False, timeout=SPEED_MAX_TIME + SPEED_CONNECT_TIMEOUT + 2)
        except subprocess.TimeoutExpired:
            return False, f'timeout after {SPEED_MAX_TIME + SPEED_CONNECT_TIMEOUT + 2}s', None
        except OSError as exc:
            return False, str(exc) or 'curl OSError', None

    raw_code = getattr(result, 'returncode', 1)
    code = int(raw_code if raw_code is not None else 1)
    body = (getattr(result, 'stdout', '') or '').strip()
    stderr = (getattr(result, 'stderr', '') or '').strip()

    if code != 0:
        return False, stderr or f'curl exit {code}', None

    http_code, speed_bps = _parse_curl_speed(body)
    if http_code not in {200, 204, 206} or speed_bps is None:
        return False, f'HTTP {http_code or "?"} / no speed', None

    mbps = round((speed_bps * 8.0) / 1_000_000.0, 2)
    return True, f'{mbps} Mbps', mbps


def _tcp_probe(host: str, port: int, *, timeout: float = 5.0) -> tuple[bool, str, int | None]:
    host = str(host or '').strip()
    if not host or port <= 0:
        return False, 'آدرس/پورت نامعتبر', None
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = max(1, int(round((time.perf_counter() - started) * 1000)))
            return True, 'TCP متصل شد', latency_ms
    except OSError as exc:
        return False, str(exc) or 'TCP ناموفق', None


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


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or '').strip())
        return True
    except ValueError:
        return False


def _interfaces_sharing_address(address: str, *, runner: Runner | None = None) -> list[str]:
    needle = str(address or '').strip()
    if not needle:
        return []
    try:
        needle_ip = str(ipaddress.ip_address(needle))
    except ValueError:
        return []

    names: list[str] = []
    for row in list_host_interfaces(runner=runner):
        name = str(row.get('name') or '').strip()
        if not name:
            continue
        for item in row.get('addresses') or []:
            text = str(item or '').strip()
            if not text:
                continue
            host = text.split('/', 1)[0].strip()
            try:
                if str(ipaddress.ip_address(host)) == needle_ip:
                    names.append(name)
                    break
            except ValueError:
                continue
    return names


def _prefer_named_bind(
    bind: str | None,
    preferred_iface: str | None,
    *,
    runner: Runner | None = None,
) -> str:
    """Prefer WireGuard iface name over a shared Mullvad tunnel IP for curl --interface."""
    preferred = str(preferred_iface or '').strip()
    current = str(bind or '').strip()
    if preferred:
        return preferred
    if not current or not _looks_like_ip(current):
        return current
    owners = _interfaces_sharing_address(current, runner=runner)
    if len(owners) == 1:
        return owners[0]
    # Shared Address across Mullvad exits — IP bind is ambiguous.
    return current


def _should_skip_exit_interface_check(
    outbound_tag: str | None,
    exit_interface: str | None,
    outbounds: list[dict[str, Any]],
    *,
    runner: Runner | None = None,
) -> bool:
    """Skip duplicate exit probe only when outbound already binds the same iface *name*."""
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
    if not bind:
        return False
    # sendThrough=shared Mullvad IP must NOT skip the named exit_interface probe.
    if _looks_like_ip(bind):
        return False
    return bind == iface


def probe_exit_interface(
    name: str,
    *,
    runner: Runner | None = None,
    start_index: int = 0,
) -> dict[str, Any]:
    iface = str(name or '').strip()
    if not iface:
        return {'ok': False, 'message': 'exit_interface تنظیم نشده'}

    row = _interface_row(iface, runner=runner)
    if row is None:
        return {'ok': False, 'message': f'اینترفیس {iface} یافت نشد'}
    if row.get('is_up') is False:
        return {'ok': False, 'message': f'اینترفیس {iface} down است'}

    ok, message, latency_ms = _curl_probe(interface=iface, runner=runner, start_index=start_index)
    result: dict[str, Any] = {'ok': ok, 'message': message, 'interface': iface}
    if latency_ms is not None:
        result['latency_ms'] = latency_ms
    return result


def probe_outbound_tag(
    tag: str,
    outbounds: list[dict[str, Any]],
    *,
    fallback_interface: str | None = None,
    runner: Runner | None = None,
    start_index: int = 0,
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
        if not bind_iface and not str(fallback_interface or '').strip():
            return {'ok': False, 'message': 'اوتباند freedom بدون sendThrough/interface قابل تست نیست'}
        # Mullvad exits share one tunnel Address — always probe by iface name when known.
        bind_iface = _prefer_named_bind(bind_iface, fallback_interface, runner=runner)
        if not bind_iface:
            return {'ok': False, 'message': 'اوتباند freedom بدون sendThrough/interface قابل تست نیست'}
        if _looks_like_ip(bind_iface):
            owners = _interfaces_sharing_address(bind_iface, runner=runner)
            if len(owners) > 1:
                return {
                    'ok': False,
                    'message': (
                        f'sendThrough={bind_iface} روی چند اینترفیس مشترک است '
                        f'({", ".join(owners[:6])}); exit_interface لازم است'
                    ),
                    'protocol': protocol,
                    'interface': bind_iface,
                }
        ok, message, latency_ms = _curl_probe(
            interface=bind_iface,
            runner=runner,
            start_index=start_index,
        )
        result: dict[str, Any] = {
            'ok': ok,
            'message': message,
            'protocol': protocol,
            'interface': bind_iface,
        }
        if latency_ms is not None:
            result['latency_ms'] = latency_ms
        return result

    if protocol in {'dns', 'loopback'}:
        return {'ok': True, 'message': f'اوتباند {protocol} — بدون تست egress', 'protocol': protocol}

    endpoint = _outbound_server(outbound)
    if endpoint is not None:
        host, port = endpoint
        ok, message, latency_ms = _tcp_probe(host, port)
        result = {
            'ok': ok,
            'message': message,
            'protocol': protocol,
            'endpoint': f'{host}:{port}',
        }
        if latency_ms is not None:
            result['latency_ms'] = latency_ms
        return result

    return {'ok': False, 'message': f'اوتباند {protocol} قابل تست نیست', 'protocol': protocol}


def probe_region_node(
    *,
    node_id: int | str,
    outbound_tag: str | None = None,
    exit_interface: str | None = None,
    outbounds: list[dict[str, Any]] | None = None,
    runner: Runner | None = None,
    start_index: int = 0,
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
            start_index=start_index,
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
        checks['exit_interface'] = probe_exit_interface(
            exit_interface,
            runner=runner,
            start_index=start_index,
        )
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
    latency_values = [
        int(check['latency_ms'])
        for check in checks.values()
        if isinstance(check, dict) and check.get('ok') and isinstance(check.get('latency_ms'), int)
    ]

    result: dict[str, Any] = {
        'id': node_id,
        'ok': ok,
        'message': 'ترافیک از این نود عبور می‌کند' if ok else (failure_messages[0] if failure_messages else 'ناموفق'),
        'checks': checks,
    }
    if latency_values:
        result['latency_ms'] = min(latency_values)

    return result


def probe_region_nodes(
    nodes: list[dict[str, Any]],
    outbounds: list[dict[str, Any]] | None = None,
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    if not isinstance(nodes, list) or not nodes:
        raise AgentError('VALIDATION_ERROR', 'nodes list is required')

    valid_nodes = [item for item in nodes if isinstance(item, dict) and item.get('id') is not None]
    if not valid_nodes:
        return {
            'ok': True,
            'nodes': [],
            'summary': {'total': 0, 'passed': 0, 'failed': 0},
        }

    def _probe_item(item: dict[str, Any], index: int) -> dict[str, Any]:
        return probe_region_node(
            node_id=item.get('id'),
            outbound_tag=item.get('outbound_tag'),
            exit_interface=item.get('exit_interface'),
            outbounds=outbounds,
            runner=runner,
            start_index=index,
        )

    # Cap concurrency to the number of distinct probe IPs so route installs overlap
    # without stampeding the same destination across Mullvad Table=off exits.
    max_workers = min(len(PROBE_TARGETS), len(valid_nodes), 6)
    rows: list[dict[str, Any] | None] = [None] * len(valid_nodes)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_probe_item, item, index): index
            for index, item in enumerate(valid_nodes)
        }
        for future, index in future_map.items():
            rows[index] = future.result()

    resolved = [row for row in rows if isinstance(row, dict)]
    passed = sum(1 for row in resolved if row.get('ok'))
    return {
        'ok': True,
        'nodes': resolved,
        'summary': {
            'total': len(resolved),
            'passed': passed,
            'failed': len(resolved) - passed,
        },
    }
