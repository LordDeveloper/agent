"""Connectivity probes for region server nodes (exit interface / Xray outbound)."""

from __future__ import annotations

import ipaddress
import re
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
#
# Many distinct IPs let parallel node probes install non-conflicting /32 routes.
# Any HTTP status (incl. 301/302) proves egress — redirects are success, not failure.
PROBE_URLS: tuple[str, ...] = (
    'http://1.1.1.1/cdn-cgi/trace',
    'http://1.0.0.1/cdn-cgi/trace',
    'http://8.8.8.8/',
    'http://8.8.4.4/',
    'http://9.9.9.9/',
    'http://149.112.112.112/',
    'http://208.67.222.222/',
    'http://208.67.220.220/',
    'http://94.140.14.14/',
    'http://94.140.15.15/',
    'http://185.228.168.9/',
    'http://76.76.2.0/',
)
# Back-compat for tests / imports that still reference PROBE_TARGETS.
PROBE_TARGETS: tuple[tuple[str, frozenset[int]], ...] = tuple(
    (url, frozenset(range(100, 600))) for url in PROBE_URLS
)
PROBE_TIMEOUT = 4
CONNECT_TIMEOUT = 3
MAX_PROBE_ATTEMPTS = 3
MAX_PROBE_WORKERS = 12
BIND_ERROR_CODES = frozenset({45, 55})
# Mullvad/WG exits: host curl can flake on Table=off while the tunnel still carries peers.
# A recent handshake means the interface is online for panel health.
HANDSHAKE_ONLINE_MAX_AGE = 180

# Panel ping is always ICMP via the exit iface (not curl time_total).
PING_TARGET = '8.8.8.8'
PING_WAIT_SECONDS = 2

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


def _rotated_probe_urls(start_index: int = 0, *, limit: int | None = None) -> list[str]:
    urls = list(PROBE_URLS)
    if not urls:
        return []
    offset = int(start_index or 0) % len(urls)
    rotated = urls[offset:] + urls[:offset] if offset > 0 else urls
    if limit is None or limit <= 0:
        return rotated
    return rotated[:limit]


def _rotated_probe_targets(start_index: int = 0) -> list[tuple[str, frozenset[int]]]:
    """Legacy helper kept for tests — prefer _rotated_probe_urls."""
    return [(url, frozenset(range(100, 600))) for url in _rotated_probe_urls(start_index)]


def _http_code_means_egress(http_code: int) -> bool:
    """Any real HTTP status means the packet left via the bound interface."""
    return 100 <= int(http_code or 0) < 600


def _wg_latest_handshake(iface: str, *, runner: Runner | None = None) -> int | None:
    name = str(iface or '').strip()
    if not name or _looks_like_ip(name) or not shutil.which('wg'):
        return None
    execute = _runner(runner)
    try:
        result = execute(['wg', 'show', name, 'latest-handshakes'], check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw_code = getattr(result, 'returncode', 1)
    if int(0 if raw_code is None else raw_code) != 0:
        return None
    newest = 0
    for line in (getattr(result, 'stdout', '') or '').splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ts = int(parts[-1])
        except ValueError:
            continue
        newest = max(newest, ts)
    return newest or None


def _wg_has_recent_handshake(
    iface: str,
    *,
    runner: Runner | None = None,
    max_age: int = HANDSHAKE_ONLINE_MAX_AGE,
) -> bool:
    handshake = _wg_latest_handshake(iface, runner=runner)
    if not handshake or int(handshake) <= 0:
        return False
    age = max(0, int(time.time()) - int(handshake))
    return age <= max(1, int(max_age))


_PING_TIME_RE = re.compile(
    r'(?:time|rtt)[=<>]\s*([0-9]+(?:\.[0-9]+)?)\s*ms',
    re.IGNORECASE,
)


def _iface_ping_ms(
    interface: str | None,
    *,
    runner: Runner | None = None,
    target: str = PING_TARGET,
) -> int | None:
    """Panel ping: ``ping -I <iface> 8.8.8.8`` (with temp /32 for Table=off)."""
    bind = _resolve_curl_bind(interface, runner=runner)
    dest = str(target or '').strip() or PING_TARGET
    if not bind or not dest or not shutil.which('ping'):
        return None

    execute = _runner(runner)
    cmd = ['ping', '-4', '-n', '-c', '1', '-W', str(PING_WAIT_SECONDS), '-I', bind, dest]
    # Named ifaces with Table=off need a host route so ICMP leaves via that device.
    route_iface = None if _looks_like_ip(bind) else bind
    try:
        with _host_routes_for_iface(route_iface, [dest], runner=execute):
            result = execute(cmd, check=False, timeout=PING_WAIT_SECONDS + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None

    body = f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    match = _PING_TIME_RE.search(body)
    if not match:
        return None
    try:
        return max(1, int(round(float(match.group(1)))))
    except ValueError:
        return None


def _handshake_online_result(
    iface: str,
    *,
    runner: Runner | None = None,
    latency_ms: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        'ok': True,
        'message': 'تونل آنلاین (handshake)',
        'interface': iface,
        'via': 'handshake',
    }
    ping_ms = latency_ms if latency_ms is not None else _iface_ping_ms(iface, runner=runner)
    if ping_ms is not None:
        result['latency_ms'] = ping_ms
        result['message'] = 'تونل آنلاین (handshake)'
    return result


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


def _ip_route_replace_dev(
    dest: str,
    iface: str,
    *,
    runner: Runner,
    src: str | None = None,
) -> bool:
    cmd = ['ip', 'route', 'replace', f'{dest}/32', 'dev', iface]
    source = str(src or '').strip()
    if source and _looks_like_ip(source):
        cmd.extend(['src', source])
    result = runner(cmd, check=False, timeout=5)
    code = getattr(result, 'returncode', 1)
    return int(0 if code is None else code) == 0


def _ip_route_del_dev(dest: str, iface: str, *, runner: Runner) -> None:
    runner(
        ['ip', 'route', 'del', f'{dest}/32', 'dev', iface],
        check=False,
        timeout=5,
    )


def _curl_interface_arg(bind: str | None) -> str | None:
    """Return curl --interface value. Keep bare names for older curl compatibility."""
    text = str(bind or '').strip()
    return text or None


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
    src = next(iter(sorted(_interface_addresses(bind, runner=execute))), None)
    try:
        for dest in ordered:
            try:
                if _ip_route_replace_dev(dest, bind, runner=execute, src=src):
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
    urls = _rotated_probe_urls(start_index, limit=MAX_PROBE_ATTEMPTS)

    # Install one /32 at a time so parallel probes on different IPs can overlap.
    for url in urls:
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
            curl_bind = _curl_interface_arg(bind)
            if curl_bind:
                cmd[1:1] = ['--interface', curl_bind]

            try:
                result = execute(cmd, check=False, timeout=per_try_timeout)
            except subprocess.TimeoutExpired:
                errors.append(f'Connection timed out after {per_try_timeout}s ({url})')
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
                if _http_code_means_egress(http_code):
                    return True, 'اتصال برقرار شد', latency_ms
                errors.append(f'HTTP {http_code or "?"}')
                continue

            # Normalize curl 28 so the panel can show a clear timeout label.
            if code == 28 or 'timed out' in stderr.lower() or 'timeout' in stderr.lower():
                errors.append(stderr or f'Connection timed out (curl exit {code})')
            else:
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
    """Skip duplicate exit probe when outbound already curls the same named iface.

    Mullvad freedom outbounds often use a shared tunnel Address as sendThrough; the
    outbound probe prefers exit_interface as --interface, so a second exit_interface
    curl only doubles load and creates false timeouts under parallel batch probes.
    """
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
    if not bind and not iface:
        return False

    preferred = _prefer_named_bind(bind, iface, runner=runner)
    return preferred == iface


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

    # Traffic path = curl; panel ping = ping -I (never curl time_total).
    ok, message, _curl_latency = _curl_probe(interface=iface, runner=runner, start_index=start_index)
    ping_ms = _iface_ping_ms(iface, runner=runner)

    if ok:
        row: dict[str, Any] = {
            'ok': True,
            'message': message,
            'interface': iface,
            'via': 'egress',
        }
        if ping_ms is not None:
            row['latency_ms'] = ping_ms
        return row

    # Curl egress flake on Table=off Mullvad — recent handshake = interface online.
    if _wg_has_recent_handshake(iface, runner=runner):
        return _handshake_online_result(iface, runner=runner, latency_ms=ping_ms)

    failed: dict[str, Any] = {'ok': False, 'message': message, 'interface': iface}
    if ping_ms is not None:
        failed['latency_ms'] = ping_ms
    return failed


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
        ok, message, _curl_latency = _curl_probe(
            interface=bind_iface,
            runner=runner,
            start_index=start_index,
        )
        ping_ms = _iface_ping_ms(bind_iface, runner=runner)

        if ok:
            row = {
                'ok': True,
                'message': message,
                'protocol': protocol,
                'interface': bind_iface,
                'via': 'egress',
            }
            if ping_ms is not None:
                row['latency_ms'] = ping_ms
            return row

        if not _looks_like_ip(bind_iface) and _wg_has_recent_handshake(bind_iface, runner=runner):
            row = _handshake_online_result(bind_iface, runner=runner, latency_ms=ping_ms)
            row['protocol'] = protocol
            return row

        failed = {
            'ok': False,
            'message': message,
            'protocol': protocol,
            'interface': bind_iface,
        }
        if ping_ms is not None:
            failed['latency_ms'] = ping_ms
        return failed

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

    # Parallel across nodes; each node starts on a different probe IP so /32 route
    # locks rarely contend (Table=off Mullvad exits need host routes per dest).
    max_workers = min(MAX_PROBE_WORKERS, len(PROBE_URLS), len(valid_nodes))
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
