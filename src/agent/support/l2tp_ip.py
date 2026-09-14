from __future__ import annotations

import ipaddress

from agent.errors import AgentError

# Within a shared /16 (e.g. 10.90.0.0/16):
#   WireGuard peers: third octet 0–127
#   L2TP clients:    third octet 128–254
L2TP_THIRD_OCTET_MIN = 128
REQUIRED_PREFIX = 16


def normalize_l2tp_subnet(subnet: str) -> str:
    """L2TP pools must be a /16 supernet."""
    text = str(subnet or '').strip()
    if not text:
        raise AgentError('VALIDATION_ERROR', 'L2TP subnet is required')

    host = text.split('/', 1)[0].strip()
    if '/' not in text:
        text = f'{host}/{REQUIRED_PREFIX}'

    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise AgentError('VALIDATION_ERROR', 'L2TP subnet must be IPv4')
    if network.prefixlen != REQUIRED_PREFIX:
        raise AgentError(
            'VALIDATION_ERROR',
            f'L2TP subnet must be /{REQUIRED_PREFIX} (got /{network.prefixlen})',
        )
    return str(network)


def is_wireguard_host(ip: ipaddress.IPv4Address) -> bool:
    return ip.packed[2] < L2TP_THIRD_OCTET_MIN


def is_l2tp_host(ip: ipaddress.IPv4Address) -> bool:
    return ip.packed[2] >= L2TP_THIRD_OCTET_MIN


def l2tp_gateway(subnet: str) -> str:
    network = ipaddress.ip_network(normalize_l2tp_subnet(subnet), strict=False)
    octets = network.network_address.packed
    return str(ipaddress.ip_address(bytes([octets[0], octets[1], L2TP_THIRD_OCTET_MIN, 1])))


def l2tp_pool_bounds(subnet: str) -> tuple[str, str]:
    """Inclusive start/end for xl2tpd ``ip range``.

    xl2tpd allocates bookkeeping for every address in the range at startup.
    A full upper-/16 slice (*.128.2–*.254.254) can make the daemon exit on start.
    Keep one /24 of L2TP hosts (third octet = 128) — enough for ~253 clients.
    """
    network = ipaddress.ip_network(normalize_l2tp_subnet(subnet), strict=False)
    octets = network.network_address.packed
    start = ipaddress.ip_address(bytes([octets[0], octets[1], L2TP_THIRD_OCTET_MIN, 2]))
    end = ipaddress.ip_address(bytes([octets[0], octets[1], L2TP_THIRD_OCTET_MIN, 254]))
    return str(start), str(end)


def _l2tp_reserved(subnet: str) -> set[str]:
    network = ipaddress.ip_network(normalize_l2tp_subnet(subnet), strict=False)
    reserved = {str(network.network_address), str(network.broadcast_address), l2tp_gateway(subnet)}
    return reserved


def next_l2tp_ip(subnet: str, used: set[str]) -> str:
    reserved = _l2tp_reserved(subnet)
    start, end = l2tp_pool_bounds(subnet)
    start_ip = ipaddress.ip_address(start)
    end_ip = ipaddress.ip_address(end)
    current = int(start_ip)
    last = int(end_ip)
    while current <= last:
        host = ipaddress.ip_address(current)
        label = str(host)
        current += 1
        if label in reserved or label in used:
            continue
        return label
    raise AgentError('VALIDATION_ERROR', 'No free IPs in L2TP pool — widen subnet or remove users')


def assert_l2tp_address(subnet: str, address: str) -> str:
    host = str(address or '').split('/', 1)[0].strip()
    if not host:
        raise AgentError('VALIDATION_ERROR', 'L2TP client address is required')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise AgentError('VALIDATION_ERROR', f'Invalid L2TP address [{host}]') from exc
    if not is_l2tp_host(ip):
        raise AgentError(
            'VALIDATION_ERROR',
            f'L2TP address [{host}] is in the WireGuard range (third octet must be >= {L2TP_THIRD_OCTET_MIN})',
        )
    network = ipaddress.ip_network(normalize_l2tp_subnet(subnet), strict=False)
    if ip not in network:
        raise AgentError('VALIDATION_ERROR', f'L2TP address [{host}] is outside subnet [{subnet}]')

    start, end = l2tp_pool_bounds(subnet)
    if not (ipaddress.ip_address(start) <= ip <= ipaddress.ip_address(end)):
        raise AgentError(
            'VALIDATION_ERROR',
            f'L2TP address [{host}] is outside xl2tpd pool [{start}-{end}]',
        )
    return host


def wireguard_skips_host(ip_text: str) -> bool:
    """True when this host belongs to the L2TP slice and must not be assigned to WG."""
    try:
        ip = ipaddress.ip_address(str(ip_text).split('/', 1)[0].strip())
    except ValueError:
        return False
    return not is_wireguard_host(ip)
