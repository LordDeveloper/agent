"""OpenVPN client IP pool helpers (topology subnet)."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from agent.errors import AgentError


def normalize_openvpn_subnet(value: str) -> str:
    text = str(value or '').strip()
    if not text:
        raise AgentError('VALIDATION_ERROR', 'OpenVPN subnet is required', 422)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise AgentError('VALIDATION_ERROR', f'Invalid OpenVPN subnet [{text}]', 422) from exc
    if network.version != 4:
        raise AgentError('VALIDATION_ERROR', 'OpenVPN subnet must be IPv4', 422)
    if network.prefixlen > 28 or network.prefixlen < 16:
        raise AgentError('VALIDATION_ERROR', 'OpenVPN subnet prefix must be /16../28', 422)
    return str(network)


def openvpn_gateway(subnet: str) -> str:
    network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    # First usable host is the server (gateway) in topology subnet.
    return str(next(network.hosts()))


def openvpn_netmask(subnet: str) -> str:
    network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    return str(network.netmask)


def assert_openvpn_address(subnet: str, address: str) -> str:
    host = str(address or '').split('/', 1)[0].strip()
    if not host:
        raise AgentError('VALIDATION_ERROR', 'OpenVPN address is required', 422)
    try:
        ip = ipaddress.ip_address(host)
        network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    except ValueError as exc:
        raise AgentError('VALIDATION_ERROR', f'Invalid OpenVPN address [{address}]', 422) from exc
    if ip.version != 4 or ip not in network:
        raise AgentError('VALIDATION_ERROR', f'Address [{host}] outside subnet [{network}]', 422)
    gateway = openvpn_gateway(str(network))
    if str(ip) == gateway or str(ip) == str(network.network_address) or str(ip) == str(network.broadcast_address):
        raise AgentError('VALIDATION_ERROR', f'Address [{host}] is reserved in [{network}]', 422)
    return str(ip)


def openvpn_host(value: Any) -> str:
    text = str(value or '').split('/', 1)[0].strip()
    if not text:
        return ''
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def move_holders_off_address(
    users: list[dict[str, Any]],
    subnet: str,
    requested: str,
    used_elsewhere: Iterable[str] = (),
    *,
    keep_user: dict[str, Any] | None = None,
    floor: str | None = None,
) -> list[tuple[str, str, str]]:
    """Free `requested` on this server by moving other users to a spare host.

    The caller is about to leave `keep_user`'s current address, so that host
    may be reused. Addresses owned by a different server stay in `used_elsewhere`
    and are never taken. Returns ``(label, old, new)`` for each user moved.
    """
    requested = openvpn_host(requested)
    taken = {openvpn_host(item) for item in used_elsewhere if openvpn_host(item)}
    taken.add(requested)
    for user in users:
        if keep_user is not None and user is keep_user:
            continue
        addr = openvpn_host(user.get('address'))
        if addr and addr != requested:
            taken.add(addr)

    moved: list[tuple[str, str, str]] = []
    for user in users:
        if keep_user is not None and user is keep_user:
            continue
        current = openvpn_host(user.get('address'))
        if current != requested:
            continue
        new_addr = next_openvpn_ip(subnet, taken, start_after=floor)
        user['address'] = new_addr
        taken.add(new_addr)
        label = str(user.get('email') or user.get('id') or '?')
        moved.append((label, current, new_addr))
    return moved


def widen_openvpn_subnet_for_host(subnet: str, host: str) -> str | None:
    """Return the containing /16 when ``host`` is outside ``subnet`` but inside that /16."""
    text = openvpn_host(host)
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
        network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    except (AgentError, ValueError):
        return None
    if ip.version != 4 or ip in network or network.prefixlen <= 16:
        return None
    octets = network.network_address.packed
    parent = ipaddress.ip_network(f'{octets[0]}.{octets[1]}.0.0/16', strict=False)
    if ip not in parent:
        return None
    return str(parent)


def next_openvpn_ip(subnet: str, used: Iterable[str], *, start_after: str | None = None) -> str:
    network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    taken = {str(item).split('/', 1)[0].strip() for item in used if str(item or '').strip()}
    taken.add(openvpn_gateway(str(network)))
    floor = openvpn_host(start_after)
    floor_ip = None
    if floor:
        try:
            floor_ip = ipaddress.ip_address(floor)
        except ValueError:
            floor_ip = None
    for host in network.hosts():
        if floor_ip is not None and int(host) <= int(floor_ip):
            continue
        text = str(host)
        if text not in taken:
            return text
    raise AgentError('VALIDATION_ERROR', f'No free OpenVPN IP left in [{network}]', 422)
