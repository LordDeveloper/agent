"""OpenVPN client IP pool helpers (topology subnet)."""

from __future__ import annotations

import ipaddress
from typing import Iterable

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


def next_openvpn_ip(subnet: str, used: Iterable[str]) -> str:
    network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    taken = {str(item).split('/', 1)[0].strip() for item in used if str(item or '').strip()}
    taken.add(openvpn_gateway(str(network)))
    for host in network.hosts():
        text = str(host)
        if text not in taken:
            return text
    raise AgentError('VALIDATION_ERROR', f'No free OpenVPN IP left in [{network}]', 422)
