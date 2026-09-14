import ipaddress

import pytest

from agent.errors import AgentError
from agent.support.l2tp_ip import (
    assert_l2tp_address,
    is_l2tp_host,
    is_wireguard_host,
    l2tp_gateway,
    l2tp_pool_bounds,
    next_l2tp_ip,
    normalize_l2tp_subnet,
    wireguard_skips_host,
)


def test_normalize_l2tp_subnet_requires_slash_16():
    assert normalize_l2tp_subnet('10.90.0.0') == '10.90.0.0/16'
    assert normalize_l2tp_subnet('10.90.0.0/16') == '10.90.0.0/16'
    with pytest.raises(AgentError):
        normalize_l2tp_subnet('10.90.0.0/24')


def test_wireguard_and_l2tp_ranges_do_not_overlap():
    for third in range(256):
        ip = ipaddress.ip_address(f'10.90.{third}.10')
        assert is_wireguard_host(ip) != is_l2tp_host(ip)
        if third < 128:
            assert is_wireguard_host(ip)
            assert wireguard_skips_host(str(ip)) is False
        else:
            assert is_l2tp_host(ip)
            assert wireguard_skips_host(str(ip)) is True


def test_l2tp_gateway_and_pool_in_upper_slice():
    subnet = '10.90.0.0/16'
    assert l2tp_gateway(subnet) == '10.90.128.1'
    start, end = l2tp_pool_bounds(subnet)
    assert start == '10.90.128.2'
    # xl2tpd cannot boot with a multi-/24 range — keep one /24.
    assert end == '10.90.128.254'


def test_next_l2tp_ip_skips_wireguard_range():
    used = set()
    first = next_l2tp_ip('10.90.0.0/16', used)
    assert first == '10.90.128.2'
    used.add(first)
    second = next_l2tp_ip('10.90.0.0/16', used)
    assert second == '10.90.128.3'


def test_matching_l2tp_subnet_picks_the_pool_that_contains_the_host():
    from agent.support.l2tp_ip import matching_l2tp_subnet

    assert matching_l2tp_subnet('10.188.128.3', ['10.164.0.0/16', '10.188.0.0/16']) == '10.188.0.0/16'
    assert matching_l2tp_subnet('10.188.128.3', ['10.164.0.0/16']) is None


def test_assert_l2tp_address_rejects_wireguard_slice():
    with pytest.raises(AgentError):
        assert_l2tp_address('10.90.0.0/16', '10.90.0.50')
