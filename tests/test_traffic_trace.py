import pytest

from agent.support.traffic_trace import classify_public_exit, parse_destination


def test_parse_destination_host_ip_and_port():
    assert parse_destination(None) == {}
    assert parse_destination("example.com") == {"domain": "example.com"}
    assert parse_destination("Example.COM:443") == {"domain": "example.com", "port": 443}
    assert parse_destination("1.1.1.1") == {"ip": "1.1.1.1"}
    assert parse_destination("[2001:db8::1]:443") == {"ip": "2001:db8::1", "port": 443}


def test_parse_destination_rejects_junk():
    with pytest.raises(ValueError):
        parse_destination("example.com;id")
    with pytest.raises(ValueError):
        parse_destination("example.com:99999")


def test_classify_public_exit_never_treats_a_host_nic_as_verified():
    result = classify_public_exit(
        probe_ip="91.107.169.147",
        iface_addresses=["91.107.169.147"],
        bound_iface="eth0",
    )
    assert result["basis"] == "UNVERIFIED"
    assert result["ip"] is None


def test_classify_public_exit_rejects_the_interface_address():
    result = classify_public_exit(
        probe_ip="185.213.154.10",
        iface_addresses=["185.213.154.10/32"],
        bound_iface="wg-fi",
    )
    assert result["basis"] == "UNVERIFIED"
    assert result["ip"] is None


def test_classify_public_exit_accepts_a_remote_probe():
    result = classify_public_exit(
        probe_ip="185.213.154.10",
        iface_addresses=["10.64.0.2"],
        bound_iface="wg-fi",
    )
    assert result["basis"] == "verified"
    assert result["ip"] == "185.213.154.10"


def test_classify_public_exit_without_a_binding_is_unverified():
    result = classify_public_exit(
        probe_ip="185.213.154.10",
        iface_addresses=[],
        bound_iface=None,
    )
    assert result["basis"] == "UNVERIFIED"
    assert result["ip"] is None
