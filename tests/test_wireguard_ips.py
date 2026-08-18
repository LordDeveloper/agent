from agent.drivers.wireguard import (
    accumulate_transfer,
    recent_peer_ips,
    remember_peer_ip,
    endpoint_host,
)


def test_endpoint_host_ipv4_and_ipv6():
    assert endpoint_host("203.0.113.10:51820") == "203.0.113.10"
    assert endpoint_host("[2001:db8::1]:51820") == "2001:db8::1"
    assert endpoint_host("2001:db8::1") == "2001:db8::1"
    assert endpoint_host("(none)") is None


def test_remember_and_recent_peer_ips_window():
    peer = {"online": True, "endpoint": "203.0.113.10:1234", "ip_logs": []}
    now = 1_700_000_000
    remember_peer_ip(peer, "203.0.113.10:1234", now=now)
    remember_peer_ip(peer, "198.51.100.8:9999", now=now - 30)
    remember_peer_ip(peer, "192.0.2.1:1", now=now - 1200)

    ips = recent_peer_ips(peer, now=now, window=600)
    assert "203.0.113.10" in ips
    assert "198.51.100.8" in ips
    assert "192.0.2.1" not in ips


def test_accumulate_transfer_records_endpoint_ip():
    peer = {
        "incoming": 0,
        "outgoing": 0,
        "_incoming": 0,
        "_outgoing": 0,
        "ip_logs": [],
    }
    accumulate_transfer(
        peer,
        incoming=10,
        outgoing=5,
        handshake_at=int(__import__("time").time()),
        endpoint="203.0.113.40:51820",
    )
    assert peer["online"] is True
    assert recent_peer_ips(peer) == ["203.0.113.40"]
