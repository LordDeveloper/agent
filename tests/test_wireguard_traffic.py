from agent.drivers.wireguard import (
    WireGuardDriver,
    _assign_peer_address,
    _next_ip,
    _repair_reserved_peer_addresses,
    _reserved_peer_addresses,
    _server_address,
    accumulate_transfer,
)


def test_server_address_is_first_host():
    assert _server_address("10.80.0.0/24") == "10.80.0.1"


def test_reserved_peer_addresses_skip_gateway_and_broadcast():
    reserved = _reserved_peer_addresses("10.80.0.0/24")
    assert reserved == {"10.80.0.0", "10.80.0.1", "10.80.0.254", "10.80.0.255"}


def test_next_ip_skips_gateway_broadcast_and_last_host():
    assert _next_ip("10.80.0.0/24", set()) == "10.80.0.2"
    assert _next_ip("10.80.0.0/24", {"10.80.0.2"}) == "10.80.0.3"


def test_assign_peer_address_rejects_gateway():
    peer: dict = {"address": "10.90.68.1"}
    _assign_peer_address(peer, "10.90.68.0/24", set())
    assert peer["address"] == "10.90.68.2"
    assert peer["allowed_ips"] == "10.90.68.2/32"


def test_assign_peer_address_keeps_valid_requested():
    peer: dict = {"address": "10.90.68.5"}
    _assign_peer_address(peer, "10.90.68.0/24", set())
    assert peer["address"] == "10.90.68.5"
    assert peer["allowed_ips"] == "10.90.68.5/32"


def test_repair_reserved_peer_addresses():
    iface = {
        "subnet": "10.90.68.0/24",
        "peers": [
            {"id": "a", "address": "10.90.68.1", "allowed_ips": "10.90.68.1/32"},
            {"id": "b", "address": "10.90.68.5", "allowed_ips": "10.90.68.5/32"},
        ],
    }
    assert _repair_reserved_peer_addresses(iface) is True
    assert iface["peers"][0]["address"] == "10.90.68.2"
    assert iface["peers"][0]["allowed_ips"] == "10.90.68.2/32"
    assert iface["peers"][1]["address"] == "10.90.68.5"


def test_merge_peer_row_keeps_address_and_allowed_ips():
    driver = WireGuardDriver.__new__(WireGuardDriver)
    before = {
        "id": "S66SZo",
        "email": "S66SZo",
        "address": "10.90.68.5",
        "allowed_ips": "10.90.68.5/32",
        "private_key": "priv",
        "public_key": "pub",
        "volume": 10,
    }
    merged = driver._merge_peer_row(
        before,
        {
            "address": "10.90.68.1",
            "allowed_ips": "10.90.68.1/32",
            "volume": 999,
            "private_key": "other",
            "public_key": "other-pub",
        },
    )
    assert merged["address"] == "10.90.68.5"
    assert merged["allowed_ips"] == "10.90.68.5/32"
    assert merged["volume"] == 999
    assert merged["private_key"] == "priv"
    assert merged["public_key"] == "pub"


def test_peer_config_includes_default_mtu(monkeypatch):
    driver = WireGuardDriver.__new__(WireGuardDriver)
    driver.key = "wireguard"
    assert driver._client_mtu() == 1420
    driver.key = "amnezia"
    assert driver._client_mtu() == 1280
    assert driver._client_mtu({"mtu": 1360}) == 1360


def test_accumulate_transfer_delta():
    peer = {"incoming": 100, "outgoing": 50, "_incoming": 40, "_outgoing": 20}
    accumulate_transfer(peer, incoming=70, outgoing=35)
    assert peer["incoming"] == 130  # 100 + (70 - 40)
    assert peer["outgoing"] == 65  # 50 + (35 - 20)
    assert peer["_incoming"] == 70
    assert peer["_outgoing"] == 35


def test_accumulate_transfer_after_reboot_reset():
    peer = {"incoming": 1000, "outgoing": 800, "_incoming": 900, "_outgoing": 700}
    # Kernel counters restarted; new raw is smaller than last snapshot.
    accumulate_transfer(peer, incoming=50, outgoing=30, handshake_at=1_700_000_000)
    assert peer["incoming"] == 1050  # 1000 + 50
    assert peer["outgoing"] == 830  # 800 + 30
    assert peer["_incoming"] == 50
    assert peer["_outgoing"] == 30
    assert peer["handshake_at"]
    assert peer["online"] is False  # handshake timestamp is old vs now


def test_accumulate_transfer_no_handshake_keeps_previous_offline():
    peer = {
        "incoming": 0,
        "outgoing": 0,
        "_incoming": 0,
        "_outgoing": 0,
        "handshake_at": "2020-01-01T00:00:00+00:00",
        "online": True,
    }
    accumulate_transfer(peer, incoming=10, outgoing=5, handshake_at=0)
    assert peer["incoming"] == 10
    assert peer["outgoing"] == 5
    assert peer["online"] is False
    assert peer["handshake_at"] == "2020-01-01T00:00:00+00:00"
