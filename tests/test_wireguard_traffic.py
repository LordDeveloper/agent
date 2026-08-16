from agent.drivers.wireguard import accumulate_transfer


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
