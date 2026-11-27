from __future__ import annotations

import asyncio

from agent.support import public_source_pin

from agent.support.peer_egress import render_apply_script
from agent.support.public_source_pin import masquerade_rewrites, render_script


def test_source_pin_script_is_a_separate_table_at_priority_minus_200():
    script = render_script(
        {
            "addresses": [{"ip": "8.8.8.8", "mark": 0x51000808}],
            "peers": [{"cidr": "10.7.0.2/32", "snat": "8.8.8.8"}],
        }
    )

    assert "nft add table inet netinja_src" in script
    assert "priority -200" in script
    assert "ip saddr 8.8.8.8 accept" in script
    assert "meta mark 0x51000808 snat ip to 8.8.8.8" in script
    assert "ip saddr 10.7.0.2/32 snat ip to 8.8.8.8" in script
    assert "flush set inet netinja_egress pinned" in script
    assert "nft add element inet netinja_egress pinned '{ 8.8.8.8 }'" in script
    assert "flush set inet netinja_egress peer_src" in script
    assert "nft add element inet netinja_egress peer_src '{ 10.7.0.2 }'" in script
    assert "flush chain inet netinja_egress" not in script
    assert (
        "nft insert rule inet netinja_egress postrouting "
        "ip saddr 10.7.0.2/32 snat ip to 8.8.8.8 "
        "comment '\"netinja-wgsnat-10.7.0.2\"'"
    ) in script


def test_peer_egress_script_does_not_own_the_source_pin_table():
    script = render_apply_script(
        [
            {
                "addr": "10.7.0.2",
                "cidr": "10.7.0.2/32",
                "iface": "eth0",
                "table": 10001,
                "action": "lookup",
                "snat": "8.8.8.8",
            }
        ],
        public_pins=[{"ip": "8.8.8.8", "mark": 1}],
    )

    assert "nft add table inet netinja_src" not in script
    assert "flush chain inet netinja_src" not in script
    assert "nft flush chain inet netinja_egress srcpin" not in script
    assert "flush set inet netinja_egress pinned" not in script
    assert 'ip saddr 10.7.0.2/32 snat ip to 8.8.8.8 comment' in script
    assert 'oifname "eth0" snat ip to 8.8.8.8 comment' in script
    assert 'snat ip to 8.8.8.8 accept' not in script
    assert 'ip saddr != @pinned ip saddr != @peer_src masquerade' in script
    assert "flush set inet netinja_egress peer_src" not in script


def test_existing_masquerade_is_rewritten_to_skip_pinned_sources():
    listing = """
    chain postrouting {
        oifname "eth0" ip saddr != @pinned masquerade comment "netinja-egress-eth0" # handle 7
        iifname "wg0" oifname "eth0" ip saddr != @pinned ip saddr != @peer_src masquerade comment "kept" # handle 8
    }
    """
    rewrites = masquerade_rewrites(listing)
    assert len(rewrites) == 1
    handle, args = rewrites[0]
    assert handle == "7"
    assert args[args.index("oifname") + 1] == "eth0"
    assert args[args.index("@pinned") - 1] == "!="
    assert "@peer_src" in args
    assert "masquerade" in args


def test_host_address_exemption_survives_xray_rebuild(tmp_path, monkeypatch):
    config = tmp_path / "xray.json"
    config.write_text('{"outbounds": []}', encoding="utf-8")
    previous = {"addresses": [{"ip": "64.49.15.27", "mark": 0, "preserve": True}], "peers": []}
    monkeypatch.setattr(public_source_pin, "load_state", lambda: previous)
    monkeypatch.setattr(public_source_pin, "_install_enabled", lambda: False)

    state = asyncio.run(public_source_pin.rebuild_from_host(None, config))

    assert state["addresses"] == previous["addresses"]
    script = render_script(state)
    assert "pinned '{ 64.49.15.27 }'" in script
    assert "snat ip to 64.49.15.27" not in script
