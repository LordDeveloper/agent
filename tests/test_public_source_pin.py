from __future__ import annotations

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
    assert "meta mark 0x51000808 snat to 8.8.8.8 accept" in script
    assert "ip saddr 10.7.0.2/32 snat to 8.8.8.8 accept" in script
    assert "flush set inet netinja_egress pinned" in script
    assert "nft add element inet netinja_egress pinned '{ 8.8.8.8 }'" in script
    assert "flush chain inet netinja_egress" not in script


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
    assert 'ip saddr != @pinned masquerade' in script


def test_existing_masquerade_is_rewritten_to_skip_pinned_sources():
    listing = """
    chain postrouting {
        oifname "eth0" masquerade comment "netinja-egress-eth0" # handle 7
        iifname "wg0" oifname "eth0" ip saddr != @pinned masquerade comment "kept" # handle 8
    }
    """
    rewrites = masquerade_rewrites(listing)
    assert len(rewrites) == 1
    handle, args = rewrites[0]
    assert handle == "7"
    assert args[args.index("oifname") + 1] == "eth0"
    assert args[args.index("!=") + 1] == "@pinned"
    assert "masquerade" in args
