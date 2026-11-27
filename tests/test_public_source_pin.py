from __future__ import annotations

from agent.support.peer_egress import render_apply_script
from agent.support.public_source_pin import render_script


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
    assert "netinja_egress" not in script


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
