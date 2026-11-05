import pytest

from agent.support.bandwidth import (
    IFB_DOWN,
    IFB_UP,
    collect_l2tp_plans,
    collect_openvpn_plans,
    collect_tunnel_plans,
    ifb_commands,
    mbps_to_kbit,
    normalize_bandwidth,
    tunnel_commands,
    BandwidthValueError,
)


def test_mbps_uses_decimal_kilobits():
    assert mbps_to_kbit(1) == 1000
    assert mbps_to_kbit(5) == 5000


def test_null_bandwidth_is_unlimited():
    assert normalize_bandwidth(None) is None
    assert normalize_bandwidth({}) is None
    assert normalize_bandwidth({"download_mbps": None, "upload_mbps": None}) is None


def test_shared_and_directional_values():
    assert normalize_bandwidth(5) == {"download_mbps": 5, "upload_mbps": 5}
    assert normalize_bandwidth({"download_mbps": 10, "upload_mbps": 2}) == {
        "download_mbps": 10,
        "upload_mbps": 2,
    }
    assert normalize_bandwidth({"mbps": 8, "upload_mbps": None}) == {
        "download_mbps": 8,
        "upload_mbps": 8,
    }
    assert normalize_bandwidth({"download_mbps": 4}) == {
        "download_mbps": 4,
        "upload_mbps": None,
    }


@pytest.mark.parametrize("value", [0, -1, 100001, "0", True, 1.5])
def test_invalid_bandwidth_is_rejected(value):
    with pytest.raises(BandwidthValueError):
        normalize_bandwidth(value)


def test_two_tunnel_addresses_share_one_class():
    plans = collect_tunnel_plans([
        {
            "name": "wg0",
            "peers": [
                {
                    "id": "sub-1",
                    "is_enabled": True,
                    "address": "10.8.0.2",
                    "allowed_ips": "10.8.0.2/32,10.8.0.3/32",
                    "bandwidth": {"download_mbps": 5, "upload_mbps": 5},
                },
                {
                    "id": "sub-2",
                    "is_enabled": True,
                    "address": "10.8.0.4",
                    "bandwidth": {"download_mbps": 20, "upload_mbps": 1},
                },
            ],
        }
    ])
    assert len(plans) == 1
    assert len(plans[0].limits) == 2
    first = plans[0].limits[0]
    commands = "\n".join(tunnel_commands("wg0", plans[0].limits))
    assert commands.count(f"classid 1:{first.minor} ") == 1
    assert "match ip dst 10.8.0.2/32" in commands
    assert "match ip dst 10.8.0.3/32" in commands
    assert f"flowid 1:{first.minor}" in commands
    assert "10.8.0.4/32" in commands
    assert "dev wg0 root" in commands
    assert IFB_UP in commands


def test_disabled_and_unlimited_peers_are_omitted():
    plans = collect_tunnel_plans([
        {
            "name": "awg1",
            "peers": [
                {"id": "off", "is_enabled": False, "address": "10.1.0.2", "bandwidth": 5},
                {"id": "free", "is_enabled": True, "address": "10.1.0.3", "bandwidth": None},
            ],
        }
    ])
    assert plans == []


def test_openvpn_sessions_share_the_subscription_class():
    plans = collect_openvpn_plans(
        [
            {
                "id": 4,
                "users": [
                    {
                        "id": "user-1",
                        "username": "alice",
                        "is_enabled": True,
                        "address": "10.9.0.2",
                        "bandwidth": {"download_mbps": 3, "upload_mbps": 3},
                    }
                ],
            }
        ],
        {"alice": ["10.9.0.2", "10.9.0.9"]},
    )
    assert plans[0].name == "ovpn4"
    assert plans[0].limits[0].addresses == ["10.9.0.2", "10.9.0.9"]
    commands = "\n".join(tunnel_commands(plans[0].name, plans[0].limits))
    minor = plans[0].limits[0].minor
    assert commands.count(f"classid 1:{minor} ") == 1
    assert "10.9.0.9/32" in commands


def test_l2tp_sessions_share_one_ifb_class():
    limits, devices = collect_l2tp_plans(
        [
            {
                "users": [
                    {
                        "id": "same",
                        "is_enabled": True,
                        "address": "10.7.0.2",
                        "bandwidth": {"download_mbps": 4, "upload_mbps": 4},
                    }
                ]
            }
        ],
        {
            "10.7.0.2": {"interface": "ppp0"},
            "10.7.0.8": {"interface": "ppp1"},
        },
    )
    assert len(limits) == 1
    assert "ppp0" in devices
    assert "ppp1" not in devices
    limits[0].addresses.append("10.7.0.8")
    commands = "\n".join(ifb_commands(IFB_DOWN, limits, direction="download"))
    minor = limits[0].minor
    assert commands.count(f"classid 1:{minor} ") == 1
    assert "match ip dst 10.7.0.2/32" in commands
    assert "match ip dst 10.7.0.8/32" in commands
    assert "dev ppp0" not in commands
