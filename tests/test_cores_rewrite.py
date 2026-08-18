from pathlib import Path

import os

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from agent.support import normalize_peer, normalize_xray_client, xray_protocol_user, xray_users_settings


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(("LISTEN", "AUTH_", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "XRAY_", "WIREGUARD_", "AMNEZIA_", "ENV_FILE")) or key in {
            "LISTEN",
            "DATA_DIR",
            "DB_PATH",
            "ENABLED_CORES",
            "ENV_FILE",
        }:
            os.environ.pop(key, None)


@pytest.fixture()
def wg_client(tmp_path, monkeypatch):
    _clear_env()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    conf = tmp_path / "wg"
    conf.mkdir()
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data.as_posix()}",
                "ENABLED_CORES=wireguard",
                f"WIREGUARD_CONFIG_DIR={conf.as_posix()}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("agent.drivers.wireguard.WireGuardDriver._bring_up", lambda self, iface: {"ok": True})
    monkeypatch.setattr("agent.drivers.wireguard.WireGuardDriver._bring_down", lambda self, iface: {"ok": True})
    monkeypatch.setattr("agent.drivers.wireguard.WireGuardDriver._apply_live", lambda self, iface: None)
    with TestClient(create_app(str(env))) as client:
        yield client
    _clear_env()


def test_normalize_xray_client_uses_netinja_fields():
    row = normalize_xray_client(
        {
            "id": "u1",
            "email": "abc",
            "is_enabled": True,
            "volume": 1024**3,
            "max_connection": 2,
            "expires_at": "2030-01-01T00:00:00+00:00",
            "incoming": 10,
            "outgoing": 20,
        }
    )
    assert row["is_enabled"] is True
    assert row["max_connection"] == 2
    assert row["volume"] == 1024**3
    assert row["expires_at"].startswith("2030-01-01")
    assert row["incoming"] == 10
    assert row["outgoing"] == 20
    assert "enable" not in row
    assert "limitIp" not in row
    assert "totalGB" not in row
    assert "expiryTime" not in row
    assert "up" not in row
    assert "down" not in row


def test_normalize_xray_client_maps_legacy_xui_then_drops_them():
    row = normalize_xray_client(
        {
            "id": "u1",
            "email": "abc",
            "enable": "1",
            "totalGB": 1073741824,
            "limitIp": "3",
            "expiryTime": {"date": "2030-01-01 00:00:00", "timezone": "UTC"},
            "down": {"uplink": 1},
            "up": ["bad"],
        }
    )
    assert row["is_enabled"] is True
    assert row["max_connection"] == 3
    assert row["volume"] == 1073741824
    assert row["expires_at"].startswith("2030-01-01")
    assert row["incoming"] == 0
    assert row["outgoing"] == 0
    assert "enable" not in row
    assert "totalGB" not in row
    assert "limitIp" not in row
    assert "expiryTime" not in row
    assert "down" not in row
    assert "up" not in row
    assert "subId" not in row
    assert "tgId" not in row


def test_normalize_peer_maps_legacy_xui_then_drops_them():
    row = normalize_peer(
        {
            "name": "peer1",
            "enable": False,
            "totalGB": 2048,
            "limitIp": 1,
            "expiryTime": 1893456000000,
            "down": 11,
            "up": 22,
            "subId": 9,
            "tgId": 8,
        }
    )
    assert row["email"] == "peer1"
    assert row["is_enabled"] is False
    assert row["max_connection"] == 1
    assert row["volume"] == 2048
    assert row["expires_at"].startswith("2030-01-01")
    assert row["incoming"] == 11
    assert row["outgoing"] == 22
    assert "enable" not in row
    assert "totalGB" not in row
    assert "limitIp" not in row
    assert "expiryTime" not in row
    assert "up" not in row
    assert "down" not in row
    assert "subId" not in row
    assert "tgId" not in row


def test_xray_protocol_user_strips_netinja_fields_and_null_flow():
    user = xray_protocol_user(
        "vless",
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "abc",
            "flow": None,
            "encryption": "none",
            "is_enabled": True,
            "volume": 1024,
            "incoming": 1,
            "outgoing": 2,
            "expires_at": "2030-01-01T00:00:00+00:00",
            "max_connection": 3,
            "subscribe_id": 9,
            "password": "secret",
        },
    )
    assert user == {
        "id": "11111111-1111-1111-1111-111111111111",
        "email": "abc",
    }


def test_xray_protocol_user_keeps_vision_flow():
    user = xray_protocol_user(
        "vless",
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "abc",
            "flow": "xtls-rprx-vision",
        },
    )
    assert user["flow"] == "xtls-rprx-vision"


def test_xray_users_settings_adds_vless_decryption():
    settings = xray_users_settings(
        "vless",
        {"fallbacks": [{"dest": 80}]},
        [{"id": "11111111-1111-1111-1111-111111111111", "email": "abc", "volume": 1}],
    )
    assert settings["decryption"] == "none"
    assert settings["clients"] == settings["users"]
    assert settings["clients"] == [{"id": "11111111-1111-1111-1111-111111111111", "email": "abc"}]
    assert settings["fallbacks"] == [{"dest": 80}]


def test_validate_wg_conf_strip_uses_absolute_config_path(tmp_path, monkeypatch):
    from agent.support.config_validate import validate_wg_conf_stripped

    seen: dict[str, list[str]] = {}

    def fake_run(args, **kwargs):
        seen["args"] = list(args)

        class Result:
            returncode = 0
            stdout = "[Interface]\nPrivateKey = x\nListenPort = 51820\n"
            stderr = ""

        return Result()

    monkeypatch.setattr("agent.support.config_validate.subprocess.run", fake_run)
    conf_dir = tmp_path / "amneziawg"
    conf_dir.mkdir()
    out = validate_wg_conf_stripped(
        "[Interface]\nPrivateKey = x\nListenPort = 51820\n",
        quick_bin="awg-quick",
        config_dir=conf_dir,
    )
    assert seen["args"][0] == "awg-quick"
    assert seen["args"][1] == "strip"
    conf_path = Path(seen["args"][2])
    assert conf_path.is_absolute()
    assert conf_path.suffix == ".conf"
    assert conf_path.parent == conf_dir
    assert out.startswith("[Interface]")


def test_wireguard_interfaces_and_peers(wg_client):
    headers = {"Authorization": "Bearer dev-token"}
    r = wg_client.post(
        "/api/v1/cores/wireguard/interfaces",
        headers=headers,
        json={"id": 7, "listen_port": 51820, "subnet": "10.9.0.0/24"},
    )
    assert r.status_code == 200, r.text
    iface = r.json()["interface"]
    assert iface["id"] == 7
    assert iface["name"] == "wg7"
    assert "tag" not in iface or not str(iface.get("tag", "")).startswith("inbound-")

    r = wg_client.get("/api/v1/cores/wireguard/inbounds", headers=headers)
    assert r.status_code == 404

    r = wg_client.post(
        "/api/v1/cores/wireguard/interfaces/7/peers",
        headers=headers,
        json={"email": "peer1", "is_enabled": True, "volume": 1024, "incoming": 0, "outgoing": 0},
    )
    assert r.status_code == 200, r.text
    peer = r.json()["peer"]
    assert peer["email"] == "peer1"
    assert peer["is_enabled"] is True
    assert peer["volume"] == 1024
    assert "enable" not in peer
    assert "totalGB" not in peer
    assert "up" not in peer
    assert "down" not in peer

    r = wg_client.get("/api/v1/stats/snapshot?core=wireguard", headers=headers)
    assert r.status_code == 200
    assert r.json()["inbounds"][0]["clients"][0]["email"] == "peer1"

    r = wg_client.post("/api/v1/cores/wireguard/backup", headers=headers)
    assert r.status_code == 200
    assert r.json()["backup"]["interfaces"]


def test_wireguard_interfaces_get_distinct_subnets(wg_client):
    headers = {"Authorization": "Bearer dev-token"}
    first = wg_client.post(
        "/api/v1/cores/wireguard/interfaces",
        headers=headers,
        json={"id": 1, "listen_port": 51821},
    )
    second = wg_client.post(
        "/api/v1/cores/wireguard/interfaces",
        headers=headers,
        json={"id": 2, "listen_port": 51822},
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    a = first.json()["interface"]["subnet"]
    b = second.json()["interface"]["subnet"]
    assert a != b
    assert a.endswith("/24") and b.endswith("/24")
    assert 80 <= int(a.split(".")[1]) <= 95
    assert 80 <= int(b.split(".")[1]) <= 95
