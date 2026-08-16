import os

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from agent.support import normalize_xray_client


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


def test_normalize_xray_client_aliases():
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
    assert row["enable"] is True
    assert row["limitIp"] == 2
    assert abs(row["totalGB"] - 1.0) < 0.001
    assert row["expiryTime"] > 0
    assert row["down"] == 10
    assert row["up"] == 20


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
        json={"email": "peer1", "is_enabled": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["peer"]["email"] == "peer1"

    r = wg_client.get("/api/v1/stats/snapshot?core=wireguard", headers=headers)
    assert r.status_code == 200
    assert r.json()["inbounds"][0]["clients"][0]["email"] == "peer1"

    r = wg_client.post("/api/v1/cores/wireguard/backup", headers=headers)
    assert r.status_code == 200
    assert r.json()["backup"]["interfaces"]
