import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from tests.fake_xray import FakeXrayHttpClient

_CLEAR_PREFIXES = (
    "LISTEN",
    "AUTH_",
    "DATA_DIR",
    "DB_PATH",
    "ENABLED_CORES",
    "XRAY_",
    "WIREGUARD_",
    "AMNEZIA_",
    "ENV_FILE",
)


def _sample_inbound(inbound_id: int = 1, port: int = 443) -> dict:
    return {
        "id": inbound_id,
        "port": port,
        "listen": "0.0.0.0",
        "protocol": "vless",
        "streamSettings": {
            "network": "tcp",
            "security": "none",
            "tcpSettings": {"acceptProxyProtocol": True},
        },
        "settings": {"decryption": "none", "clients": []},
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "fakedns"],
        },
    }


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(_CLEAR_PREFIXES) or key in {"LISTEN", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "ENV_FILE"}:
            os.environ.pop(key, None)


def _write_env(path: Path, data_dir: Path, cores: str = "xray,wireguard,amnezia") -> None:
    path.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data_dir.as_posix()}",
                f"ENABLED_CORES={cores}",
                "XRAY_API_BASE=http://127.0.0.1:8080",
                "XRAY_BINARY=/usr/local/bin/xray",
                "",
            ]
        ),
        encoding="utf-8",
    )


@pytest.fixture()
def fake_xray(monkeypatch):
    fake = FakeXrayHttpClient()
    monkeypatch.setattr("agent.drivers.xray.XrayHttpClient", lambda settings, transport=None: fake)
    return fake


@pytest.fixture()
def client(tmp_path, fake_xray):
    _clear_env()
    env = tmp_path / ".env"
    _write_env(env, tmp_path / "data")
    os.environ["ENV_FILE"] = str(env)
    with TestClient(create_app(str(env))) as test_client:
        yield test_client
    _clear_env()


def test_health_no_auth(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["success"] is True


def test_per_core_health_is_isolated(client: TestClient):
    xray = client.get("/cores/xray/health")
    assert xray.status_code == 200, xray.text
    body = xray.json()
    assert body["core"] == "xray"
    assert body["slug"] == "xray"
    assert "cores" not in body

    wg = client.get("/cores/wireguard/health")
    assert wg.status_code == 200, wg.text
    assert wg.json()["core"] == "wireguard"
    assert wg.json()["slug"] == "wireguard"

    awg = client.get("/cores/amnezia/health")
    assert awg.status_code == 200, awg.text
    assert awg.json()["core"] == "amnezia"
    assert awg.json()["slug"] == "amnezia"

    auth = client.get("/api/v1/cores/xray/health")
    assert auth.status_code == 401

    headers = {"Authorization": "Bearer dev-token"}
    scoped = client.get("/api/v1/cores/xray/health", headers=headers)
    assert scoped.status_code == 200
    assert scoped.json()["core"] == "xray"
    assert "cores" not in scoped.json()


def test_api_requires_auth(client: TestClient):
    r = client.get("/api/v1/cores")
    assert r.status_code == 401


def test_xray_flow(client: TestClient, fake_xray):
    headers = {"Authorization": "Bearer dev-token"}
    r = client.post(
        "/api/v1/cores/xray/inbounds",
        headers=headers,
        json=_sample_inbound(99, 10443),
    )
    assert r.status_code == 200, r.text
    inbound = r.json()["inbound"]
    assert inbound["tag"] == "inbound-99"

    r = client.post(
        "/api/v1/cores/xray/inbounds/99/clients",
        headers=headers,
        json={"email": "abc12345", "id": "22222222-2222-2222-2222-222222222222"},
    )
    assert r.status_code == 200, r.text

    fake_xray._user_traffic["abc12345"] = {"uplink": 20, "downlink": 10}
    fake_xray._online = ["abc12345"]
    r = client.get("/api/v1/stats/online/traffic?core=xray", headers=headers)
    traffic = r.json()
    assert traffic["success"] is True
    assert traffic["users"]["abc12345"]["uplink"] == 20
    assert traffic["users"]["abc12345"]["downlink"] == 10

    r = client.get("/api/v1/stats/snapshot?core=xray", headers=headers)
    body = r.json()
    assert body["inbounds"]
    assert body["inbounds"][0]["clients"]
    assert body["inbounds"][0]["clients"][0]["incoming"] == 10
    assert "up" not in body["inbounds"][0]["clients"][0]
    assert "down" not in body["inbounds"][0]["clients"][0]


def test_xray_client_rejects_xui_field_names(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    r = client.post(
        "/api/v1/cores/xray/inbounds",
        headers=headers,
        json=_sample_inbound(12, 11443),
    )
    assert r.status_code == 200, r.text

    r = client.post(
        "/api/v1/cores/xray/inbounds/12/clients",
        headers=headers,
        json={
            "email": "netinja1",
            "id": "33333333-3333-3333-3333-333333333333",
            "enable": True,
            "totalGB": 2048,
            "limitIp": 2,
            "expiryTime": 1893456000000,
            "down": 5,
            "up": 7,
            "subId": "legacy",
            "tgId": 1,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()["client"]
    assert body["is_enabled"] is True
    assert body["volume"] == 2048
    assert body["max_connection"] == 2
    assert body["incoming"] == 5
    assert body["outgoing"] == 7
    assert body["expires_at"].startswith("2030-01-01")
    for key in ("enable", "totalGB", "limitIp", "expiryTime", "up", "down", "subId", "tgId"):
        assert key not in body


def test_xray_roundtrip_via_http_api(tmp_path, fake_xray):
    _clear_env()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    _write_env(env, data, cores="xray")
    headers = {"Authorization": "Bearer dev-token"}
    with TestClient(create_app(str(env))) as client:
        r = client.post(
            "/api/v1/cores/xray/inbounds",
            headers=headers,
            json=_sample_inbound(7, 443),
        )
        assert r.status_code == 200

    with TestClient(create_app(str(env))) as client2:
        r = client2.get("/api/v1/cores/xray/inbounds", headers=headers)
        assert r.status_code == 200
        ids = [str(i["id"]) for i in r.json()["inbounds"]]
        assert "7" in ids
    _clear_env()


def test_disabled_core_routes_are_hidden(tmp_path, fake_xray):
    _clear_env()
    env = tmp_path / ".env"
    _write_env(env, tmp_path / "data", cores="xray")
    headers = {"Authorization": "Bearer dev-token"}
    with TestClient(create_app(str(env))) as client:
        assert client.get("/api/v1/cores/xray/inbounds", headers=headers).status_code == 200
        assert client.get("/api/v1/cores/wireguard/interfaces", headers=headers).status_code == 404
        assert client.get("/cores/wireguard/health").status_code == 404
        assert client.get("/cores/xray/health").status_code == 200
        stats = client.get("/api/v1/stats/snapshot?core=amnezia", headers=headers)
        assert stats.status_code == 404
        assert "not enabled" in stats.text
    _clear_env()
