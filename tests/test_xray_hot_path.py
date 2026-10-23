import os

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from tests.fake_xray import FakeXrayHttpClient


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(("LISTEN", "AUTH_", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "XRAY_", "ENV_FILE")) or key in {
            "LISTEN",
            "DATA_DIR",
            "DB_PATH",
            "ENABLED_CORES",
            "ENV_FILE",
        }:
            os.environ.pop(key, None)


def _sample_inbound(inbound_id: int = 1, port: int = 443) -> dict:
    return {
        "id": inbound_id,
        "port": port,
        "listen": "0.0.0.0",
        "protocol": "vless",
        "streamSettings": {"network": "tcp", "security": "none"},
        "settings": {"decryption": "none", "clients": []},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


@pytest.fixture()
def fake_xray(monkeypatch):
    fake = FakeXrayHttpClient()
    monkeypatch.setattr("agent.drivers.xray.XrayHttpClient", lambda settings, transport=None: fake)
    return fake


@pytest.fixture()
def client(tmp_path, fake_xray):
    _clear_env()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data.as_posix()}",
                "ENABLED_CORES=xray",
                "XRAY_API_BASE=http://127.0.0.1:8080",
                "XRAY_BINARY=/usr/local/bin/xray",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with TestClient(create_app(str(env))) as test_client:
        yield test_client
    _clear_env()


def test_get_inbound_can_skip_live_user_dump(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(1644, 443)).status_code == 200
    fake_xray.add_users(
        "inbound-1644",
        [{"id": "00000000-0000-0000-0000-000000000001", "email": "seed@x"}],
        protocol="vless",
    )

    calls: list[tuple[str, str | None]] = []
    real = fake_xray.list_users

    def tracked(tag: str, email: str | None = None):
        calls.append((tag, email))
        return real(tag, email)

    fake_xray.list_users = tracked  # type: ignore[method-assign]

    light = client.get("/api/v1/cores/xray/inbounds/1644?include_clients=false", headers=headers)
    assert light.status_code == 200
    inbound = light.json()["inbound"]
    assert inbound.get("clients") in (None, []) or inbound.get("settings", {}).get("clients") == []
    assert calls == []


def test_single_client_upsert_looks_up_one_email(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(50, 4450)).status_code == 200

    calls: list[tuple[str, str | None]] = []
    real = fake_xray.list_users

    def tracked(tag: str, email: str | None = None):
        calls.append((tag, email))
        return real(tag, email)

    fake_xray.list_users = tracked  # type: ignore[method-assign]

    created = client.post(
        "/api/v1/cores/xray/inbounds/50/clients/batch",
        headers=headers,
        json={"mode": "upsert", "clients": [{"id": "node-1", "email": "trial@x"}]},
    )
    assert created.status_code == 200
    assert created.json()["succeeded"] == 1
    assert any(email == "trial@x" for _tag, email in calls)
    assert not any(email is None for _tag, email in calls)


def test_usage_snapshot_does_not_list_live_inbounds(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(60, 4460)).status_code == 200

    calls = {"list": 0}
    real = fake_xray.list_inbounds

    def tracked():
        calls["list"] += 1
        return real()

    fake_xray.list_inbounds = tracked  # type: ignore[method-assign]
    before = calls["list"]
    listed = client.get("/api/v1/stats/clients/traffic/pending", headers=headers)
    assert listed.status_code == 200
    assert calls["list"] == before


def test_pending_get_skips_resample_when_fresh(client: TestClient, monkeypatch):
    headers = {"Authorization": "Bearer dev-token"}
    traffic = client.app.state.traffic
    samples = {"n": 0}
    real = traffic.sample_all

    def counted(registry):
        samples["n"] += 1
        return real(registry)

    monkeypatch.setattr(traffic, "sample_all", counted)
    first = client.get("/api/v1/stats/clients/traffic/pending", headers=headers)
    second = client.get("/api/v1/stats/clients/traffic/pending", headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert samples["n"] == 0
