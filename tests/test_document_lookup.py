import os

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from tests.fake_xray import FakeXrayHttpClient


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(("LISTEN", "AUTH_", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "XRAY_", "ENV_FILE")):
            os.environ.pop(key, None)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    fake = FakeXrayHttpClient()
    monkeypatch.setattr("agent.drivers.xray.XrayHttpClient", lambda settings, transport=None: fake)
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
                f"XRAY_CONFIG={(tmp_path / 'xray-config.json').as_posix()}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with TestClient(create_app(str(env))) as test_client:
        yield test_client
    _clear_env()


def test_lookup_matches_document_primary_key_not_protocol_uuid(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    created = client.post(
        "/api/v1/cores/xray/inbounds",
        headers=headers,
        json={
            "id": 21,
            "port": 2443,
            "listen": "0.0.0.0",
            "protocol": "vless",
            "streamSettings": {"network": "tcp", "security": "none"},
            "settings": {"decryption": "none", "clients": []},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
    )
    assert created.status_code == 200, created.text

    node_id = "5eadad7e-73e7-4326-96ff-dc3a50bbbb64"
    protocol_id = "3f114cba-9b5f-48f3-8570-152de1d85464"
    seeded = client.post(
        "/api/v1/cores/xray/inbounds/21/clients/batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [{
                "id": protocol_id,
                "node_id": node_id,
                "client_link_uuid": protocol_id,
                "email": "audit@x",
                "password": "do-not-return",
            }],
        },
    )
    assert seeded.status_code == 200, seeded.text

    denied = client.post("/api/v1/documents/lookup", json={"ids": [node_id]})
    assert denied.status_code == 401

    found = client.post(
        "/api/v1/documents/lookup",
        headers=headers,
        json={"ids": [node_id, protocol_id, "missing-pk"]},
    )
    assert found.status_code == 200, found.text
    body = found.json()
    assert body["success"] is True
    keys = {row["doc_id"] for row in body["documents"]}
    assert keys == {node_id}
    row = body["documents"][0]
    assert row["kind"] == "client_quota"
    assert row["email"] == "audit@x"
    assert row["client_link_uuid"] == protocol_id
    assert "password" not in row
    assert "do-not-return" not in found.text

    rejected = client.post("/api/v1/documents/lookup", headers=headers, json={"ids": "pk"})
    assert rejected.status_code == 422
