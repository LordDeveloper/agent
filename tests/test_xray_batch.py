import os
from pathlib import Path

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


def test_refresh_preserves_clients_without_wipe(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(21, 2443)).status_code == 200

    seed = [
        {"id": f"00000000-0000-0000-0000-{i:012d}", "email": f"user{i}@x"}
        for i in range(1, 6)
    ]
    batch = client.post(
        "/api/v1/cores/xray/inbounds/21/clients/batch",
        headers=headers,
        json={"mode": "upsert", "clients": seed},
    )
    assert batch.status_code == 200, batch.text
    assert batch.json()["succeeded"] == 5

    refresh = client.post(
        "/api/v1/cores/xray/inbounds/21/refresh",
        headers=headers,
        json={
            "protocol": "vless",
            "port": 2444,
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/v"}},
            "settings": {"decryption": "none", "clients": []},
        },
    )
    assert refresh.status_code == 200, refresh.text
    inbound = refresh.json()["inbound"]
    assert inbound["port"] == 2444
    assert inbound["streamSettings"]["network"] == "ws"
    assert len(inbound["settings"]["clients"]) == 5


def test_inbound_write_strips_panel_domain_settings(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    payload = _sample_inbound(31, 3143)
    payload["remark"] = "panel-only"
    payload["streamSettings"]["domainSettings"] = {"addresses": {"original": "share.example.com"}}

    created = client.post("/api/v1/cores/xray/inbounds", headers=headers, json=payload)
    assert created.status_code == 200, created.text

    stored = next(row for row in fake_xray._inbounds if row.get("tag") == "inbound-31")
    assert "remark" not in stored
    assert "domainSettings" not in (stored.get("streamSettings") or {})
    assert stored["streamSettings"]["network"] == "tcp"


def test_patch_settings_returns_clients_count(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(22, 2543)).status_code == 200
    client.post(
        "/api/v1/cores/xray/inbounds/22/clients/batch",
        headers=headers,
        json={
            "clients": [
                {"id": "11111111-1111-1111-1111-111111111111", "email": "a@x"},
                {"id": "22222222-2222-2222-2222-222222222222", "email": "b@x"},
            ]
        },
    )

    patched = client.patch(
        "/api/v1/cores/xray/inbounds/22",
        headers=headers,
        json={"port": 2544, "settings": {"decryption": "none"}},
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["ok"] is True
    assert body["inbound"]["clients_count"] == 2
    assert body["inbound"]["port"] == 2544


def test_client_batch_limit_and_partial_upsert(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(23, 2643)).status_code == 200

    too_many = [{"id": f"00000000-0000-0000-0000-{i:012d}", "email": f"u{i}@x"} for i in range(201)]
    limited = client.post(
        "/api/v1/cores/xray/inbounds/23/clients/batch",
        headers=headers,
        json={"clients": too_many},
    )
    assert limited.status_code == 413

    ok = client.post(
        "/api/v1/cores/xray/inbounds/23/clients:batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [
                {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "email": "keep@x"},
                {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "email": "next@x"},
            ],
        },
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["succeeded"] == 2

    removed = client.request(
        "DELETE",
        "/api/v1/cores/xray/inbounds/23/clients/batch",
        headers=headers,
        json={"emails": ["next@x"]},
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["succeeded"] == 1

    listed = client.get("/api/v1/cores/xray/inbounds/23", headers=headers)
    emails = [c["email"] for c in listed.json()["inbound"]["settings"]["clients"]]
    assert emails == ["keep@x"]


def test_client_batch_accepts_edit_mode_alias(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(24, 2743)).status_code == 200
    seed = client.post(
        "/api/v1/cores/xray/inbounds/24/clients/batch",
        headers=headers,
        json={"mode": "upsert", "clients": [{"id": "cccccccc-cccc-cccc-cccc-cccccccccccc", "email": "edit@x"}]},
    )
    assert seed.status_code == 200, seed.text

    edited = client.post(
        "/api/v1/cores/xray/inbounds/24/clients/batch",
        headers=headers,
        json={
            "mode": "edit",
            "clients": [{"id": "dddddddd-dddd-dddd-dddd-dddddddddddd", "email": "edit@x"}],
        },
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["succeeded"] == 1
    listed = client.get("/api/v1/cores/xray/inbounds/24", headers=headers)
    clients = listed.json()["inbound"]["settings"]["clients"]
    assert len(clients) == 1
    assert clients[0]["id"] == "dddddddd-dddd-dddd-dddd-dddddddddddd"


def test_update_missing_client_upserts_instead_of_404(client: TestClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(25, 2843)).status_code == 200

    updated = client.put(
        "/api/v1/cores/xray/inbounds/inbound-25/clients/KJODDyxE",
        headers=headers,
        json={
            "id": "6a8a151e-cad6-4953-a638-c69d9345fba4",
            "email": "KJODDyxE",
            "is_enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text

    listed = client.get("/api/v1/cores/xray/inbounds/25", headers=headers)
    clients = listed.json()["inbound"]["settings"]["clients"]
    assert clients == []


def test_disabling_existing_client_keeps_it_visible_until_reenabled(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(26, 2943)).status_code == 200
    client_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    seeded = client.post(
        "/api/v1/cores/xray/inbounds/26/clients/batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [{"id": client_id, "email": "stay@x", "is_enabled": True, "volume": 1000}],
        },
    )
    assert seeded.status_code == 200, seeded.text

    disabled = client.post(
        "/api/v1/cores/xray/inbounds/26/clients/batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [{
                "id": client_id,
                "email": "stay@x",
                "is_enabled": False,
                "disabled_reason": "quota_exceeded",
                "volume": 1,
            }],
        },
    )
    assert disabled.status_code == 200, disabled.text
    live = fake_xray._inbounds[0]["settings"]["clients"]
    assert live == []

    listed = client.get("/api/v1/cores/xray/inbounds/26", headers=headers)
    clients = listed.json()["inbound"]["settings"]["clients"]
    assert len(clients) == 1, clients
    assert clients[0]["id"] == client_id
    assert clients[0]["is_enabled"] is False, clients[0]
    assert clients[0]["disabled_reason"] == "quota_exceeded"

    record = client.get(f"/api/v1/cores/xray/inbounds/26/clients/{client_id}", headers=headers)
    assert record.status_code == 200, record.text
    assert record.json()["client"]["email"] == "stay@x"
    assert record.json()["client"]["is_enabled"] is False

    enabled = client.put(
        f"/api/v1/cores/xray/inbounds/26/clients/{client_id}",
        headers=headers,
        json={"id": client_id, "email": "stay@x", "is_enabled": True, "volume": 5_000_000_000},
    )
    assert enabled.status_code == 200, enabled.text
    live = fake_xray._inbounds[0]["settings"]["clients"]
    assert [row["email"] for row in live] == ["stay@x"]
    listed = client.get("/api/v1/cores/xray/inbounds/26", headers=headers)
    clients = listed.json()["inbound"]["settings"]["clients"]
    assert len(clients) == 1
    assert clients[0]["is_enabled"] is True


def test_batch_upsert_creates_missing_client_without_relying_on_xray_upsert(client: TestClient, fake_xray: FakeXrayHttpClient):
    """Xray users/upsert may report success without inserting. Bulk apply must still add."""
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(27, 3043)).status_code == 200

    def upsert_reports_success_but_writes_nothing(tag, clients, **kwargs):
        return {"succeeded": len(clients), "failed": 0}

    fake_xray.upsert_users = upsert_reports_success_but_writes_nothing

    created = client.post(
        "/api/v1/cores/xray/inbounds/27/clients/batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [{
                "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "email": "missing@x",
                "is_enabled": True,
            }],
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["failed"] == 0
    listed = client.get("/api/v1/cores/xray/inbounds/27", headers=headers)
    emails = [row["email"] for row in listed.json()["inbound"]["settings"]["clients"]]
    assert "missing@x" in emails


def test_batch_upsert_applies_each_client_even_if_a_bulk_add_would_lie(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(28, 3044)).status_code == 200

    sizes: list[int] = []
    real_add = fake_xray.add_users

    def add_users(tag, clients, **kwargs):
        sizes.append(len(clients))
        if len(clients) != 1:
            return {"succeeded": len(clients), "failed": 0}
        return real_add(tag, clients, **kwargs)

    fake_xray.add_users = add_users

    created = client.post(
        "/api/v1/cores/xray/inbounds/28/clients/batch",
        headers=headers,
        json={
            "mode": "upsert",
            "clients": [
                {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "email": "one@x", "is_enabled": True},
                {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "email": "two@x", "is_enabled": True},
            ],
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["failed"] == 0
    assert sizes and all(size == 1 for size in sizes)
    listed = client.get("/api/v1/cores/xray/inbounds/28", headers=headers)
    emails = [row["email"] for row in listed.json()["inbound"]["settings"]["clients"]]
    assert "one@x" in emails
    assert "two@x" in emails


def test_get_client_finds_user_that_inbounds_list_omits(client: TestClient, fake_xray: FakeXrayHttpClient):
    """users/add can leave the uuid out of inbounds/list. GET must still see it."""
    headers = {"Authorization": "Bearer dev-token"}
    fake_xray.users_hidden_from_inbound_list = True
    assert client.post("/api/v1/cores/xray/inbounds", headers=headers, json=_sample_inbound(29, 3045)).status_code == 200

    node_id = "876f18a0-644b-401b-a61a-a1064db044bf"
    created = client.post(
        "/api/v1/cores/xray/inbounds/29/clients/batch",
        headers=headers,
        json={"mode": "upsert", "clients": [{"id": node_id, "email": "TEY8ECJn", "is_enabled": True}]},
    )
    assert created.status_code == 200, created.text
    assert created.json()["failed"] == 0

    listed = client.get("/api/v1/cores/xray/inbounds/29", headers=headers)
    assert listed.json()["inbound"]["settings"]["clients"] == []

    found = client.get(f"/api/v1/cores/xray/inbounds/29/clients/{node_id}", headers=headers)
    assert found.status_code == 200, found.text
    assert found.json()["client"]["id"] == node_id


def test_replace_routing_rules(client: TestClient, fake_xray: FakeXrayHttpClient):
    headers = {"Authorization": "Bearer dev-token"}
    fake_xray._rules = [{"tag": "old", "outboundTag": "direct"}]

    replaced = client.put(
        "/api/v1/cores/xray/routing/rules",
        headers=headers,
        json={
            "domainStrategy": "AsIs",
            "rules": [
                {"tag": "node:1", "inboundTag": ["inbound-1"], "outboundTag": "proxy"},
                {"tag": "node:2", "inboundTag": ["inbound-1"], "outboundTag": "direct"},
            ],
        },
    )
    assert replaced.status_code == 200, replaced.text
    body = replaced.json()
    assert body["ok"] is True
    assert body["rules_count"] == 2
    assert [r["tag"] for r in fake_xray._rules] == ["node:1", "node:2"]

    upserted = client.post(
        "/api/v1/cores/xray/routing/rules/upsert",
        headers=headers,
        json={
            "remove_tags": ["node:1"],
            "add": [{"tag": "node:3", "outboundTag": "blocked"}],
        },
    )
    assert upserted.status_code == 200, upserted.text
    tags = [r["tag"] for r in fake_xray._rules]
    assert "node:1" not in tags
    assert "node:3" in tags
