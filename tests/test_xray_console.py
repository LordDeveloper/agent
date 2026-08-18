import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.main import create_app
from tests.fake_xray import FakeXrayHttpClient
from tests.test_smoke import _clear_env, _write_env

HEADERS = {"Authorization": "Bearer dev-token"}


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
    config = tmp_path / "xray-config.json"
    error_log = tmp_path / "error.log"
    error_log.write_text("boom-1\nboom-2\n", encoding="utf-8")
    config.write_text(
        json.dumps(
            {
                "log": {"loglevel": "warning", "error": str(error_log), "access": "none"},
                "httpapi": {"username": "x", "password": "secret-pass"},
                "dns": {"servers": ["1.1.1.1"]},
                "inbounds": [],
                "outbounds": [{"protocol": "freedom", "tag": "direct"}],
                "routing": {"domainStrategy": "AsIs", "rules": []},
            }
        ),
        encoding="utf-8",
    )
    _write_env(env, data, cores="xray")
    env.write_text(env.read_text(encoding="utf-8") + f"XRAY_CONFIG={config.as_posix()}\n", encoding="utf-8")
    os.environ["ENV_FILE"] = str(env)
    os.environ["XRAY_CONFIG"] = str(config)
    with TestClient(create_app(str(env))) as test_client:
        yield test_client, config
    _clear_env()
    os.environ.pop("XRAY_CONFIG", None)


def test_xray_console_and_routing(client, fake_xray):
    http, config_path = client

    console = http.get("/api/v1/cores/xray/console", headers=HEADERS)
    assert console.status_code == 200, console.text
    body = console.json()
    assert body["success"] is True
    assert body["api_ok"] is True
    assert any(row.get("tag") == "direct" for row in body["outbounds"])
    assert body["dns"]["servers"] == ["1.1.1.1"]

    added = http.post(
        "/api/v1/cores/xray/outbounds",
        headers=HEADERS,
        json={"outbounds": [{"protocol": "blackhole", "tag": "blocked"}]},
    )
    assert added.status_code == 200, added.text
    tags = [row["tag"] for row in http.get("/api/v1/cores/xray/outbounds", headers=HEADERS).json()["outbounds"]]
    assert "blocked" in tags

    edited = http.put(
        "/api/v1/cores/xray/outbounds",
        headers=HEADERS,
        json={"outbounds": [{"protocol": "blackhole", "tag": "blocked", "settings": {"response": {"type": "http"}}}]},
    )
    assert edited.status_code == 200, edited.text

    http.post(
        "/api/v1/cores/xray/rules",
        headers=HEADERS,
        json={"rules": [{"type": "field", "tag": "ads", "domain": ["geosite:category-ads-all"], "outboundTag": "blocked"}]},
    )
    rules = http.get("/api/v1/cores/xray/rules", headers=HEADERS).json()["rules"]
    assert any(row.get("tag") == "ads" for row in rules)

    dumped = http.get("/api/v1/cores/xray/config", headers=HEADERS)
    assert dumped.status_code == 200, dumped.text
    assert dumped.json()["config"]["httpapi"]["password"] == "***"

    dns = http.put(
        "/api/v1/cores/xray/config",
        headers=HEADERS,
        json={"section": "dns", "value": {"servers": ["8.8.8.8"], "queryStrategy": "UseIPv4"}},
    )
    assert dns.status_code == 200, dns.text
    saved = json.loads(Path(config_path).read_text(encoding="utf-8"))
    assert saved["dns"]["servers"] == ["8.8.8.8"]
    assert saved["httpapi"]["password"] == "secret-pass"

    logs = http.get("/api/v1/cores/xray/logs?kind=error&lines=20", headers=HEADERS)
    assert logs.status_code == 200, logs.text
    assert "boom-2" in logs.json()["files"]["error"]["content"]

    restart = http.post("/api/v1/cores/xray/logger/restart", headers=HEADERS)
    assert restart.status_code == 200, restart.text
