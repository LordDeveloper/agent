import json
from pathlib import Path

from agent.xray_service import (
    default_xray_config,
    ensure_xray_runtime,
    httpapi_listen,
    write_xray_config_if_missing,
    write_xray_unit,
    xray_unit_text,
)
from agent.errors import AgentError


def test_httpapi_listen_parses_api_base():
    assert httpapi_listen("http://127.0.0.1:8080") == "127.0.0.1:8080"
    assert httpapi_listen("http://0.0.0.0:9090/") == "0.0.0.0:9090"


def test_default_config_enables_httpapi():
    cfg = default_xray_config(api_base="http://127.0.0.1:8080", config_path="/tmp/xray.json")
    assert cfg["httpapi"]["listen"] == "127.0.0.1:8080"
    assert cfg["httpapi"]["config_path"] == "/tmp/xray.json"
    assert "username" not in cfg["httpapi"]
    assert any(row.get("tag") == "api" for row in cfg["inbounds"])


def test_write_config_only_if_missing(tmp_path):
    path = tmp_path / "config.json"
    assert write_xray_config_if_missing(path, api_base="http://127.0.0.1:8080") is True
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["httpapi"]["listen"] == "127.0.0.1:8080"

    path.write_text('{"keep": true}\n', encoding="utf-8")
    assert write_xray_config_if_missing(path, api_base="http://127.0.0.1:1") is False
    assert json.loads(path.read_text(encoding="utf-8")) == {"keep": True}


def test_unit_file_runs_binary_with_config():
    text = xray_unit_text("/usr/local/bin/xray", "/usr/local/etc/xray/config.json")
    assert "ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json" in text


def test_ensure_writes_unit_and_config(tmp_path, monkeypatch):
    binary = tmp_path / "xray"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    config = tmp_path / "etc" / "config.json"
    unit = tmp_path / "systemd" / "xray.service"

    result = ensure_xray_runtime(
        binary=str(binary),
        config_path=str(config),
        api_base="http://127.0.0.1:8080",
        unit_path=str(unit),
        start=False,
    )
    assert result["wrote_config"] is True
    assert config.is_file()
    assert unit.is_file()
    assert "run -config" in unit.read_text(encoding="utf-8")


def test_ensure_start_without_systemctl_raises(tmp_path, monkeypatch):
    binary = tmp_path / "xray"
    binary.write_text("x", encoding="utf-8")
    monkeypatch.setattr("agent.xray_service.which", lambda cmd: None)
    try:
        ensure_xray_runtime(
            binary=str(binary),
            config_path=str(tmp_path / "config.json"),
            unit_path=str(tmp_path / "xray.service"),
            start=True,
        )
        assert False, "expected AgentError"
    except AgentError as exc:
        assert "systemctl" in exc.message
