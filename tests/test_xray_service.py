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


def test_client_api_base_rewrites_wildcard_bind():
    from agent.xray_service import client_api_base

    assert client_api_base("0.0.0.0:8080") == "http://127.0.0.1:8080"
    assert client_api_base("http://0.0.0.0:9090/") == "http://127.0.0.1:9090"
    assert client_api_base("127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_binary_has_httpapi_detects_custom_marker(tmp_path):
    from agent.xray_service import binary_has_httpapi

    stock = tmp_path / "stock-xray"
    stock.write_bytes(b"Xray, Penetrates Everything.")
    custom = tmp_path / "custom-xray"
    custom.write_bytes(b"Xray httpapi /api/stats/sys")

    assert binary_has_httpapi(stock) is False
    assert binary_has_httpapi(custom) is True
    assert binary_has_httpapi(tmp_path / "missing") is False


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
    binary.write_bytes(b"xray httpapi /api/stats/sys")
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


def test_ensure_start_rejects_stock_binary(tmp_path, monkeypatch):
    binary = tmp_path / "xray"
    binary.write_bytes(b"Xray, Penetrates Everything.")
    monkeypatch.setattr("agent.xray_service.which", lambda cmd: "/usr/bin/systemctl" if cmd == "systemctl" else None)
    try:
        ensure_xray_runtime(
            binary=str(binary),
            config_path=str(tmp_path / "config.json"),
            unit_path=str(tmp_path / "xray.service"),
            start=True,
        )
        assert False, "expected AgentError"
    except AgentError as exc:
        assert "HTTP API" in exc.message


def test_install_xray_skips_customized_binary(tmp_path, monkeypatch):
    from agent.ops import install_xray

    binary = tmp_path / "xray"
    binary.write_bytes(b"customized xray httpapi /api/inbounds/list")
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setenv("XRAY_API_BASE", "http://127.0.0.1:8080")

    called = {"download": False}

    def fake_download(dest, token=None):
        called["download"] = True
        return {"core": "xray", "installed": True, "downloaded": True, "binary": str(dest)}

    monkeypatch.setattr("agent.xray_release.install_xray_binary", fake_download)
    monkeypatch.setattr("agent.ops._prepare_xray_service", lambda result: result)
    result = install_xray()
    assert called["download"] is False
    assert result["downloaded"] is False
    assert result["httpapi_capable"] is True


def test_install_xray_replaces_stock_binary(tmp_path, monkeypatch):
    from agent.ops import install_xray

    binary = tmp_path / "xray"
    binary.write_bytes(b"Xray, Penetrates Everything.")
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setattr("agent.ops.which", lambda cmd: None)
    monkeypatch.setattr("agent.xray_service.which", lambda cmd: None)
    monkeypatch.setattr("agent.xray_service.systemctl", lambda *args, **kwargs: {"ok": True})

    def fake_download(dest, token=None):
        dest.write_bytes(b"customized xray httpapi /api/stats/sys")
        return {"core": "xray", "installed": True, "downloaded": True, "binary": str(dest)}

    monkeypatch.setattr("agent.xray_release.install_xray_binary", fake_download)
    monkeypatch.setattr("agent.ops._prepare_xray_service", lambda result: result)
    result = install_xray()
    assert result["downloaded"] is True
    assert result["replaced_stock"] is True
    assert result["httpapi_capable"] is True


def test_wait_xray_http_api_rejects_bare_404(monkeypatch):
    from agent.xray_service import wait_xray_http_api

    class _Resp:
        status_code = 404
        text = "404 page not found"

    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: _Resp())

    try:
        wait_xray_http_api(api_base="http://127.0.0.1:9", attempts=1, delay=0)
        assert False, "expected AgentError"
    except AgentError as exc:
        assert exc.code == "CONFIG_NOT_FOUND"
        assert "404" in exc.message


def test_xray_http_maps_404_to_config_not_found():
    from agent.config import XraySettings
    from agent.drivers.xray_http import XrayHttpClient
    import httpx

    transport = httpx.MockTransport(lambda request: httpx.Response(404, text="404 page not found"))
    client = XrayHttpClient(XraySettings(api_base="http://test"), transport=transport)
    try:
        client.list_inbounds()
        assert False, "expected AgentError"
    except AgentError as exc:
        assert exc.code == "CONFIG_NOT_FOUND"
        assert "404" in exc.message
    finally:
        client.close()
