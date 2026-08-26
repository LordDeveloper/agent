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


def test_ensure_start_skips_restart_when_already_active(tmp_path, monkeypatch):
    """Keep-alive: httpapi drift must not bounce a live unit (sync must not drop connections)."""
    from agent.xray_service import ensure_xray_running

    binary = tmp_path / "xray"
    binary.write_bytes(b"xray httpapi /api/stats/sys /api/inbounds/list")
    config = tmp_path / "config.json"
    unit = tmp_path / "xray.service"
    actions: list[str] = []

    monkeypatch.setattr(
        "agent.xray_service.which",
        lambda cmd: "/usr/bin/systemctl" if cmd == "systemctl" else None,
    )
    monkeypatch.setattr("agent.xray_service.service_is_active", lambda unit_name: True)
    monkeypatch.setattr("agent.xray_service.wait_xray_http_api", lambda **kwargs: None)

    def fake_systemctl(action, unit_name):
        actions.append(action)
        return {"ok": True, "action": action, "unit": unit_name, "stdout": "", "stderr": ""}

    monkeypatch.setattr("agent.xray_service.systemctl", fake_systemctl)
    monkeypatch.setattr(
        "agent.xray_service.run_cmd",
        lambda *args, **kwargs: type("P", (), {"stdout": "", "stderr": "", "returncode": 0})(),
    )

    result = ensure_xray_running(
        binary=str(binary),
        config_path=str(config),
        api_base="http://127.0.0.1:8080",
        unit_path=str(unit),
    )
    assert result["already_running"] is True
    assert result["started"] is False
    assert "restart" not in actions
    assert "start" not in actions


def test_ensure_start_starts_only_when_inactive(tmp_path, monkeypatch):
    binary = tmp_path / "xray"
    binary.write_bytes(b"xray httpapi /api/stats/sys /api/inbounds/list")
    config = tmp_path / "config.json"
    unit = tmp_path / "xray.service"
    actions: list[str] = []
    active = {"value": False}

    monkeypatch.setattr(
        "agent.xray_service.which",
        lambda cmd: "/usr/bin/systemctl" if cmd == "systemctl" else None,
    )
    monkeypatch.setattr("agent.xray_service.service_is_active", lambda unit_name: active["value"])
    monkeypatch.setattr("agent.xray_service.wait_xray_http_api", lambda **kwargs: None)

    def fake_systemctl(action, unit_name):
        actions.append(action)
        if action == "start":
            active["value"] = True
        return {"ok": True, "action": action, "unit": unit_name, "stdout": "", "stderr": ""}

    monkeypatch.setattr("agent.xray_service.systemctl", fake_systemctl)
    monkeypatch.setattr(
        "agent.xray_service.run_cmd",
        lambda *args, **kwargs: type("P", (), {"stdout": "", "stderr": "", "returncode": 0})(),
    )

    result = ensure_xray_runtime(
        binary=str(binary),
        config_path=str(config),
        api_base="http://127.0.0.1:8080",
        unit_path=str(unit),
        start=True,
    )
    assert result["started"] is True
    assert result.get("already_running") is False
    assert "start" in actions
    assert "restart" not in actions


def test_install_xray_skips_customized_binary(tmp_path, monkeypatch):
    from agent.ops import install_xray

    binary = tmp_path / "xray"
    binary.write_bytes(b"customized xray httpapi /api/inbounds/list")
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setenv("XRAY_API_BASE", "http://127.0.0.1:8080")

    called = {"download": False}

    def fake_download(dest, token=None, tag=None):
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

    def fake_download(dest, token=None, tag=None):
        dest.write_bytes(b"customized xray httpapi /api/stats/sys")
        return {
            "core": "xray",
            "installed": True,
            "downloaded": True,
            "binary": str(dest),
            "source": "release",
            "release_tag": "v1.0.7",
            "asset": "Xray-linux-64.zip",
        }

    monkeypatch.setattr("agent.xray_release.install_xray_binary", fake_download)
    monkeypatch.setattr("agent.ops._prepare_xray_service", lambda result: result)
    result = install_xray()
    assert result["downloaded"] is True
    assert result["replaced_stock"] is True
    assert result["httpapi_capable"] is True


def test_resolve_xray_release_asset_and_tag():
    from agent.xray_release import ASSET_BY_ARCH, resolve_xray_tag
    from agent.update import pick_release_asset

    assert resolve_xray_tag(None) is None
    assert resolve_xray_tag("latest") is None
    assert resolve_xray_tag("v1.0.7") == "v1.0.7"
    assert ASSET_BY_ARCH["amd64"] == "Xray-linux-64.zip"
    assert ASSET_BY_ARCH["arm64"] == "Xray-linux-arm64-v8a.zip"
    assets = [
        {"id": 1, "name": "Xray-linux-32.zip"},
        {"id": 2, "name": "Xray-linux-64.zip"},
        {"id": 3, "name": "Xray-linux-arm64-v8a.zip"},
    ]
    assert pick_release_asset(assets, "Xray-linux-64.zip", prefix="Xray")["id"] == 2


def test_install_xray_binary_from_release_zip(tmp_path, monkeypatch):
    import zipfile

    from agent.update import ReleaseInfo
    from agent.xray_release import install_xray_binary

    dest = tmp_path / "bin" / "xray"
    monkeypatch.setattr(
        "agent.xray_release.detect_host_platform",
        lambda: type("H", (), {"arch": "amd64", "libc": "gnu"})(),
    )
    monkeypatch.setattr("agent.xray_release.detect_arch", lambda: "amd64")
    monkeypatch.setattr(
        "agent.xray_release.fetch_xray_release",
        lambda **kwargs: ReleaseInfo(
            tag="v1.0.7",
            version="1.0.7",
            asset_name="Xray-linux-64.zip",
            asset_id=1,
            asset_url="https://example.invalid/asset",
            html_url="https://github.com/LordDeveloper/xray/releases/tag/v1.0.7",
        ),
    )

    def fake_download(release, dest_path, token=None, timeout=300.0):
        with zipfile.ZipFile(dest_path, "w") as zf:
            zf.writestr("xray", b"customized xray httpapi /api/stats/sys")
            zf.writestr("geoip.dat", b"geo")
        return dest_path

    monkeypatch.setattr("agent.xray_release.download_release_asset", fake_download)
    monkeypatch.setattr("agent.xray_release.which", lambda cmd: None)
    monkeypatch.setattr(
        "agent.xray_release.run_cmd",
        lambda *args, **kwargs: type("P", (), {"stdout": "Xray 1.0.7\n", "stderr": "", "returncode": 0})(),
    )
    monkeypatch.setenv("XRAY_GEO_DIR", str(tmp_path / "geo"))

    result = install_xray_binary(dest, tag="v1.0.7")
    assert dest.is_file()
    assert result["source"] == "release"
    assert result["release_tag"] == "v1.0.7"
    assert result["asset"] == "Xray-linux-64.zip"
    assert (tmp_path / "geo" / "geoip.dat").is_file()


def test_install_xray_custom_tag_forces_download(tmp_path, monkeypatch):
    from agent.ops import install_xray

    binary = tmp_path / "xray"
    binary.write_bytes(b"customized xray httpapi /api/inbounds/list")
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setattr("agent.ops.which", lambda cmd: None)
    monkeypatch.setattr("agent.xray_service.which", lambda cmd: None)
    monkeypatch.setattr("agent.xray_service.stop_xray_service", lambda: None)

    def fake_download(dest, token=None, tag=None):
        dest.write_bytes(b"customized xray httpapi /api/stats/sys")
        return {
            "core": "xray",
            "installed": True,
            "downloaded": True,
            "binary": str(dest),
            "release_tag": tag,
            "source": "release",
        }

    monkeypatch.setattr("agent.xray_release.install_xray_binary", fake_download)
    monkeypatch.setattr("agent.ops._prepare_xray_service", lambda result: result)
    result = install_xray(tag="v1.0.7")
    assert result["downloaded"] is True
    assert result["release_tag"] == "v1.0.7"


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


def test_xray_http_users_upsert_falls_back_to_inbound_edit():
    """When /users/* is missing but list/edit exist, upsert must still apply clients."""
    from agent.config import XraySettings
    from agent.drivers.xray_http import XrayHttpClient
    import httpx
    import json

    state = {
        "inbounds": [
            {
                "tag": "inbound-1642",
                "protocol": "vless",
                "listen": "0.0.0.0",
                "port": 2053,
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {"network": "ws", "domainSettings": {"addresses": {}}},
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/api/inbounds/list") and request.method == "GET":
            return httpx.Response(200, json={"inbounds": state["inbounds"]})
        if "/api/inbounds/users/" in path:
            return httpx.Response(404, text="404 page not found")
        if path.endswith("/api/inbounds/edit") and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            rows = body.get("inbounds") or []
            assert rows and rows[0]["tag"] == "inbound-1642"
            assert "domainSettings" not in (rows[0].get("streamSettings") or {})
            clients = (rows[0].get("settings") or {}).get("clients") or []
            assert len(clients) == 1
            assert clients[0]["email"] == "probe-test"
            state["inbounds"][0] = rows[0]
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(500, text=f"unexpected {request.method} {path}")

    client = XrayHttpClient(XraySettings(api_base="http://test"), transport=httpx.MockTransport(handler))
    try:
        result = client.upsert_users(
            "inbound-1642",
            [{"id": "00000000-0000-4000-8000-000000000001", "email": "probe-test"}],
            protocol="vless",
            inbound_settings={"decryption": "none"},
        )
        assert result.get("succeeded") == 1
        assert result.get("fallback") == "inbounds/edit"
        assert state["inbounds"][0]["settings"]["clients"][0]["email"] == "probe-test"
    finally:
        client.close()
