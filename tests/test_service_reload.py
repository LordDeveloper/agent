"""Service reload rebuilds missing runtime from stored data."""

import asyncio
from types import SimpleNamespace

from agent.cli import build_parser
from agent.db import Store
from agent.errors import AgentError
from agent.service_reload import _reload_tunnel_core, _reload_xray, reload_stored_services
from agent.support.mullvad import MullvadService


def test_cli_accepts_service_reload():
    args = build_parser().parse_args(["service", "reload"])
    assert args.action == "reload"
    assert args.func.__name__ == "cmd_service"


def test_missing_xray_config_is_not_invented(tmp_path):
    path = tmp_path / "config.json"

    class Driver:
        def __init__(self):
            self.settings = SimpleNamespace(
                xray=SimpleNamespace(
                    config=str(path),
                    binary="/usr/local/bin/xray",
                    api_base="http://127.0.0.1:8080",
                    username="",
                    password="",
                )
            )

        def _binary(self):
            return None

        async def _api_call(self, name, *args, **kwargs):
            raise AgentError("EXEC_ERROR", "xray down", 500)

    result = asyncio.run(_reload_xray(Driver()))
    assert result["ok"] is False
    assert "missing" in result["error"]
    assert not path.exists()


def test_down_tunnel_is_brought_up_and_live_tunnel_is_synced():
    class Driver:
        def __init__(self):
            self.up: list[str] = []
            self.synced: list[str] = []

        def list_interfaces(self):
            return [{"name": "wg0"}, {"name": "wg1"}]

        async def _interface_is_up(self, name):
            return name == "wg1"

        async def _bring_up(self, iface):
            self.up.append(iface["name"])
            return {"name": iface["name"], "ok": True}

        async def _apply_live(self, iface):
            self.synced.append(iface["name"])

    driver = Driver()
    result = asyncio.run(_reload_tunnel_core(driver))
    assert result["ok"] is True
    assert result["brought_up"] == ["wg0"]
    assert result["synced"] == ["wg1"]
    assert driver.up == ["wg0"]


def test_reload_awaits_async_list_interfaces():
    class Driver:
        def __init__(self):
            self.up: list[str] = []

        async def list_interfaces(self):
            return [{"name": "awg0"}]

        async def _interface_is_up(self, name):
            return False

        async def _bring_up(self, iface):
            self.up.append(iface["name"])
            return {"name": iface["name"], "ok": True}

        async def _apply_live(self, iface):
            raise AssertionError("down interface should be brought up")

    driver = Driver()
    result = asyncio.run(_reload_tunnel_core(driver))
    assert result["ok"] is True
    assert result["brought_up"] == ["awg0"]
    assert driver.up == ["awg0"]


def test_reload_reports_disabled_cores_and_a_failed_one(monkeypatch):
    async def core(key, driver):
        if key == "wireguard":
            return {"ok": False, "error": "wg-quick missing"}
        return {"ok": True, "skipped": True}

    async def skipped(*_args, **_kwargs):
        return {"ok": True, "skipped": True, "reason": "nothing stored"}

    monkeypatch.setattr("agent.service_reload._reload_core", core)
    monkeypatch.setattr("agent.service_reload._reload_mullvad", skipped)
    monkeypatch.setattr("agent.service_reload._reload_peer_egress", skipped)

    class Registry:
        def enabled_drivers(self):
            return [("wireguard", object())]

        def get(self, key, require_enabled=False):
            return object()

    report = asyncio.run(reload_stored_services(SimpleNamespace(), object(), Registry()))
    assert report["ok"] is False
    assert report["cores"]["xray"]["skipped"] is True
    assert report["cores"]["wireguard"]["error"] == "wg-quick missing"
    assert report["cores"]["mullvad"]["skipped"] is True


def _runner(args, timeout=30, check=False, input_text=None):
    if len(args) >= 2 and args[0] == "wg-quick" and args[1] == "strip":
        return SimpleNamespace(returncode=0, stdout="[Interface]\nPrivateKey = abc\n", stderr="")
    return SimpleNamespace(returncode=0, stdout="active\n", stderr="")


def test_mullvad_reload_rewrites_a_deleted_conf(tmp_path):
    async def run():
        store = Store(tmp_path / "agent.db")
        await store.open()
        try:
            await store.put_doc(
                "mullvad",
                "settings",
                "account",
                {"private_key": "privkeyprivkeyprivkeyprivkeyprivkey12=", "address": "10.64.0.8/32"},
            )
            await store.put_doc(
                "mullvad",
                "location",
                "de",
                {
                    "country_code": "de",
                    "iface": "de",
                    "pubkey": "relayrelayrelayrelayrelayrelayrelayrelayrelay=",
                    "endpoint": "185.213.154.0:51820",
                },
            )
            service = MullvadService(
                store,
                config_dir=tmp_path / "wg",
                runner=_runner,
                persist_script=tmp_path / "bin" / "hold.sh",
                persist_unit_path=tmp_path / "unit" / "mullvad.conf",
            )
            return await service.reload_bindings()
        finally:
            await store.close()

    result = asyncio.run(run())

    text = (tmp_path / "wg" / "de.conf").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert result["rebuilt"] == ["de"]
    assert "PrivateKey = privkeyprivkeyprivkeyprivkeyprivkey12=" in text
    assert "Address = 10.64.0.8/32" in text
    assert "PublicKey = relayrelayrelayrelayrelayrelayrelayrelayrelay=" in text
    assert "Endpoint = 185.213.154.0:51820" in text


def test_mullvad_reload_keeps_a_live_conf(tmp_path):
    conf = tmp_path / "wg" / "de.conf"
    conf.parent.mkdir()
    original = (
        "[Interface]\n"
        "PrivateKey = keepmekeepmekeepmekeepmekeepmekeepme=\n"
        "Address = 10.64.0.8/32\n"
        "\n"
        "[Peer]\n"
        "PublicKey = relayrelayrelayrelayrelayrelayrelayrelayrelay=\n"
        "Endpoint = 185.213.154.0:51820\n"
    )
    conf.write_text(original, encoding="utf-8")

    async def run():
        store = Store(tmp_path / "agent.db")
        await store.open()
        try:
            await store.put_doc(
                "mullvad",
                "settings",
                "account",
                {"private_key": "privkeyprivkeyprivkeyprivkeyprivkey12=", "address": "10.64.0.8/32"},
            )
            await store.put_doc(
                "mullvad",
                "location",
                "de",
                {
                    "country_code": "de",
                    "iface": "de",
                    "pubkey": "relayrelayrelayrelayrelayrelayrelayrelayrelay=",
                    "endpoint": "185.213.154.0:51820",
                },
            )
            service = MullvadService(
                store,
                config_dir=tmp_path / "wg",
                runner=_runner,
                persist_script=tmp_path / "bin" / "hold.sh",
                persist_unit_path=tmp_path / "unit" / "mullvad.conf",
            )
            service._iface_up = lambda iface: True
            return await service.reload_bindings()
        finally:
            await store.close()

    result = asyncio.run(run())

    assert result["ok"] is True
    assert result["rebuilt"] == []
    assert conf.read_text(encoding="utf-8") == original
