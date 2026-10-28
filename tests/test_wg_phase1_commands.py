from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.wireguard import WireGuardDriver
from agent.errors import AgentError
from agent.support.peer_egress import (
    _peer_egress_unit_enabled,
    _wants_target_is_unit,
    ensure_peer_egress_unit,
)


class _Audit:
    async def record(self, *args, **kwargs) -> None:
        return None


def _driver(tmp_path: Path) -> tuple[Store, WireGuardDriver]:
    store = Store(tmp_path / "agent.db")
    settings = AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "agent.db"),
        wireguard_config_dir=str(tmp_path / "wg"),
    )
    return store, WireGuardDriver(settings, _Audit(), store)


def _iface() -> dict:
    return {
        "id": 1,
        "name": "wg0",
        "listen_port": 51820,
        "subnet": "10.80.0.0/24",
        "address": "10.80.0.1/24",
        "private_key": "server-private",
        "public_key": "server-public",
        "peers": [
            {
                "id": "p1",
                "email": "a@b",
                "address": "10.80.0.2",
                "allowed_ips": "10.80.0.2/32",
                "private_key": "peer-private",
                "public_key": "peer-public",
                "is_enabled": True,
            }
        ],
    }


def test_apply_live_reuses_strip_text(tmp_path, monkeypatch):
    store, driver = _driver(tmp_path)
    seen: dict[str, str] = {}
    commands: list[list[str]] = []

    async def fake_run(args, **kwargs):
        commands.append(list(args))
        if len(args) >= 4 and args[1] == "syncconf":
            seen["text"] = Path(args[3]).read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    async def up(_name: str) -> bool:
        return True

    async def no_egress(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr("agent.drivers.wireguard.run", fake_run)
    driver._cli_bin = lambda: "wg"
    driver._quick_bin = lambda: "wg-quick"
    driver._interface_is_up = up
    driver._sync_conf = lambda _iface: None
    driver._sync_peer_egress = no_egress

    async def run() -> None:
        await store.open()
        try:
            await driver._apply_live(_iface(), stripped="PrivateKey = abc\n")
        finally:
            await store.close()

    asyncio.run(run())

    assert seen["text"] == "PrivateKey = abc\n"
    assert commands == [["wg", "syncconf", "wg0", commands[0][3]]]
    assert all(arg != "strip" for command in commands for arg in command)


def test_batch_peers_validates_once_and_skips_extra_l2tp(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[tuple] = []

    async def validate(_iface):
        calls.append(("validate",))
        return "stripped-conf\n"

    async def apply_live(_iface, **kwargs):
        calls.append(("apply", kwargs.get("stripped"), kwargs.get("drop_keys")))

    async def sync_egress(*_args, **kwargs):
        calls.append(("egress", kwargs.get("drop_keys")))

    async def sync_l2tp(drop_keys=None):
        calls.append(("l2tp", list(drop_keys or [])))

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_peer_egress = sync_egress
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            result = await driver.batch_peers(1, [{"id": "p1", "email": "a@b", "is_enabled": False}])
        finally:
            await store.close()
        assert result["succeeded"] == 1

    asyncio.run(run())

    assert calls == [("validate",), ("apply", "stripped-conf\n", None)]


def test_delete_peer_passes_drop_keys_once(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[tuple] = []

    async def update_interface(_interface_id, _payload, *, drop_keys=None):
        calls.append(("update", list(drop_keys or [])))
        return _payload

    async def sync_l2tp(drop_keys=None):
        calls.append(("l2tp", list(drop_keys or [])))

    driver.update_interface = update_interface
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            assert await driver.delete_peer(1, "p1") is True
        finally:
            await store.close()

    asyncio.run(run())

    assert calls == [("update", ["p1", "a@b"])]


def test_batch_remove_passes_drop_keys_once(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[tuple] = []

    async def validate(_iface):
        return "stripped-conf\n"

    async def apply_live(_iface, **kwargs):
        calls.append(("apply", kwargs.get("drop_keys")))

    async def sync_l2tp(drop_keys=None):
        calls.append(("l2tp", list(drop_keys or [])))

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            result = await driver.batch_remove_peers(1, ids=["p1"])
        finally:
            await store.close()
        assert result["succeeded"] == 1

    asyncio.run(run())

    assert calls == [("apply", ["p1", "a@b"])]


def test_update_peer_volume_skips_egress(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def sync_egress(*_args, **_kwargs):
        calls.append("egress")

    async def sync_l2tp(*_args, **_kwargs):
        calls.append("l2tp")

    driver._sync_peer_egress = sync_egress
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            await driver.update_peer(1, "p1", {"volume": 1024})
        finally:
            await store.close()

    asyncio.run(run())

    assert calls == []


def test_update_peer_does_not_reconcile_l2tp_twice(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def update_interface(*_args, **_kwargs):
        calls.append("update")
        return _iface()

    async def sync_l2tp(*_args, **_kwargs):
        calls.append("l2tp")

    driver.update_interface = update_interface
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            await driver.update_peer(1, "p1", {"is_enabled": False})
        finally:
            await store.close()

    asyncio.run(run())

    assert calls == ["update"]


def test_peer_egress_unit_enables_once_then_skips(tmp_path, monkeypatch):
    import agent.support.peer_egress as egress

    unit = tmp_path / "agent-peer-egress.service"
    monkeypatch.setattr(egress, "_UNIT_PATH", unit)
    monkeypatch.setattr(egress.shutil, "which", lambda cmd: "/bin/systemctl" if cmd == "systemctl" else None)
    commands: list[list[str]] = []
    enabled = {"value": False}

    async def fake_execute(_runner, args, **_kwargs):
        commands.append(list(args))
        if args[:2] == ["systemctl", "enable"]:
            enabled["value"] = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(egress, "execute", fake_execute)
    monkeypatch.setattr(egress, "_peer_egress_unit_enabled", lambda _path: enabled["value"])

    async def run() -> None:
        first = await ensure_peer_egress_unit(tmp_path / "apply.sh", start=False)
        assert first["ok"] is True
        assert first["already_enabled"] is False
        assert commands == [
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "agent-peer-egress.service"],
        ]
        commands.clear()
        second = await ensure_peer_egress_unit(tmp_path / "apply.sh", start=False)
        assert second["already_enabled"] is True
        assert second["ok"] is True
        assert commands == []
        changed = await ensure_peer_egress_unit(tmp_path / "other.sh", start=True)
        assert changed["already_enabled"] is True
        assert commands == [
            ["systemctl", "daemon-reload"],
            ["systemctl", "start", "agent-peer-egress.service"],
        ]

    asyncio.run(run())


def test_peer_egress_unit_enabled_states(tmp_path, monkeypatch):
    unit = tmp_path / "agent-peer-egress.service"
    unit.write_text("unit\n", encoding="utf-8")
    link = tmp_path / "multi-user.target.wants" / unit.name
    link.parent.mkdir()

    assert _peer_egress_unit_enabled(unit) is False

    link.write_text("not a symlink\n", encoding="utf-8")
    assert _peer_egress_unit_enabled(unit) is False
    link.unlink()

    assert _wants_target_is_unit(link, "../agent-peer-egress.service", unit) is True
    assert _wants_target_is_unit(link, str(unit), unit) is True
    assert _wants_target_is_unit(link, "../other.service", unit) is False
    assert _wants_target_is_unit(link, "", unit) is False

    state = {"symlink": True, "raw": "../agent-peer-egress.service"}
    real_is_symlink = Path.is_symlink

    def is_symlink(self: Path) -> bool:
        if self == link:
            return state["symlink"]
        return real_is_symlink(self)

    def readlink(path):
        if Path(path) == link:
            if state["raw"] is None:
                raise OSError("broken")
            return state["raw"]
        raise OSError(path)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    monkeypatch.setattr("agent.support.peer_egress.os.readlink", readlink)

    state["raw"] = "../agent-peer-egress.service"
    assert _peer_egress_unit_enabled(unit) is True
    state["raw"] = str(unit)
    assert _peer_egress_unit_enabled(unit) is True
    state["raw"] = "../other.service"
    assert _peer_egress_unit_enabled(unit) is False
    state["symlink"] = False
    state["raw"] = "../agent-peer-egress.service"
    assert _peer_egress_unit_enabled(unit) is False
    state["symlink"] = True
    state["raw"] = None
    assert _peer_egress_unit_enabled(unit) is False


def test_apply_live_strips_once_and_rolls_back_syncconf(tmp_path, monkeypatch):
    store, driver = _driver(tmp_path)
    conf = tmp_path / "wg" / "wg0.conf"
    conf.parent.mkdir()
    conf.write_text("OLD\n", encoding="utf-8")
    strips: list[str] = []
    commands: list[list[str]] = []

    async def fake_strip(conf_text, **_kwargs):
        strips.append(conf_text)
        return "PrivateKey = stripped\n"

    async def fake_run(args, **_kwargs):
        commands.append(list(args))
        if len(args) >= 2 and args[1] == "syncconf":
            return SimpleNamespace(returncode=1, stdout="", stderr="sync failed")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("agent.drivers.wireguard.validate_wg_conf_stripped", fake_strip)
    monkeypatch.setattr("agent.drivers.wireguard.validate_wg_iface", lambda _iface: None)
    monkeypatch.setattr("agent.drivers.wireguard.run", fake_run)
    driver._cli_bin = lambda: "wg"
    driver._quick_bin = lambda: "wg-quick"
    driver._interface_is_up = lambda _name: _async_true()
    driver._sync_peer_egress = _async_none

    async def run() -> None:
        await store.open()
        try:
            with pytest.raises(AgentError, match="sync failed"):
                await driver._apply_live(_iface())
            assert conf.read_text(encoding="utf-8") == "OLD\n"
            assert len(strips) == 1
            assert all(arg != "strip" for command in commands for arg in command)
            assert any(command[1] == "syncconf" for command in commands)
        finally:
            await store.close()

    asyncio.run(run())


def test_sync_peer_egress_calls_l2tp_once_with_drop_keys(tmp_path, monkeypatch):
    store, driver = _driver(tmp_path)
    seen: list[object] = []

    class FakeL2tp:
        def __init__(self, *_args, **_kwargs):
            return None

        async def reconcile_runtime(self, drop_keys=None):
            seen.append(list(drop_keys or []))

    async def reconcile(*_args, **_kwargs):
        seen.append("wireguard")

    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver", FakeL2tp)
    monkeypatch.setattr("agent.support.peer_egress.reconcile_core_egress", reconcile)

    async def run() -> None:
        await store.open()
        try:
            await driver._sync_peer_egress(drop_keys=["p1", "a@b"])
        finally:
            await store.close()

    asyncio.run(run())

    assert seen == ["wireguard", ["p1", "a@b"]]


def test_delete_peer_forwards_drop_keys_through_update_interface(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[list[str] | None] = []

    async def validate(_iface):
        return "stripped-conf\n"

    async def apply_live(_iface, **kwargs):
        calls.append(kwargs.get("drop_keys"))

    async def sync_l2tp(drop_keys=None):
        calls.append(["extra", *(drop_keys or [])])

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_linked_l2tp = sync_l2tp

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            assert await driver.delete_peer(1, "p1") is True
        finally:
            await store.close()

    asyncio.run(run())

    assert calls == [["p1", "a@b"]]


async def _async_true() -> bool:
    return True


async def _async_none(*_args, **_kwargs) -> None:
    return None
