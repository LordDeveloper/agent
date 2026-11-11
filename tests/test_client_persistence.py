"""Client state must match the core runtime and the persistent config."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.openvpn import OpenVpnDriver
from agent.drivers.wireguard import WireGuardDriver
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError
from tests.fake_xray import FakeXrayHttpClient


class _Audit:
    async def record(self, *_args, **_kwargs) -> None:
        return None


def _inbound(tag: str = "inbound-1") -> dict:
    return {
        "tag": tag,
        "protocol": "vless",
        "port": 443,
        "listen": "0.0.0.0",
        "settings": {"decryption": "none", "clients": []},
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def _client(email: str = "one@x") -> dict:
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "email": email,
        "is_enabled": True,
    }


async def _xray(tmp_path: Path, fake: FakeXrayHttpClient) -> tuple[Store, XrayDriver, Path]:
    store = Store(tmp_path / "agent.db")
    await store.open()
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"inbounds": [_inbound()]}), encoding="utf-8")
    settings = AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "agent.db"),
        xray_config=str(config),
        xray_binary=str(tmp_path / "missing-xray"),
    )
    fake.add_inbounds([_inbound()])
    fake.config_path = config
    fake.persist_config = True
    driver = XrayDriver(settings, _Audit(), store, client=fake)
    return store, driver, config


def _emails(config: Path) -> list[str]:
    data = json.loads(config.read_text(encoding="utf-8"))
    rows = ((data["inbounds"][0].get("settings") or {}).get("clients") or [])
    return [str(row.get("email") or "") for row in rows]


def test_xray_create_persists_and_is_visible_at_runtime(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        try:
            async def agent_must_not_write(*_args, **_kwargs):
                raise AssertionError("agent wrote config.json")

            driver._mutate_persisted_config = agent_must_not_write
            result = await driver.batch_clients(1, [_client()])
            assert result["failed"] == 0
            assert result["succeeded"] == 1
            assert _emails(config) == ["one@x"]
            assert [row["email"] for row in fake.list_users("inbound-1")] == ["one@x"]
            assert "_wire_user" not in result["clients"][0]
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_runtime_success_without_persistence_is_not_success(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        original = config.read_text(encoding="utf-8")
        fake.persist_config = False
        try:
            result = await driver.batch_clients(1, [_client()])
            assert result["ok"] is False
            assert result["failed"] == 1
            assert result["clients"] == []
            assert config.read_text(encoding="utf-8") == original
            assert [row["email"] for row in fake.list_users("inbound-1")] == ["one@x"]
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_disable_clears_client_left_in_config_users(tmp_path: Path):
    """users/remove can clear settings.clients and leave the same row in settings.users."""

    async def run() -> None:
        import agent.drivers.xray as xray_mod

        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        previous_delay = xray_mod._PERSIST_CONFIRM_DELAY_SECONDS
        xray_mod._PERSIST_CONFIRM_DELAY_SECONDS = 0
        try:
            keep = {
                "id": "11111111-1111-4111-8111-111111111111",
                "email": "keep@x",
                "is_enabled": True,
            }
            stay = {
                "id": "22222222-2222-4222-8222-222222222222",
                "email": "stay@x",
                "is_enabled": True,
            }
            created = await driver.batch_clients(1, [keep, stay])
            assert created["failed"] == 0, created

            data = json.loads(config.read_text(encoding="utf-8"))
            copied = [dict(row) for row in data["inbounds"][0]["settings"]["clients"]]
            data["inbounds"][0]["settings"]["users"] = copied
            config.write_text(json.dumps(data), encoding="utf-8")
            for inbound in fake._inbounds:
                if inbound.get("tag") == "inbound-1":
                    inbound.setdefault("settings", {})["users"] = [dict(row) for row in copied]

            def remove_users(tag, emails, **_kwargs):
                email_set = {str(email) for email in emails}
                for inbound in fake._inbounds:
                    if inbound.get("tag") != tag:
                        continue
                    settings = inbound.setdefault("settings", {})
                    settings["clients"] = [
                        row
                        for row in (settings.get("clients") or [])
                        if str(row.get("email")) not in email_set
                    ]
                    fake._mirror_config()
                    return {"succeeded": len(emails), "failed": 0, "removed_users": len(emails)}
                raise RuntimeError(f"inbound {tag} missing")

            real_edit = fake.edit_inbounds

            def edit_inbounds(inbounds, **kwargs):
                result = real_edit(inbounds, **kwargs)
                stored = json.loads(config.read_text(encoding="utf-8"))
                live = {str(row.get("tag") or ""): row for row in fake._inbounds}
                for inbound in stored.get("inbounds") or []:
                    source = live.get(str(inbound.get("tag") or ""))
                    if source is None:
                        continue
                    src = source.get("settings") or {}
                    settings = inbound.setdefault("settings", {})
                    settings["clients"] = json.loads(json.dumps(src.get("clients") or []))
                    if "users" in src:
                        settings["users"] = json.loads(json.dumps(src.get("users") or []))
                config.write_text(json.dumps(stored), encoding="utf-8")
                return result

            fake.remove_users = remove_users
            fake.edit_inbounds = edit_inbounds

            disabled = await driver.batch_clients(1, [{**stay, "is_enabled": False}])
            assert disabled["failed"] == 0, disabled
            assert disabled["ok"] is True

            stored = json.loads(config.read_text(encoding="utf-8"))
            settings = stored["inbounds"][0]["settings"]
            assert [row.get("email") for row in settings.get("clients") or []] == ["keep@x"]
            assert settings.get("users") == []
            assert [row["email"] for row in fake.list_users("inbound-1")] == ["keep@x"]
        finally:
            xray_mod._PERSIST_CONFIRM_DELAY_SECONDS = previous_delay
            await store.close()

    asyncio.run(run())


def test_xray_persistence_is_not_written_when_runtime_rejects(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        original = config.read_text(encoding="utf-8")

        def reject(*_args, **_kwargs):
            raise AgentError("EXEC_ERROR", "xray rejected the user", 500)

        fake.add_users = reject
        try:
            result = await driver.batch_clients(1, [_client()])
            assert result["failed"] == 1
            assert config.read_text(encoding="utf-8") == original
            assert fake.list_users("inbound-1") == []
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_reconcile_repairs_disk_and_runtime_without_duplicates(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
            data["inbounds"][0]["settings"]["clients"] = [
                {"id": "11111111-1111-4111-8111-111111111111", "email": "disk@x"}
            ]
            config.write_text(json.dumps(data), encoding="utf-8")
            driver._invalidate_config_cache()
            first = await driver.reconcile_persisted_clients()
            assert first["added_runtime"] == 1
            assert [row["email"] for row in fake.list_users("inbound-1")] == ["disk@x"]

            fake.persist_config = False
            fake.add_users("inbound-1", [{"id": "22222222-2222-4222-8222-222222222222", "email": "live@x"}])
            fake.persist_config = True
            second = await driver.reconcile_persisted_clients()
            assert second["persisted"] == 1
            assert sorted(_emails(config)) == ["disk@x", "live@x"]

            third = await driver.reconcile_persisted_clients()
            assert third["added_runtime"] == 0
            assert third["persisted"] == 0
            assert sorted(_emails(config)) == ["disk@x", "live@x"]
            assert sorted(row["email"] for row in fake.list_users("inbound-1")) == ["disk@x", "live@x"]
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_reconcile_leaves_disk_clients_when_api_is_down(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
            data["inbounds"][0]["settings"]["clients"] = [
                {"id": "11111111-1111-4111-8111-111111111111", "email": "disk@x"}
            ]
            config.write_text(json.dumps(data), encoding="utf-8")
            driver._invalidate_config_cache()

            async def down(*_args, **_kwargs):
                raise AgentError("EXEC_ERROR", "connection refused", 500)

            driver._api_call = down
            report = await driver.reconcile_persisted_clients()
            assert report["ok"] is False
            assert "inbound-1" in report["skipped"]
            assert _emails(config) == ["disk@x"]
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_invalid_config_is_left_unchanged(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        config.write_text("{", encoding="utf-8")
        driver._invalidate_config_cache()
        try:
            report = await driver.reconcile_persisted_clients()
            assert report["ok"] is False
            assert report["skipped"] == ["invalid_config"]
            assert config.read_text(encoding="utf-8") == "{"
        finally:
            await store.close()

    asyncio.run(run())


def test_xray_retry_after_persist_failure_does_not_duplicate(tmp_path: Path):
    async def run() -> None:
        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        fake.persist_config = False
        try:
            first = await driver.batch_clients(1, [_client()])
            assert first["ok"] is False
            fake.persist_config = True
            second = await driver.batch_clients(1, [_client()])
            assert second["ok"] is True
            assert _emails(config) == ["one@x"]
            assert [row["email"] for row in fake.list_users("inbound-1")] == ["one@x"]
        finally:
            await store.close()

    asyncio.run(run())


def _wg_settings(tmp_path: Path) -> tuple[Store, WireGuardDriver]:
    store = Store(tmp_path / "agent.db")
    settings = AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "agent.db"),
        wireguard_config_dir=str(tmp_path / "wg"),
    )
    return store, WireGuardDriver(settings, _Audit(), store)


def _wg_iface() -> dict:
    return {
        "id": 1,
        "name": "wg0",
        "listen_port": 51820,
        "subnet": "10.80.0.0/24",
        "address": "10.80.0.1/24",
        "private_key": "server-private",
        "public_key": "server-public",
        "peers": [],
    }


def test_wireguard_conf_write_is_atomic_and_contains_the_peer(tmp_path: Path):
    store, driver = _wg_settings(tmp_path)
    iface = _wg_iface()
    iface["peers"] = [
        {
            "id": "p1",
            "email": "a@b",
            "address": "10.80.0.2",
            "allowed_ips": "10.80.0.2/32",
            "private_key": "peer-private",
            "public_key": "peer-public",
            "is_enabled": True,
        }
    ]

    driver._sync_conf(iface)
    text = (tmp_path / "wg" / "wg0.conf").read_text(encoding="utf-8")
    assert "PublicKey = peer-public" in text
    assert "SaveConfig" not in text
    assert "peer-private" not in text
    assert list((tmp_path / "wg").glob(".wg0.conf.*.tmp")) == []
    if os.name == "posix":
        assert (tmp_path / "wg" / "wg0.conf").stat().st_mode & 0o777 == 0o600


def test_concurrent_wireguard_peers_are_not_lost(tmp_path: Path):
    store, driver = _wg_settings(tmp_path)

    async def validate(_iface):
        return "stripped\n"

    async def apply_live(_iface, **_kwargs):
        await asyncio.sleep(0.05)

    driver._validate_before_apply = validate
    driver._apply_live = apply_live

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _wg_iface())
            peer_a = {
                "id": "a",
                "email": "a@x",
                "address": "10.80.0.2",
                "public_key": "pub-a",
                "private_key": "priv-a",
                "is_enabled": True,
            }
            peer_b = {
                "id": "b",
                "email": "b@x",
                "address": "10.80.0.3",
                "public_key": "pub-b",
                "private_key": "priv-b",
                "is_enabled": True,
            }
            await asyncio.gather(
                driver.batch_peers(1, [peer_a]),
                driver.batch_peers(1, [peer_b]),
            )
            stored = await driver.get_interface(1)
            assert {row["id"] for row in stored["peers"]} == {"a", "b"}
        finally:
            await store.close()

    asyncio.run(run())


def test_wireguard_restart_reconcile_repairs_missing_peers(tmp_path: Path):
    store, driver = _wg_settings(tmp_path)
    repaired: list[str] = []

    async def is_up(_name: str) -> bool:
        return True

    async def repair(iface, **_kwargs):
        repaired.append(str(iface.get("name")))
        return True

    async def egress(*_args, **_kwargs):
        return None

    driver._interface_is_up = is_up
    driver._repair_kernel_peers = repair
    driver._sync_peer_egress = egress

    async def run() -> None:
        await store.open()
        try:
            await driver._reconcile_after_lifecycle([_wg_iface()], [], "restart")
            assert repaired == ["wg0"]
            await driver._reconcile_after_lifecycle([_wg_iface()], [], "restart")
            assert repaired == ["wg0", "wg0"]
        finally:
            await store.close()

    asyncio.run(run())


def test_openvpn_auth_write_is_verified_and_failure_is_not_success(tmp_path: Path):
    settings = AgentSettings(data_dir=str(tmp_path), db_path=str(tmp_path / "agent.db"))
    store = Store(tmp_path / "agent.db")
    driver = OpenVpnDriver(settings, _Audit(), store)
    driver._auth_root = lambda: tmp_path / "openvpn"
    server = {
        "id": 1,
        "subnet": "10.8.0.0/24",
        "users": [
            {
                "id": "u1",
                "username": "alice",
                "password": "secret",
                "address": "10.8.0.2",
                "is_enabled": True,
            }
        ],
    }

    async def run() -> None:
        await driver._apply_server_auth_files(server)
        passwd = (tmp_path / "openvpn" / "ovpn1" / "passwd").read_text(encoding="utf-8")
        assert "alice " in passwd

        async def fail(*_args, **_kwargs):
            raise OSError("disk full")

        driver_fail = OpenVpnDriver(settings, _Audit(), store)
        driver_fail._auth_root = driver._auth_root
        import agent.support.aiofs as aiofs

        original = aiofs.atomic_write
        aiofs.atomic_write = fail
        try:
            with pytest.raises(AgentError, match="were not written"):
                await driver_fail._apply_server_auth_files(server)
        finally:
            aiofs.atomic_write = original

    asyncio.run(run())


def test_xray_batch_remove_drops_live_user_when_config_row_is_gone(tmp_path: Path):
    async def run() -> None:
        import agent.drivers.xray as xray_mod

        fake = FakeXrayHttpClient()
        store, driver, config = await _xray(tmp_path, fake)
        previous_delay = xray_mod._PERSIST_CONFIRM_DELAY_SECONDS
        xray_mod._PERSIST_CONFIRM_DELAY_SECONDS = 0
        node_id = "panel-node-1"
        email = "ss1a2b"
        try:
            fake.add_users("inbound-1", [_client(email)])
            await store.put_doc(
                "xray",
                "client_quota",
                node_id,
                {"id": node_id, "node_id": node_id, "email": email},
            )
            config.write_text(json.dumps({"inbounds": [_inbound()]}), encoding="utf-8")
            driver._invalidate_config_cache()

            result = await driver.batch_remove_clients(1, ids=[node_id])
            assert result["succeeded"] == 1, result
            assert [row["email"] for row in fake.list_users("inbound-1")] == []
            assert await store.get_doc("xray", "client_quota", node_id) is None
        finally:
            xray_mod._PERSIST_CONFIRM_DELAY_SECONDS = previous_delay
            await store.close()

    asyncio.run(run())
