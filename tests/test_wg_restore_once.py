from __future__ import annotations

import asyncio

from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.wireguard import WireGuardDriver, _materialize_peer_keypair


class _Audit:
    async def record(self, *args, **kwargs) -> None:
        return None


def test_materialize_keeps_existing_keypair_without_wg(monkeypatch):
    async def fail_pubkey(*args, **kwargs):
        raise AssertionError("wg pubkey should not run when the backup already has both keys")

    monkeypatch.setattr("agent.drivers.wireguard._require_wg_pubkey", fail_pubkey)
    peer = {"private_key": "priv", "public_key": "pub"}
    asyncio.run(_materialize_peer_keypair(peer, "wg"))
    assert peer == {"private_key": "priv", "public_key": "pub"}


def test_sync_linked_l2tp_awaits_reconcile(tmp_path, monkeypatch):
    import agent.drivers.l2tp as l2tp_mod

    seen: dict = {}

    class FakeL2tp:
        def __init__(self, settings, audit, store):
            seen["ready"] = True

        async def reconcile_runtime(self, drop_keys=None):
            seen["drop_keys"] = list(drop_keys or [])

    monkeypatch.setattr(l2tp_mod, "L2tpDriver", FakeL2tp)
    store = Store(tmp_path / "agent.db")

    async def run():
        await store.open()
        settings = AgentSettings(data_dir=str(tmp_path), db_path=str(store.path))
        driver = WireGuardDriver(settings, _Audit(), store)
        await driver._sync_linked_l2tp(["peer-1"])
        await store.close()

    asyncio.run(run())

    assert seen["ready"] is True
    assert seen["drop_keys"] == ["peer-1"]


def test_restore_brings_each_interface_up_once(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    settings = AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "agent.db"),
        wireguard_config_dir=str(tmp_path / "wg"),
    )
    driver = WireGuardDriver(settings, _Audit(), store)
    calls: list[tuple] = []

    async def create_interface(payload, *, apply=True):
        calls.append(("create", apply, payload.get("name")))
        iface = {"id": 7, "name": payload.get("name") or "wg0", "peers": []}
        await store.put_doc("wireguard", "interface", "7", iface)
        return iface

    async def stage_peers(interface_id, peers):
        calls.append(("stage", interface_id, len(peers)))
        iface = {"id": interface_id, "name": "wg0", "peers": peers}
        return iface

    async def bring_up(iface):
        calls.append(("up", len(iface.get("peers") or [])))
        return {"ok": True}

    async def delete_interface(interface_id):
        calls.append(("delete", interface_id))
        return True

    monkeypatch.setattr(driver, "create_interface", create_interface)
    monkeypatch.setattr(driver, "_stage_peers", stage_peers)
    monkeypatch.setattr(driver, "_bring_up", bring_up)
    monkeypatch.setattr(driver, "delete_interface", delete_interface)

    async def run():
        await store.open()
        try:
            await store.put_doc(
                "wireguard",
                "interface",
                "1",
                {"id": 1, "name": "old", "subnet": "10.90.0.0/16"},
            )
            await driver.restore(
                {
                    "interfaces": [
                        {
                            "name": "wg0",
                            "private_key": "server",
                            "public_key": "serverpub",
                            "peers": [
                                {"id": "a", "public_key": "p1", "private_key": "k1", "address": "10.90.68.2"},
                                {"id": "b", "public_key": "p2", "private_key": "k2", "address": "10.90.68.5"},
                            ],
                        }
                    ]
                }
            )
        finally:
            await store.close()

    asyncio.run(run())

    assert calls == [
        ("delete", 1),
        ("create", False, "wg0"),
        ("stage", 7, 2),
        ("up", 2),
    ]
