from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.wireguard import WireGuardDriver, _peer_routing_changed
from agent.support.peer_egress import (
    _EgressCache,
    _gateway_for_iface,
    _install_default_route,
    _mutate_rule,
    _sysctl_write,
    reconcile_core_egress,
    repair_peer_egress,
    table_id_for_interface,
)


class _Audit:
    async def record(self, *args, **kwargs) -> None:
        return None


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


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
                "exit_interface": "eth1",
            }
        ],
    }


async def _stub_unit(*_args, **_kwargs):
    return {"ok": True, "skipped": True, "started": False}


async def _stub_true(*_args, **_kwargs):
    return True


def _patch_reconcile(monkeypatch, proc) -> None:
    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr("agent.support.peer_egress.ensure_peer_egress_unit", _stub_unit)
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)
    monkeypatch.setattr("agent.support.peer_egress._proc_sys_value", proc)


def _peers(n: int = 3) -> list[dict]:
    return [
        {
            "address": f"10.80.0.{host}",
            "exit_interface": "eth1",
            "is_enabled": True,
        }
        for host in range(2, 2 + n)
    ]


@pytest.mark.asyncio
async def test_reconcile_reads_rules_link_and_main_route_once(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []
    table = table_id_for_interface("eth1")

    def proc(key: str) -> str:
        if key == "net.ipv4.ip_forward" or key.endswith(".rp_filter"):
            return "1" if key.endswith("ip_forward") else "0"
        return "0"

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout="")
        return _Result()

    _patch_reconcile(monkeypatch, proc)
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"name": "wg0", "peers": _peers(4)}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["rules"] == 4
    assert [cmd for cmd in commands if cmd[:3] == ["ip", "-j", "rule"]] == [["ip", "-j", "rule", "show"]]
    assert [cmd for cmd in commands if cmd[:4] == ["ip", "link", "show", "eth1"]] == [["ip", "link", "show", "eth1"]]
    assert commands.count(["ip", "-4", "route", "show", "default"]) == 1
    assert commands.count(["ip", "-4", "route", "show", "table", str(table)]) == 1
    assert result["probes"]["rule_show"] == 1
    assert result["probes"]["link_show"] == 1
    assert result["probes"]["route_show"] == 2
    assert result["probes"]["route_replace"] == 1
    assert result["probes"]["sysctl_write"] == 0
    assert not any(cmd[:1] == ["sysctl"] for cmd in commands)
    await store.close()


@pytest.mark.asyncio
async def test_route_replace_skipped_only_when_single_default_matches(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    table = table_id_for_interface("eth1")
    commands: list[list[str]] = []

    def proc(key: str) -> str:
        return "1" if key.endswith("ip_forward") else "0"

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    _patch_reconcile(monkeypatch, proc)
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": _peers(1)}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert result["rules"] == 1
    assert result["deferred"] == 0
    assert ["ip", "link", "show", "eth1"] in commands
    assert ["ip", "-4", "route", "show", "default"] in commands
    assert ["ip", "-4", "route", "show", "table", str(table)] in commands
    assert result["probes"]["link_show"] == 1
    assert result["probes"]["route_show"] == 2
    assert result["probes"]["route_replace"] == 0
    assert any(cmd[:5] == ["ip", "rule", "add", "from", "10.80.0.2/32"] for cmd in commands)
    assert [cmd for cmd in commands if cmd[:3] == ["ip", "route", "replace"]] == []
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table_stdout",
    [
        "",
        "default via 10.9.9.9 dev eth1\n",
        "default via 10.0.0.1 dev eth0\n",
        "default via 10.0.0.1 dev eth1\ndefault via 10.0.0.2 dev eth1\n",
    ],
)
async def test_route_replace_runs_when_table_default_is_not_exact(tmp_path, monkeypatch, table_stdout):
    store = Store(tmp_path / "agent.db")
    await store.open()
    table = table_id_for_interface("eth1")
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout=table_stdout)
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    _patch_reconcile(monkeypatch, lambda key: "1" if str(key).endswith("ip_forward") else "0")
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": _peers(1)}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["probes"]["route_replace"] == 1
    assert [
        "ip",
        "route",
        "replace",
        "default",
        "via",
        "10.0.0.1",
        "dev",
        "eth1",
        "table",
        str(table),
    ] in commands
    await store.close()


@pytest.mark.asyncio
async def test_failed_route_replace_drops_table_cache(monkeypatch):
    shows = {"n": 0}

    def fake_run(args, **kwargs):
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            shows["n"] += 1
            return _Result(stdout="")
        if args[:3] == ["ip", "route", "replace"]:
            return _Result(returncode=1, stderr="replace failed")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    cache = _EgressCache()
    table = table_id_for_interface("eth1")
    first = await _install_default_route(fake_run, iface="eth1", table=table, cache=cache)
    second = await _install_default_route(fake_run, iface="eth1", table=table, cache=cache)
    assert first is False and second is False
    assert shows["n"] == 2
    assert cache.counts["route_replace"] == 2
    assert cache.counts["route_show"] == 3


@pytest.mark.asyncio
async def test_failed_rule_add_reloads_the_rule_book():
    shows = {"n": 0}

    def fake_run(args, **kwargs):
        if args[:3] == ["ip", "-j", "rule"]:
            shows["n"] += 1
            return _Result(stdout="[]")
        if args[:3] == ["ip", "rule", "add"]:
            return _Result(returncode=1, stderr="busy")
        return _Result()

    cache = _EgressCache()
    await cache.ensure_rules(fake_run)
    ok = await _mutate_rule(fake_run, ["rule", "add", "from", "10.80.0.2/32", "lookup", "100"], cache)
    assert ok is False
    await cache.ensure_rules(fake_run)
    assert shows["n"] == 2


@pytest.mark.asyncio
async def test_rule_book_updates_after_successful_add_without_another_show():
    shows = {"n": 0}

    def fake_run(args, **kwargs):
        if args[:3] == ["ip", "-j", "rule"]:
            shows["n"] += 1
            return _Result(stdout="[]")
        return _Result()

    cache = _EgressCache()
    await cache.ensure_rules(fake_run)
    assert cache.has_lookup("10.80.0.2/32", 100) is False
    assert await _mutate_rule(
        fake_run,
        ["rule", "add", "from", "10.80.0.2/32", "lookup", "100", "pref", "200"],
        cache,
    )
    await cache.ensure_rules(fake_run)
    assert cache.has_lookup("10.80.0.2/32", 100) is True
    assert await _mutate_rule(fake_run, ["rule", "del", "from", "10.80.0.2/32", "lookup", "100"], cache)
    assert cache.has_lookup("10.80.0.2/32", 100) is False
    assert shows["n"] == 1


@pytest.mark.asyncio
async def test_sysctl_write_skipped_when_proc_matches(monkeypatch):
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: "/sbin/sysctl")
    monkeypatch.setattr("agent.support.peer_egress._proc_sys_value", lambda key: "0")
    cache = _EgressCache()
    await _sysctl_write(fake_run, "net.ipv4.conf.all.rp_filter", "0", cache)
    await _sysctl_write(fake_run, "net.ipv4.conf.eth1.rp_filter", "0", cache)
    assert commands == []
    assert cache.counts["sysctl_write"] == 0

    monkeypatch.setattr("agent.support.peer_egress._proc_sys_value", lambda key: "1")
    await _sysctl_write(fake_run, "net.ipv4.conf.eth1.rp_filter", "0", cache)
    assert commands == [["sysctl", "-w", "net.ipv4.conf.eth1.rp_filter=0"]]
    assert cache.counts["sysctl_write"] == 1


def test_volume_batch_does_not_validate_or_reconcile(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def validate(_iface):
        calls.append("validate")
        return "stripped\n"

    async def apply_live(_iface, **kwargs):
        calls.append(f"apply:{kwargs.get('sync_egress')}")

    async def sync_egress(*_args, **_kwargs):
        calls.append("egress")

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_peer_egress = sync_egress

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            result = await driver.batch_peers(1, [{"id": "p1", "email": "a@b", "volume": 2048}])
            assert result["succeeded"] == 1
            await driver.update_peer(1, "p1", {"incoming": 10, "outgoing": 4})
        finally:
            await store.close()

    asyncio.run(run())
    assert calls == []


def test_exit_change_reconciles_without_syncconf(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def validate(_iface):
        calls.append("validate")
        return "stripped\n"

    async def apply_live(_iface, **kwargs):
        calls.append(f"apply:{kwargs.get('sync_egress')}")

    async def sync_egress(*_args, **_kwargs):
        calls.append("egress")

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_peer_egress = sync_egress

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            result = await driver.batch_peers(1, [{"id": "p1", "email": "a@b", "exit_interface": "eth2"}])
            assert result["succeeded"] == 1
        finally:
            await store.close()

    asyncio.run(run())
    assert calls == ["egress"]


def test_keepalive_syncconfs_without_egress(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def validate(_iface):
        calls.append("validate")
        return "stripped\n"

    async def apply_live(_iface, **kwargs):
        calls.append(f"apply:{kwargs.get('sync_egress')}")

    async def sync_egress(*_args, **_kwargs):
        calls.append("egress")

    driver._validate_before_apply = validate
    driver._apply_live = apply_live
    driver._sync_peer_egress = sync_egress

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            result = await driver.batch_peers(1, [{"id": "p1", "email": "a@b", "persistent_keepalive": 25}])
            assert result["succeeded"] == 1
        finally:
            await store.close()

    asyncio.run(run())
    assert calls == ["validate", "apply:False"]


def test_disable_and_delete_still_reconcile(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[tuple] = []

    async def validate(_iface):
        return "stripped\n"

    async def apply_live(_iface, **kwargs):
        calls.append((kwargs.get("sync_egress"), list(kwargs.get("drop_keys") or [])))

    driver._validate_before_apply = validate
    driver._apply_live = apply_live

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            disabled = await driver.batch_peers(1, [{"id": "p1", "email": "a@b", "is_enabled": False}])
            assert disabled["succeeded"] == 1
            assert await driver.delete_peer(1, "p1") is True
        finally:
            await store.close()

    asyncio.run(run())
    assert calls == [(True, []), (True, ["p1", "a@b"])]


def test_new_peer_with_exit_reconciles_and_without_exit_does_not(tmp_path):
    store, driver = _driver(tmp_path)
    calls: list[str] = []

    async def spawn(_iface, raw, _used):
        peer = {
            "id": str(raw.get("id") or "new"),
            "email": str(raw.get("email") or "n@b"),
            "address": "10.80.0.9",
            "allowed_ips": "10.80.0.9/32",
            "public_key": "peer-public-2",
            "private_key": "peer-private-2",
            "is_enabled": True,
        }
        if raw.get("exit_interface"):
            peer["exit_interface"] = raw["exit_interface"]
        return peer

    async def validate(_iface):
        calls.append("validate")
        return "stripped\n"

    async def apply_live(_iface, **kwargs):
        calls.append(f"apply:{kwargs.get('sync_egress')}")

    driver._spawn_peer = spawn
    driver._prefetch_create_keypairs = lambda *args, **kwargs: _done()
    driver._validate_before_apply = validate
    driver._apply_live = apply_live

    async def run() -> None:
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", _iface())
            plain = await driver.batch_peers(1, [{"id": "n1", "email": "n@b"}])
            assert plain["succeeded"] == 1
            routed = await driver.batch_peers(1, [{"id": "n2", "email": "r@b", "exit_interface": "eth1"}])
            assert routed["succeeded"] == 1
        finally:
            await store.close()

    asyncio.run(run())
    assert calls == ["validate", "apply:False", "validate", "apply:True"]


def _done():
    async def inner():
        return None

    return inner()


def test_routing_key_ignores_quota_and_sees_exit_enable_and_link():
    before = {"address": "10.80.0.2", "exit_interface": "eth1", "is_enabled": True, "volume": 1}
    assert _peer_routing_changed(before, {**before, "volume": 9, "incoming": 3}) is False
    assert _peer_routing_changed(before, {**before, "exit_interface": "eth2"}) is True
    assert _peer_routing_changed(before, {**before, "is_enabled": False}) is True
    assert _peer_routing_changed(before, {**before, "address": "10.80.0.3"}) is True
    linked = {**before, "is_enabled": False, "linked_peer_id": "l2"}
    assert _peer_routing_changed(before, linked) is True
    assert _peer_routing_changed(linked, {**linked, "volume": 4}) is False


@pytest.mark.asyncio
async def test_successful_empty_main_table_installs_on_link_default(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    table = table_id_for_interface("eth1")
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout="")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    _patch_reconcile(monkeypatch, lambda key: "1" if str(key).endswith("ip_forward") else "0")
    cache = _EgressCache()
    read = await _gateway_for_iface(fake_run, "eth1", cache)
    assert read.ok is True
    assert read.via is None
    assert cache.main_defaults == []

    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": _peers(1)}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["rules"] == 1
    assert ["ip", "route", "replace", "default", "dev", "eth1", "table", str(table)] in commands
    await store.close()


@pytest.mark.asyncio
async def test_failed_main_route_is_not_cached_as_empty_and_does_not_strip_gateway(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    table = table_id_for_interface("eth1")
    commands: list[list[str]] = []
    mode = {"main": "raise"}

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            if mode["main"] == "raise":
                raise RuntimeError("netlink down")
            if mode["main"] == "fail":
                return _Result(returncode=1, stderr="RTNETLINK answers: Network is down")
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    _patch_reconcile(monkeypatch, lambda key: "1" if str(key).endswith("ip_forward") else "0")
    cache = _EgressCache()
    raised = await _gateway_for_iface(fake_run, "eth1", cache)
    mode["main"] = "fail"
    failed = await _gateway_for_iface(fake_run, "eth1", cache)
    assert raised.ok is False and failed.ok is False
    assert cache.main_defaults is None

    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": _peers(1)}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["deferred"] == 1
    assert result["rules"] == 0
    assert ["ip", "route", "replace", "default", "dev", "eth1", "table", str(table)] not in commands
    assert [cmd for cmd in commands if cmd[:3] == ["ip", "route", "replace"]] == []

    mode["main"] = "ok"
    commands.clear()
    retry_cache = _EgressCache()
    retried = await _gateway_for_iface(fake_run, "eth1", retry_cache)
    assert retried.ok is True
    assert retried.via == "10.0.0.1"
    assert retry_cache.main_defaults == [("eth1", "10.0.0.1")]
    installed = await _install_default_route(fake_run, iface="eth1", table=table, cache=retry_cache)
    assert installed is True
    assert [cmd for cmd in commands if cmd[:3] == ["ip", "route", "replace"]] == []
    await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stderr",
    [
        "RTNETLINK answers: No such file or directory",
        "Error: No such process",
    ],
)
async def test_absent_rule_delete_updates_the_map(stderr):
    shows = {"n": 0}

    def fake_run(args, **kwargs):
        if args[:3] == ["ip", "-j", "rule"]:
            shows["n"] += 1
            return _Result(stdout='[{"src":"10.80.0.2","table":100}]')
        if args[:3] == ["ip", "rule", "del"]:
            return _Result(returncode=2, stderr=stderr)
        return _Result()

    cache = _EgressCache()
    await cache.ensure_rules(fake_run)
    assert cache.has_lookup("10.80.0.2/32", 100) is True
    ok = await _mutate_rule(fake_run, ["rule", "del", "from", "10.80.0.2/32", "lookup", "100"], cache)
    assert ok is True
    assert cache.rules_loaded is True
    assert cache.has_lookup("10.80.0.2/32", 100) is False
    assert shows["n"] == 1


@pytest.mark.asyncio
async def test_unrelated_rule_delete_failure_reloads_the_map():
    shows = {"n": 0}

    def fake_run(args, **kwargs):
        if args[:3] == ["ip", "-j", "rule"]:
            shows["n"] += 1
            return _Result(stdout='[{"src":"10.80.0.2","table":100}]')
        if args[:3] == ["ip", "rule", "del"]:
            return _Result(returncode=1, stderr="RTNETLINK answers: Operation not permitted")
        return _Result()

    cache = _EgressCache()
    await cache.ensure_rules(fake_run)
    ok = await _mutate_rule(fake_run, ["rule", "del", "from", "10.80.0.2/32", "lookup", "100"], cache)
    assert ok is False
    assert cache.rules_loaded is False
    await cache.ensure_rules(fake_run)
    assert cache.has_lookup("10.80.0.2/32", 100) is True
    assert shows["n"] == 2


@pytest.mark.asyncio
async def test_repair_fixes_missing_rule_and_wrong_route(tmp_path, monkeypatch):
    import agent.support.peer_egress as egress

    store = Store(tmp_path / "agent.db")
    await store.open()
    table = table_id_for_interface("eth1")
    commands: list[list[str]] = []
    monkeypatch.setattr(egress, "_UNIT_PATH", tmp_path / "systemd" / "agent-peer-egress.service")
    monkeypatch.setattr(egress, "_SYSCTL_DROPIN", tmp_path / "sysctl" / "99-netinja-peer-egress.conf")
    monkeypatch.setattr(
        egress.shutil,
        "which",
        lambda cmd: None if cmd in {"iptables", "iptables-legacy", "conntrack"} else f"/usr/sbin/{cmd}",
    )
    monkeypatch.setattr(egress, "_proc_sys_value", lambda key: "1" if str(key).endswith("ip_forward") else "0")

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if args[:5] == ["ip", "-4", "route", "show", "table"]:
            return _Result(stdout="default via 10.9.9.9 dev eth1\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    await store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg0",
            "peers": [{"address": "10.80.0.2", "exit_interface": "eth1", "is_enabled": True}],
        },
    )
    result = await repair_peer_egress(store, data_dir=tmp_path, runner=fake_run)
    core = result["cores"]["wireguard"]
    assert result["forced"] is True
    assert result["ok"] is True
    assert core["forced"] is True
    assert core["nat_rebuilt"] is True
    assert core["rules"] == 1
    assert ["ip", "link", "show", "eth1"] in commands
    assert any(cmd[:5] == ["ip", "rule", "add", "from", "10.80.0.2/32"] and str(table) in cmd for cmd in commands)
    assert [
        "ip",
        "route",
        "replace",
        "default",
        "via",
        "10.0.0.1",
        "dev",
        "eth1",
        "table",
        str(table),
    ] in commands
    assert ["nft", "flush", "chain", "inet", "netinja_egress", "postrouting"] in commands
    assert ["systemctl", "start", "agent-peer-egress.service"] in commands
    assert result["persist"]["unit"]["started"] is True
    await store.close()
