from __future__ import annotations

import json

import pytest
from types import SimpleNamespace

from agent.db import Store
from agent.support.host_interfaces import list_host_interfaces
from agent.support.peer_egress import (
    desired_rules_from_interfaces,
    reconcile_core_egress,
    repair_peer_egress,
    render_apply_script,
    table_id_for_interface,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


async def _stub_peer_egress_unit(_script_path, *, runner=None, start=False, **_kwargs):
    return {"ok": True, "skipped": True, "started": start}


async def _stub_true(*_args, **_kwargs):
    return True


def test_table_id_for_interface_is_stable():
    assert table_id_for_interface("eth1") == table_id_for_interface("eth1")
    assert 10000 <= table_id_for_interface("eth1") < 30000
    assert table_id_for_interface("eth1") != table_id_for_interface("wg-de")


def test_desired_rules_from_interfaces_skips_disabled_and_missing_exit():
    rules = desired_rules_from_interfaces(
        [
            {
                "peers": [
                    {"address": "10.80.0.2", "exit_interface": "eth1", "is_enabled": True},
                    {"address": "10.80.0.3", "exit_interface": "eth1", "is_enabled": False},
                    {"address": "10.80.0.4", "is_enabled": True},
                    {"address": "10.80.0.5", "exit_interface": "wg-de", "enable": True},
                ]
            }
        ]
    )
    assert {(row["addr"], row["iface"]) for row in rules} == {
        ("10.80.0.2", "eth1"),
        ("10.80.0.5", "wg-de"),
    }


def test_desired_rules_prohibit_disabled_companion():
    rules = desired_rules_from_interfaces(
        [
            {
                "peers": [
                    {
                        "address": "10.90.128.3",
                        "linked_peer_id": "peer-1",
                        "exit_interface": "de",
                        "is_enabled": False,
                    }
                ]
            }
        ]
    )
    assert rules == [
        {
            "addr": "10.90.128.3",
            "cidr": "10.90.128.3/32",
            "iface": "",
            "table": 0,
            "action": "prohibit",
        }
    ]


@pytest.mark.asyncio
async def test_list_host_interfaces_filters_loopback(monkeypatch):
    payload = [
        {
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP"],
            "operstate": "UNKNOWN",
            "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}],
        },
        {
            "ifname": "eth1",
            "flags": ["BROADCAST", "UP", "LOWER_UP"],
            "operstate": "UP",
            "link_type": "ether",
            "addr_info": [
                {"family": "inet", "local": "10.0.0.8", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
            ],
        },
        {
            "ifname": "wg-de",
            "flags": ["POINTOPOINT", "UP"],
            "operstate": "UP",
            "link_type": "wireguard",
            "addr_info": [{"family": "inet", "local": "10.66.0.1", "prefixlen": 32}],
        },
    ]

    def fake_run(args, **kwargs):
        assert args[:2] == ["ip", "-j"]
        return _Result(stdout=json.dumps(payload))

    monkeypatch.setattr("agent.support.host_interfaces.shutil.which", lambda cmd: "/sbin/ip" if cmd == "ip" else None)
    rows = await list_host_interfaces(runner=fake_run)
    assert [row["name"] for row in rows] == ["eth1", "wg-de"]
    assert rows[0]["addresses"] == ["10.0.0.8/24"]
    assert rows[1]["link_type"] == "wireguard"


@pytest.mark.asyncio
async def test_reconcile_core_egress_applies_and_cleans(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []
    live_rules: set[tuple[str, int]] = set()

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "rule", "add"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.add((cidr, table))
            return _Result()
        if args[:3] == ["ip", "rule", "del"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.discard((cidr, table))
            return _Result()
        if args[:3] == ["ip", "-j", "rule"]:
            rows = [{"src": cidr.split("/", 1)[0], "table": table} for cidr, table in live_rules]
            return _Result(stdout=json.dumps(rows))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1 proto dhcp metric 100\n")
        if args[:2] == ["nft", "-j"] and "postrouting" in args:
            return _Result(
                stdout=json.dumps(
                    {
                        "nftables": [
                            {
                                "rule": {
                                    "expr": [
                                        {"match": {"left": {"meta": {"key": "oifname"}}, "right": "eth1"}},
                                        {"masquerade": None},
                                    ]
                                }
                            }
                        ]
                    }
                )
            )
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    first = await reconcile_core_egress(
        store,
        "wireguard",
        [
            {
                "peers": [
                    {
                        "address": "10.80.0.2",
                        "exit_interface": "eth1",
                        "is_enabled": True,
                    }
                ]
            }
        ],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert first["ok"] is True
    assert first["rules"] == 1
    table = table_id_for_interface("eth1")
    assert any(
        cmd[:5] == ["ip", "rule", "add", "from", "10.80.0.2/32"] and str(table) in cmd
        for cmd in commands
    )
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
    assert ["sysctl", "-w", "net.ipv4.conf.eth1.rp_filter=0"] in commands
    script = tmp_path / "peer-egress-apply.sh"
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert f'lookup {table}' in text
    assert f'_default_for_iface "eth1" {table}' in text
    assert "_iface_ready" in text
    assert "_soften_rp_filter" in text

    # Idempotent re-reconcile: do not churn rules or rebuild NAT when already healthy.
    commands.clear()
    again = await reconcile_core_egress(
        store,
        "wireguard",
        [
            {
                "peers": [
                    {
                        "address": "10.80.0.2",
                        "exit_interface": "eth1",
                        "is_enabled": True,
                    }
                ]
            }
        ],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert again["ok"] is True
    assert again.get("nat_rebuilt") is False
    assert not any(cmd[:5] == ["ip", "rule", "add", "from", "10.80.0.2/32"] for cmd in commands)
    assert not any(cmd[:1] == ["nft"] and "flush" in cmd for cmd in commands)

    commands.clear()
    second = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": []}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert second["ok"] is True
    assert second["rules"] == 0
    assert ["ip", "rule", "del", "from", "10.80.0.2/32", "lookup", str(table)] in commands
    assert ["ip", "route", "flush", "table", str(table)] in commands
    assert ["conntrack", "-D", "-s", "10.80.0.2"] in commands
    await store.close()


@pytest.mark.asyncio
async def test_reconcile_switches_exit_atomically(tmp_path, monkeypatch):
    """Server change: add new exit rule before deleting the old one."""
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []
    live_rules: set[tuple[str, int]] = set()

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "rule", "add"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.add((cidr, table))
            return _Result()
        if args[:3] == ["ip", "rule", "del"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.discard((cidr, table))
            return _Result()
        if args[:3] == ["ip", "-j", "rule"]:
            rows = [{"src": cidr.split("/", 1)[0], "table": table} for cidr, table in live_rules]
            return _Result(stdout=json.dumps(rows))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    poland = table_id_for_interface("poland")
    sweden = table_id_for_interface("sweden")

    first = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.72.174.10", "exit_interface": "poland", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert first["ok"] is True
    assert first["rules"] == 1
    assert ("10.72.174.10/32", poland) in live_rules

    commands.clear()
    switched = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.72.174.10", "exit_interface": "sweden", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert switched["ok"] is True
    assert switched["switched"] == 1

    add_new = ["ip", "rule", "add", "from", "10.72.174.10/32", "lookup", str(sweden)]
    # Cutover uses pref; accept any add that targets sweden lookup.
    add_idxs = [
        i
        for i, cmd in enumerate(commands)
        if cmd[:5] == ["ip", "rule", "add", "from", "10.72.174.10/32"] and str(sweden) in cmd
    ]
    del_old = ["ip", "rule", "del", "from", "10.72.174.10/32", "lookup", str(poland)]
    assert add_idxs, f"missing sweden add in {commands}"
    assert del_old in commands
    assert min(add_idxs) < commands.index(del_old)
    assert ["conntrack", "-D", "-s", "10.72.174.10"] in commands
    assert ("10.72.174.10/32", sweden) in live_rules
    assert ("10.72.174.10/32", poland) not in live_rules
    await store.close()


@pytest.mark.asyncio
async def test_reconcile_skips_missing_exit_interface(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "link", "show"] and args[3:] == ["usa"]:
            return _Result(returncode=1, stderr="Device \"usa\" does not exist.\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    table = table_id_for_interface("usa")
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "usa", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert result["rules"] == 0
    assert result.get("deferred") == 1
    assert ["ip", "rule", "add", "from", "10.90.68.3/32", "lookup", str(table)] not in commands
    await store.close()


@pytest.mark.asyncio
async def test_reconcile_probes_a_missing_exit_once(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "link", "show"]:
            return _Result(returncode=1, stderr="missing")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)
    peers = [
        {"address": f"10.90.68.{host}", "exit_interface": "tr", "is_enabled": True}
        for host in (2, 5, 8)
    ]
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"name": "wg0", "peers": peers}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    probes = [cmd for cmd in commands if cmd[:4] == ["ip", "link", "show", "tr"]]
    assert result["deferred"] == 3
    assert probes == [["ip", "link", "show", "tr"]]
    await store.close()


@pytest.mark.asyncio
async def test_reconcile_retains_rule_when_exit_temporarily_missing(tmp_path, monkeypatch):
    """Missing exit must not delete the prior lookup rule (avoids region primary IP leak)."""
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []
    live_rules: set[tuple[str, int]] = set()
    usa_up = True

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "link", "show"] and args[3:] == ["usa"]:
            if usa_up:
                return _Result()
            return _Result(returncode=1, stderr='Device "usa" does not exist.\n')
        if args[:3] == ["ip", "rule", "add"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.add((cidr, table))
            return _Result()
        if args[:3] == ["ip", "rule", "del"] and "from" in args and "lookup" in args:
            cidr = args[args.index("from") + 1]
            table = int(args[args.index("lookup") + 1])
            live_rules.discard((cidr, table))
            return _Result()
        if args[:3] == ["ip", "-j", "rule"]:
            rows = [{"src": cidr.split("/", 1)[0], "table": table} for cidr, table in live_rules]
            return _Result(stdout=json.dumps(rows))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    table = table_id_for_interface("usa")
    first = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "usa", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert first["ok"] is True
    assert first["rules"] == 1
    assert ("10.90.68.3/32", table) in live_rules

    commands.clear()
    usa_up = False
    deferred = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "usa", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert deferred["ok"] is True
    assert deferred["rules"] == 1
    assert deferred.get("deferred") == 1
    assert ["ip", "rule", "del", "from", "10.90.68.3/32", "lookup", str(table)] not in commands
    assert ["ip", "route", "flush", "table", str(table)] not in commands
    assert ("10.90.68.3/32", table) in live_rules

    state = await store.get_doc("wireguard", "egress_state", "applied") or {}
    assert state.get("rules") == [{"addr": "10.90.68.3", "table": table, "iface": "usa", "action": "lookup"}]
    await store.close()


@pytest.mark.asyncio
async def test_reconcile_uses_dev_only_when_exit_has_no_main_gateway(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            # Main default is on eth0; exit iface `uk` is a tunnel without main default.
            return _Result(stdout="default via 203.0.113.1 dev eth0\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    table = table_id_for_interface("uk")
    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "uk", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert ["ip", "route", "replace", "default", "dev", "uk", "table", str(table)] in commands
    await store.close()


def test_render_apply_script_is_idempotent_shell():
    from agent.support.peer_egress import render_apply_script

    table = table_id_for_interface("eth1")
    script = render_apply_script(
        [{"addr": "10.80.0.2", "cidr": "10.80.0.2/32", "iface": "eth1", "table": table}]
    )
    assert script.startswith("#!/bin/sh")
    assert "ip_forward=1" in script
    assert f"lookup {table}" in script
    assert 'oifname "eth1"' in script
    assert "maxseg size set rt mtu" in script
    assert "while iptables -t nat -D POSTROUTING" in script
    assert "_iface_ready" in script
    assert "_soften_rp_filter" in script
    assert "netinja-egress-eth1" in script
    assert f'if _default_for_iface "eth1" {table}; then' in script
    assert "keeping existing rule" in script
    assert "sleep" not in script
    assert "flock -n 9" in script
    # Failure path must not tear down the lookup rule (region IP leak).
    else_idx = script.index("keeping existing rule")
    assert f'ip rule del from "10.80.0.2/32" lookup {table}' not in script[else_idx:]


@pytest.mark.asyncio
async def test_reconcile_prefers_nft_and_purges_iptables_masq(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        if args[:2] == ["nft", "-j"] and "postrouting" in args:
            return _Result(
                stdout=json.dumps(
                    {
                        "nftables": [
                            {
                                "rule": {
                                    "expr": [
                                        {"match": {"left": {"meta": {"key": "oifname"}}, "right": "deutch"}},
                                        {"masquerade": None},
                                    ]
                                }
                            }
                        ]
                    }
                )
            )
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)

    result = await reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "deutch", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert result.get("nat_rebuilt") is True
    assert any(cmd[:1] == ["nft"] and "masquerade" in cmd for cmd in commands)
    # Must purge duplicate iptables MASQUERADE when nft owns NAT.
    assert any(cmd[:1] == ["iptables"] and "-D" in cmd and "MASQUERADE" in cmd and "deutch" in cmd for cmd in commands)
    assert any(
        cmd[:1] == ["iptables-legacy"] and "-D" in cmd and "MASQUERADE" in cmd and "deutch" in cmd for cmd in commands
    )
    # Must NOT keep installing MASQUERADE on iptables while nft is healthy.
    assert not any(cmd[:1] == ["iptables"] and "-A" in cmd and "MASQUERADE" in cmd for cmd in commands)
    await store.close()


def test_render_apply_script_includes_tunnel_forward_and_mss_rules():
    script = render_apply_script(
        [{"addr": "10.80.0.2", "cidr": "10.80.0.2/32", "iface": "eth1", "table": 12345}],
        ["wg0"],
    )
    assert '_soften_rp_filter "wg0"' in script
    assert 'iifname "wg0"' in script
    assert "tunnel-wg0-mss" in script
    assert "tunnel-wg0-in" in script
    assert "tunnel-wg0-out" in script
    # iptables / legacy fallbacks must also cover tunnel FORWARD (not only nft).
    assert 'iptables -C FORWARD -i "wg0"' in script
    assert 'iptables-legacy -C FORWARD -i "wg0"' in script
    assert "tunnel-wg0-in" in script


@pytest.mark.asyncio
async def test_repair_peer_egress_force_reconciles(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    await store.open()
    await store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg0",
            "peers": [
                {
                    "address": "10.90.68.1",
                    "exit_interface": "deutch",
                    "is_enabled": True,
                }
            ],
        },
    )
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "rule", "add"]:
            return _Result()
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        if args[:1] == ["nft"]:
            return _Result(returncode=1, stderr="no")
        return _Result()

    monkeypatch.setattr(
        "agent.support.peer_egress.shutil.which",
        lambda cmd: None if cmd == "nft" else f"/usr/sbin/{cmd}",
    )
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        _stub_peer_egress_unit,
    )
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", _stub_true)
    monkeypatch.setattr("agent.support.peer_egress._iface_exists", _stub_true)
    monkeypatch.setattr("agent.support.peer_egress._install_default_route", _stub_true)

    try:
        result = await repair_peer_egress(store, data_dir=tmp_path, runner=fake_run)
        assert result["ok"] is True
        assert "wireguard" in result["cores"]
        assert result["cores"]["wireguard"].get("forced") is True
        assert result["cores"]["wireguard"].get("nat_rebuilt") is True
        script = (tmp_path / "peer-egress-apply.sh").read_text(encoding="utf-8")
        assert 'iptables -C FORWARD -i "wg0"' in script
        assert "tunnel-wg0-in" in script
    finally:
        await store.close()
