from __future__ import annotations

import json
from types import SimpleNamespace

from agent.db import Store
from agent.support.host_interfaces import list_host_interfaces
from agent.support.peer_egress import (
    desired_rules_from_interfaces,
    reconcile_core_egress,
    table_id_for_interface,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


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


def test_list_host_interfaces_filters_loopback(monkeypatch):
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
    rows = list_host_interfaces(runner=fake_run)
    assert [row["name"] for row in rows] == ["eth1", "wg-de"]
    assert rows[0]["addresses"] == ["10.0.0.8/24"]
    assert rows[1]["link_type"] == "wireguard"


def test_reconcile_core_egress_applies_and_cleans(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1 proto dhcp metric 100\n")
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        lambda script_path, runner=None: {"ok": True, "skipped": True},
    )

    first = reconcile_core_egress(
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
    assert ["ip", "rule", "add", "from", "10.80.0.2/32", "lookup", str(table)] in commands
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

    # Stale SQLite state must not skip re-apply (reboot scenario).
    commands.clear()
    again = reconcile_core_egress(
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
    assert ["ip", "rule", "add", "from", "10.80.0.2/32", "lookup", str(table)] in commands

    commands.clear()
    second = reconcile_core_egress(
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
    store.close()


def test_reconcile_switches_exit_atomically(tmp_path, monkeypatch):
    """Server change: add new exit rule before deleting the old one."""
    store = Store(tmp_path / "agent.db")
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
        lambda script_path, runner=None: {"ok": True, "skipped": True},
    )

    poland = table_id_for_interface("poland")
    sweden = table_id_for_interface("sweden")

    first = reconcile_core_egress(
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
    switched = reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.72.174.10", "exit_interface": "sweden", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert switched["ok"] is True
    assert switched["switched"] == 1

    add_new = ["ip", "rule", "add", "from", "10.72.174.10/32", "lookup", str(sweden)]
    del_old = ["ip", "rule", "del", "from", "10.72.174.10/32", "lookup", str(poland)]
    assert add_new in commands
    assert del_old in commands
    assert commands.index(add_new) < commands.index(del_old)
    assert ["conntrack", "-D", "-s", "10.72.174.10"] in commands
    assert ("10.72.174.10/32", sweden) in live_rules
    assert ("10.72.174.10/32", poland) not in live_rules
    store.close()


def test_reconcile_skips_missing_exit_interface(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
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
        lambda script_path, runner=None: {"ok": True, "skipped": True},
    )

    table = table_id_for_interface("usa")
    result = reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "usa", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert result["rules"] == 0
    assert ["ip", "rule", "add", "from", "10.90.68.3/32", "lookup", str(table)] not in commands
    store.close()


def test_reconcile_uses_dev_only_when_exit_has_no_main_gateway(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
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
        lambda script_path, runner=None: {"ok": True, "skipped": True},
    )

    table = table_id_for_interface("uk")
    result = reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "uk", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert ["ip", "route", "replace", "default", "dev", "uk", "table", str(table)] in commands
    store.close()


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
    assert ' -o "eth1"' in script
    assert "iptables-legacy" in script
    assert "_iface_ready" in script
    assert "_soften_rp_filter" in script
    assert "netinja-egress-eth1" in script
    assert f'if _default_for_iface "eth1" {table}; then' in script


def test_reconcile_installs_masq_on_nft_and_iptables(tmp_path, monkeypatch):
    store = Store(tmp_path / "agent.db")
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        if args[:3] == ["ip", "-j", "rule"]:
            return _Result(stdout="[]")
        if args[:4] == ["ip", "-4", "route", "show"] and args[4:] == ["default"]:
            return _Result(stdout="")
        return _Result()

    monkeypatch.setattr("agent.support.peer_egress.shutil.which", lambda cmd: f"/usr/sbin/{cmd}")
    monkeypatch.setattr(
        "agent.support.peer_egress.ensure_peer_egress_unit",
        lambda script_path, runner=None: {"ok": True, "skipped": True},
    )

    result = reconcile_core_egress(
        store,
        "wireguard",
        [{"peers": [{"address": "10.90.68.3", "exit_interface": "deutch", "is_enabled": True}]}],
        runner=fake_run,
        data_dir=tmp_path,
    )
    assert result["ok"] is True
    assert any(cmd[:1] == ["nft"] and "masquerade" in cmd for cmd in commands)
    assert any(
        cmd[:1] == ["iptables"] and "-t" in cmd and "MASQUERADE" in cmd and "deutch" in cmd
        for cmd in commands
    )
    assert any(
        cmd[:1] == ["iptables-legacy"] and "MASQUERADE" in cmd and "deutch" in cmd
        for cmd in commands
    )
    store.close()
