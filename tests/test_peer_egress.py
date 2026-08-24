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
    assert ["ip", "route", "replace", "default", "dev", "eth1", "table", str(table)] in commands
    script = tmp_path / "peer-egress-apply.sh"
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert f'lookup {table}' in text
    assert 'dev "eth1"' in text

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
    assert 'oifname "eth1"' in script or ' -o "eth1"' in script
