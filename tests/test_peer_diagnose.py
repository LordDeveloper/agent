from __future__ import annotations

import json
import time
from types import SimpleNamespace

from agent.db import Store
from agent.support.peer_diagnose import (
    allowed_ips_cover_host,
    allowed_ips_lists_match,
    diagnose_peer_address,
    find_peers_by_address,
    normalize_peer_host,
)


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def _store_with_peer(tmp_path) -> Store:
    store = Store(tmp_path / "agent.db")
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg1",
            "listen_port": 51820,
            "subnet": "10.80.0.0/24",
            "public_key": "iface-pub",
            "peers": [
                {
                    "id": "peer-1",
                    "email": "user@test",
                    "address": "10.80.0.5",
                    "allowed_ips": "10.80.0.5/32",
                    "public_key": "peer-pub-key",
                    "exit_interface": "eth1",
                    "is_enabled": True,
                }
            ],
        },
    )
    return store


def test_normalize_peer_host():
    assert normalize_peer_host("10.80.0.5/32") == "10.80.0.5"
    assert normalize_peer_host("10.80.0.5") == "10.80.0.5"


def test_allowed_ips_cover_host_does_not_use_substring_match():
    assert allowed_ips_cover_host("10.90.68.15/32", "10.90.68.15") is True
    assert allowed_ips_cover_host("10.90.68.150/32", "10.90.68.15") is False
    assert allowed_ips_lists_match("10.90.68.15/32", "10.90.68.150/32", "10.90.68.15") is False


def test_find_peers_by_address(tmp_path):
    store = _store_with_peer(tmp_path)
    rows = find_peers_by_address(store, "wireguard", "10.80.0.5")
    assert len(rows) == 1
    assert rows[0]["peer"]["email"] == "user@test"


def test_diagnose_reports_missing_peer(tmp_path):
    store = Store(tmp_path / "empty.db")
    report = diagnose_peer_address(store, "wireguard", "10.80.0.99", runner=lambda *a, **k: _Result())
    assert report["found"] is False
    assert report["issues"][0]["code"] == "PEER_NOT_FOUND"


def test_diagnose_detects_routing_and_live_peer(tmp_path, monkeypatch):
    store = _store_with_peer(tmp_path)
    table = 12345

    def fake_dump(_iface: str):
        now = int(time.time())
        return {
            "peer-pub-key": {
                "public_key": "peer-pub-key",
                "allowed_ips": "10.80.0.5/32",
                "endpoint": "203.0.113.10:51820",
                "handshake_at": now - 30,
                "transfer_rx": 100,
                "transfer_tx": 200,
            }
        }

    def fake_runner(args, **kwargs):
        cmd = args[0] if args else ""
        if cmd == "ip" and len(args) >= 3 and args[1] == "-j" and args[2] == "rule":
            return _Result(stdout=json.dumps([{"src": "10.80.0.5", "table": table, "pref": 15001}]))
        if cmd == "ip" and args[1:4] == ["-4", "route", "show"]:
            return _Result(stdout="default via 10.0.0.1 dev eth1\n")
        if cmd == "ip" and args[1:3] == ["-j", "link"]:
            return _Result(
                stdout=json.dumps([{"ifname": "eth1", "operstate": "UP", "flags": ["UP", "LOWER_UP"]}])
            )
        if cmd == "ip" and args[1:3] == ["route", "get"]:
            return _Result(stdout="1.1.1.1 from 10.80.0.5 dev wg1 table main\n")
        if cmd == "nft":
            return _Result(stdout='oifname "eth1" masquerade')
        return _Result()

    monkeypatch.setattr(
        "agent.support.peer_diagnose.table_id_for_interface",
        lambda name: table if name == "eth1" else 999,
    )
    monkeypatch.setattr("agent.support.peer_diagnose._read_sysctl", lambda path: "1" if "ip_forward" in path else None)
    monkeypatch.setattr("agent.support.peer_diagnose.shutil.which", lambda cmd: "/usr/bin/nft" if cmd == "nft" else None)

    report = diagnose_peer_address(
        store,
        "wireguard",
        "10.80.0.5",
        runner=fake_runner,
        peer_dump_fn=fake_dump,
        interface_is_up_fn=lambda name: name == "wg1",
    )

    assert report["found"] is True
    assert report["summary"]["match_count"] == 1
    match = report["matches"][0]
    assert match["live"]["allowed_ips"] == "10.80.0.5/32"
    assert match["routing"]["exit_interface"] == "eth1"
    assert match["routing"]["nat"]["masquerade"] is True
    assert match["issue_counts"]["error"] == 0, match["issues"]


def test_diagnose_flags_missing_exit_and_live_peer(tmp_path, monkeypatch):
    store = _store_with_peer(tmp_path)
    iface = store.get_doc("wireguard", "interface", "1")
    iface["peers"][0].pop("exit_interface", None)
    store.put_doc("wireguard", "interface", "1", iface)

    monkeypatch.setattr("agent.support.peer_diagnose._read_sysctl", lambda path: "1")

    report = diagnose_peer_address(
        store,
        "wireguard",
        "10.80.0.5",
        runner=lambda *a, **k: _Result(),
        peer_dump_fn=lambda _n: {},
        interface_is_up_fn=lambda _n: True,
    )

    codes = {row["code"] for row in report["matches"][0]["issues"]}
    assert "PEER_NOT_IN_LIVE_WG" in codes
    assert "EXIT_INTERFACE_UNSET" in codes
    assert report["summary"]["healthy"] is False
