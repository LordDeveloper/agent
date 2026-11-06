"""Peer drift is AllowedIPs / presence, never handshake or byte counters."""

from __future__ import annotations

import asyncio

from copy import deepcopy

from agent.drivers.wireguard import (
    WireGuardDriver,
    _allowed_ip_set,
    _apply_dump_counters,
    _dump_is_usable,
    _peer_kernel_drift,
    parse_ipv4_routes,
    peer_route_gaps,
    repair_tunnel_routes,
)
from agent.support.interface_lifecycle import InterfaceLockRegistry


def _peer(public_key: str, allowed: str, *, enabled: bool = True, peer_id: str = "p1") -> dict:
    return {
        "id": peer_id,
        "public_key": public_key,
        "allowed_ips": allowed,
        "enable": enabled,
    }


def _iface(*peers: dict) -> dict:
    return {"id": "1", "name": "wg0", "peers": list(peers)}


def test_formatting_and_idle_counters_are_not_drift() -> None:
    iface = _iface(_peer("aaa", "10.0.0.2/32, 10.0.0.3/32"))
    dump = {
        "aaa": {
            "allowed_ips": "10.0.0.3/32,10.0.0.2/32",
            "handshake_at": 0,
            "incoming": 0,
            "outgoing": 0,
        }
    }
    assert _peer_kernel_drift(iface, dump) == []
    assert _allowed_ip_set("10.0.0.2") == _allowed_ip_set("10.0.0.2/32")


def test_missing_wrong_allowed_and_disabled_are_drift() -> None:
    iface = _iface(
        _peer("aaa", "10.0.0.2/32", peer_id="alive"),
        _peer("bbb", "10.0.0.3/32", peer_id="stale"),
        _peer("ccc", "10.0.0.4/32", enabled=False, peer_id="off"),
    )
    dump = {
        "bbb": {"allowed_ips": "10.9.9.9/32", "handshake_at": 999, "incoming": 50, "outgoing": 50},
        "ccc": {"allowed_ips": "10.0.0.4/32"},
    }
    reasons = {row["public_key"]: row["action"] for row in _peer_kernel_drift(iface, dump)}
    assert reasons == {"aaa": "add", "bbb": "reinstall", "ccc": "remove"}


def test_overlapping_desired_prefixes_are_not_reinstalled() -> None:
    iface = _iface(
        _peer("aaa", "10.0.0.2/32", peer_id="a"),
        _peer("bbb", "10.0.0.2/32", peer_id="b"),
    )
    dump = {
        "aaa": {"allowed_ips": "10.0.0.2/32"},
        "bbb": {"allowed_ips": "10.0.0.2/32"},
    }
    rows = _peer_kernel_drift(iface, dump)
    assert {row["action"] for row in rows} == {"skip"}
    assert {row["reason"] for row in rows} == {"allowed_ips_conflict"}


def test_empty_dump_is_not_every_peer_missing() -> None:
    iface = _iface(_peer("aaa", "10.0.0.2/32"))
    assert _dump_is_usable(iface, {}) is False
    assert _dump_is_usable({"peers": []}, {}) is True


def test_repair_leaves_matching_peers_untouched_and_reinstalls_one() -> None:
    class Fake:
        _repair_noted: set[tuple[str, str, str]] = set()

        def __init__(self) -> None:
            self.iface = _iface(
                _peer("aaa", "10.0.0.2/32", peer_id="healthy"),
                _peer("bbb", "10.0.0.3/32", peer_id="broken"),
            )
            self.dumps = [
                {
                    "aaa": {"allowed_ips": "10.0.0.2/32", "handshake_at": 10, "incoming": 5},
                    "bbb": {"allowed_ips": "10.8.8.8/32", "handshake_at": 10, "incoming": 9},
                },
                {
                    "aaa": {"allowed_ips": "10.0.0.2/32"},
                    "bbb": {"allowed_ips": "10.0.0.3/32"},
                },
            ]
            self.calls: list[list[list[str]]] = []

        def _cli_bin(self) -> str:
            return "wg"

        async def get_interface(self, _interface_id: str) -> dict:
            return self.iface

        async def _peer_dump(self, _name: str) -> dict:
            return self.dumps.pop(0)

        async def _wg_set_chunked(self, _name: str, groups: list[list[str]], *, per_peer: bool = False) -> bool:
            self.calls.append(groups)
            return True

        _log_peer_recovery = WireGuardDriver._log_peer_recovery
        _peer_add_argv = WireGuardDriver._peer_add_argv

    fake = Fake()
    ok = asyncio.run(WireGuardDriver._repair_kernel_peers(fake, fake.iface, hold_lock=False))
    assert ok is True
    assert len(fake.calls) == 2
    assert fake.calls[0] == [["peer", "bbb", "remove"]]
    assert fake.calls[1][0][:4] == ["peer", "bbb", "allowed-ips", "10.0.0.3/32"]
    assert all("aaa" not in group for group in fake.calls[0] + fake.calls[1])


def test_counter_merge_keeps_a_peer_added_after_the_snapshot() -> None:
    current = {
        "peers": [
            {
                "id": "a",
                "public_key": "aaa",
                "allowed_ips": "10.0.0.2/32",
                "address": "10.0.0.2",
                "enable": True,
                "incoming": 1,
                "outgoing": 1,
                "_raw_incoming": 1,
                "_raw_outgoing": 1,
            },
            {
                "id": "b",
                "public_key": "bbb",
                "allowed_ips": "10.0.0.9/32",
                "address": "10.0.0.9",
                "enable": True,
            },
        ]
    }
    changed = _apply_dump_counters(
        current,
        {"aaa": {"incoming": 5, "outgoing": 4, "handshake_at": 0, "endpoint": ""}},
    )
    assert changed is True
    assert [peer["id"] for peer in current["peers"]] == ["a", "b"]
    assert current["peers"][0]["allowed_ips"] == "10.0.0.2/32"
    assert current["peers"][0]["incoming"] == 5
    assert current["peers"][1]["allowed_ips"] == "10.0.0.9/32"


def test_sync_peer_stats_does_not_write_the_stale_peer_list() -> None:
    fresh = {
        "id": "1",
        "name": "wg0",
        "peers": [
            {
                "id": "a",
                "public_key": "aaa",
                "allowed_ips": "10.0.0.2/32",
                "address": "10.0.0.2",
                "enable": True,
                "incoming": 0,
                "outgoing": 0,
                "_raw_incoming": 0,
                "_raw_outgoing": 0,
            },
            {
                "id": "b",
                "public_key": "bbb",
                "allowed_ips": "10.0.0.9/32",
                "address": "10.0.0.9",
                "enable": True,
            },
        ],
    }

    class Fake:
        key = "wireguard"
        _kind = "interface"
        _repair_noted: set[tuple[str, str, str]] = set()

        def __init__(self) -> None:
            self._iface_locks = InterfaceLockRegistry()
            self.writes: list[dict] = []
            self.repaired: dict | None = None
            self.store = self

        async def list_interfaces(self) -> list[dict]:
            stale = deepcopy(fresh)
            stale["peers"] = [stale["peers"][0]]
            return [stale]

        async def get_interface(self, _interface_id: str) -> dict:
            return deepcopy(fresh)

        async def _peer_dump(self, _name: str) -> dict:
            return {"aaa": {"incoming": 8, "outgoing": 1, "handshake_at": 0, "endpoint": ""}}

        async def put_doc(self, _key: str, _kind: str, _doc_id: str, data: dict) -> None:
            self.writes.append(deepcopy(data))

        async def _repair_kernel_peers(self, iface: dict, *, hold_lock: bool = True) -> bool:
            self.repaired = deepcopy(iface)
            return True

        _log_peer_recovery = WireGuardDriver._log_peer_recovery
        _iface_lock_key = WireGuardDriver._iface_lock_key

    fake = Fake()
    asyncio.run(WireGuardDriver.sync_peer_stats(fake))
    assert fake.writes
    saved_ids = [peer["id"] for peer in fake.writes[-1]["peers"]]
    assert saved_ids == ["a", "b"]
    assert fake.writes[-1]["peers"][0]["allowed_ips"] == "10.0.0.2/32"
    assert fake.writes[-1]["peers"][0]["incoming"] == 8
    assert fake.writes[-1]["peers"][1]["allowed_ips"] == "10.0.0.9/32"
    assert fake.repaired is not None
    assert [peer["id"] for peer in fake.repaired["peers"]] == ["a", "b"]


def test_idle_peer_on_the_connected_route_is_not_repaired() -> None:
    routes = parse_ipv4_routes("10.80.0.0/16 dev wg0 proto kernel scope link src 10.80.0.1\n")
    peer = _peer("aaa", "10.80.0.2/32", peer_id="idle")
    peer["address"] = "10.80.0.2"
    peer["handshake_at"] = 0
    peer["incoming"] = 0
    peer["outgoing"] = 0
    iface = _iface(peer)
    iface["name"] = "wg0"
    assert peer_route_gaps(iface, routes) == []


def test_route_replace_touches_only_the_misrouted_peer() -> None:
    routes = {"text": "10.80.0.0/16 dev wg0 proto kernel scope link\n10.0.0.5 dev eth0 scope link\n"}

    class Runner:
        def __call__(self, args, **_kwargs):
            from types import SimpleNamespace

            if args == ["ip", "-4", "route", "show"]:
                return SimpleNamespace(returncode=0, stdout=routes["text"], stderr="")
            if args[:3] == ["ip", "route", "replace"]:
                self.replaced.append(list(args))
                host = args[3].split("/", 1)[0]
                kept = [
                    line
                    for line in routes["text"].splitlines()
                    if line and not line.startswith(host + " ")
                ]
                kept.append(f"{host} dev {args[5]} scope link")
                routes["text"] = "\n".join(kept) + "\n"
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(args)

    runner = Runner()
    runner.replaced = []
    healthy = _peer("aaa", "10.80.0.2/32", peer_id="healthy")
    healthy["address"] = "10.80.0.2"
    healthy["handshake_at"] = 10
    healthy["incoming"] = 0
    broken = _peer("bbb", "10.0.0.5/32", peer_id="broken")
    broken["address"] = "10.0.0.5"
    broken["handshake_at"] = 10
    broken["incoming"] = 20
    report = asyncio.run(
        repair_tunnel_routes(
            [{"name": "wg0", "peers": [healthy, broken]}],
            runner=runner,
        )
    )
    assert report["ok"] is True
    assert runner.replaced == [["ip", "route", "replace", "10.0.0.5/32", "dev", "wg0"]]
