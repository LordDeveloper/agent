"""Peer drift is AllowedIPs / presence, never handshake or byte counters."""

from __future__ import annotations

import asyncio

from agent.drivers.wireguard import (
    WireGuardDriver,
    _allowed_ip_set,
    _dump_is_usable,
    _peer_kernel_drift,
)


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
