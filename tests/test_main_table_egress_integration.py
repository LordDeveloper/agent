"""Handshake and IPv4 round trip for a non-region WireGuard peer.

The agent test discovers the uplink from the namespace routing table. Interface
names and addresses are allocated by the test and are not product constants.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid

import pytest

from agent.db import Store
from agent.support.peer_egress import reconcile_core_egress
from agent.support.process import execute


def _need_root_netns() -> None:
    if os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0:
        pytest.skip("needs a root Linux network namespace")
    for tool in ("ip", "wg", "nft", "ping", "sysctl"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is required")


def _sh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(list(args), text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise AssertionError(f"{args}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


def _key() -> str:
    return subprocess.check_output(["wg", "genkey"], text=True).strip()


def _pub(private: str) -> str:
    return subprocess.check_output(["wg", "pubkey"], input=private + "\n", text=True).strip()


@pytest.mark.asyncio
async def test_non_region_peer_handshake_and_ipv4_round_trip(tmp_path, monkeypatch):
    _need_root_netns()
    token = uuid.uuid4().hex[:4]
    srv, cli, upl = f"njs{token}", f"njc{token}", f"nju{token}"
    server_client, client_server = f"sc{token}", f"cs{token}"
    server_uplink, uplink_server = f"su{token}", f"us{token}"
    tunnel = f"wg{token}"
    peer_ip = "10.66.0.2"
    uplink_ip = "198.51.100.1"
    namespaces = (srv, cli, upl)

    def runner(args, **_kwargs):
        return subprocess.run(
            ["ip", "netns", "exec", srv, *args],
            text=True,
            capture_output=True,
            check=False,
        )

    async def forward(active, cache=None):
        for key in (
            "net.ipv4.ip_forward=1",
            "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0",
        ):
            await execute(active, ["sysctl", "-w", key], check=False)

    async def persist_ok():
        return True

    async def unit(*_args, **_kwargs):
        return {"ok": True, "skipped": True, "started": False}

    monkeypatch.setattr("agent.support.peer_egress._ensure_ip_forward", forward)
    monkeypatch.setattr("agent.support.peer_egress._persist_sysctl_forward", persist_ok)
    monkeypatch.setattr("agent.support.peer_egress.ensure_peer_egress_unit", unit)

    try:
        for name in namespaces:
            _sh("ip", "netns", "add", name)
            _sh("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")
        _sh("ip", "link", "add", server_client, "type", "veth", "peer", "name", client_server)
        _sh("ip", "link", "set", server_client, "netns", srv)
        _sh("ip", "link", "set", client_server, "netns", cli)
        _sh("ip", "link", "add", server_uplink, "type", "veth", "peer", "name", uplink_server)
        _sh("ip", "link", "set", server_uplink, "netns", srv)
        _sh("ip", "link", "set", uplink_server, "netns", upl)

        _sh("ip", "netns", "exec", srv, "ip", "addr", "add", "192.0.2.1/24", "dev", server_client)
        _sh("ip", "netns", "exec", srv, "ip", "link", "set", server_client, "up")
        _sh("ip", "netns", "exec", cli, "ip", "addr", "add", "192.0.2.2/24", "dev", client_server)
        _sh("ip", "netns", "exec", cli, "ip", "link", "set", client_server, "up")
        _sh("ip", "netns", "exec", srv, "ip", "addr", "add", "198.51.100.2/24", "dev", server_uplink)
        _sh("ip", "netns", "exec", srv, "ip", "link", "set", server_uplink, "up")
        _sh("ip", "netns", "exec", srv, "ip", "route", "add", "default", "via", uplink_ip)
        _sh("ip", "netns", "exec", upl, "ip", "addr", "add", f"{uplink_ip}/24", "dev", uplink_server)
        _sh("ip", "netns", "exec", upl, "ip", "link", "set", uplink_server, "up")
        for name in (srv, cli, upl):
            _sh("ip", "netns", "exec", name, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
            _sh("ip", "netns", "exec", name, "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
        _sh("ip", "netns", "exec", srv, "sysctl", "-w", "net.ipv4.ip_forward=1")

        server_private = _key()
        client_private = _key()
        server_key = tmp_path / "server.key"
        client_key = tmp_path / "client.key"
        server_key.write_text(server_private + "\n", encoding="utf-8")
        client_key.write_text(client_private + "\n", encoding="utf-8")
        server_public = _pub(server_private)
        client_public = _pub(client_private)

        _sh("ip", "netns", "exec", srv, "ip", "link", "add", tunnel, "type", "wireguard")
        _sh("ip", "netns", "exec", srv, "ip", "addr", "add", "10.66.0.1/24", "dev", tunnel)
        _sh("ip", "netns", "exec", srv, "wg", "set", tunnel, "listen-port", "51820", "private-key", str(server_key))
        _sh("ip", "netns", "exec", srv, "ip", "link", "set", tunnel, "up")
        _sh(
            "ip", "netns", "exec", srv, "wg", "set", tunnel,
            "peer", client_public, "allowed-ips", f"{peer_ip}/32",
        )
        _sh("ip", "netns", "exec", cli, "ip", "link", "add", tunnel, "type", "wireguard")
        _sh("ip", "netns", "exec", cli, "ip", "addr", "add", f"{peer_ip}/32", "dev", tunnel)
        _sh("ip", "netns", "exec", cli, "wg", "set", tunnel, "private-key", str(client_key))
        _sh("ip", "netns", "exec", cli, "ip", "link", "set", tunnel, "up")
        _sh(
            "ip", "netns", "exec", cli, "wg", "set", tunnel,
            "peer", server_public, "endpoint", "192.0.2.1:51820", "allowed-ips", "0.0.0.0/0",
        )
        _sh("ip", "netns", "exec", cli, "ip", "route", "add", "192.0.2.1/32", "dev", client_server)
        _sh("ip", "netns", "exec", cli, "ip", "route", "add", f"{uplink_ip}/32", "dev", tunnel)

        store = Store(tmp_path / "agent.db")
        await store.open()
        iface = {
            "id": 1,
            "name": tunnel,
            "peers": [{"address": peer_ip, "is_enabled": True, "public_key": client_public}],
        }
        await store.put_doc("wireguard", "interface", "1", iface)
        result = await reconcile_core_egress(store, "wireguard", [iface], runner=runner, data_dir=tmp_path)
        await store.close()
        assert result["ok"] is True
        assert result["rules"] == 0
        assert result["main_egress"] == [server_uplink]

        ping = _sh(
            "ip", "netns", "exec", cli, "ping", "-c", "1", "-W", "3", uplink_ip,
            check=False,
        )
        dump = _sh("ip", "netns", "exec", srv, "wg", "show", tunnel, "dump")
        peer_line = next((line for line in dump.stdout.splitlines()[1:] if client_public in line), "")
        handshake = peer_line.split("\t")[4] if peer_line.count("\t") >= 4 else "0"
        assert handshake not in {"", "0"}, dump.stdout
        assert ping.returncode == 0, f"stdout={ping.stdout}\nstderr={ping.stderr}\ndump={dump.stdout}"
    finally:
        for name in namespaces:
            subprocess.run(["ip", "netns", "del", name], check=False, capture_output=True)
