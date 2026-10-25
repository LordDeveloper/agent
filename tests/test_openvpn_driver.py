import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent.audit import AuditLog
from tests.conftest import open_store
from agent.drivers.openvpn import OpenVpnDriver
from agent.support.openvpn_config import (
    parse_status_v2,
    render_ccd_file,
    render_client_ovpn,
    render_passwd,
    render_server_conf,
)
from agent.support.openvpn_ip import (
    assert_openvpn_address,
    next_openvpn_ip,
    normalize_openvpn_subnet,
    openvpn_gateway,
)
from agent.support.peer_egress import openvpn_servers_as_interfaces


class FakeProc(SimpleNamespace):
    pass


def _settings(tmp_path: Path):
    from agent.config import AgentSettings

    return AgentSettings(
        data_dir=str(tmp_path / "data"),
        openvpn_config_dir=str(tmp_path / "ovpn"),
        enabled_cores="openvpn",
    )


async def _async_none(*_args, **_kwargs):
    return None


def _driver(tmp_path: Path) -> OpenVpnDriver:
    store = open_store(tmp_path / "agent.db")
    settings = _settings(tmp_path)
    audit = AuditLog(store)
    drv = OpenVpnDriver(settings, audit, store)

    drv._apply_all_configs = _async_none  # type: ignore[method-assign]
    drv._ensure_services = _async_none  # type: ignore[method-assign]
    drv._sync_peer_egress = _async_none  # type: ignore[method-assign]
    drv._apply_server_auth_files = _async_none  # type: ignore[method-assign]
    return drv


def test_normalize_openvpn_subnet_and_gateway():
    assert normalize_openvpn_subnet("10.8.0.0/24") == "10.8.0.0/24"
    assert openvpn_gateway("10.8.0.0/24") == "10.8.0.1"
    assert assert_openvpn_address("10.8.0.0/24", "10.8.0.10") == "10.8.0.10"
    assert next_openvpn_ip("10.8.0.0/24", {"10.8.0.2"}) == "10.8.0.3"


def test_render_passwd_and_ccd():
    servers = [
        {
            "id": 1,
            "users": [
                {"username": "alice", "password": "secret", "address": "10.8.0.2", "is_enabled": True},
                {"username": "bob", "password": "x", "address": "10.8.0.3", "is_enabled": False},
            ],
        }
    ]
    text = render_passwd(servers)
    assert "alice secret" in text
    assert "bob" not in text
    ccd = render_ccd_file(servers[0]["users"][0], subnet="10.8.0.0/24")
    assert "ifconfig-push 10.8.0.2" in ccd


def test_render_server_conf_and_ovpn():
    server = {
        "id": 1,
        "name": "openvpn-1",
        "listen_port": 1194,
        "proto": "udp",
        "subnet": "10.8.0.0/24",
        "tun_dev": "ovpn1",
    }
    conf = render_server_conf(server, server_dir="/etc/openvpn/server/openvpn-1", auth_script="/auth.py")
    assert "dev ovpn1" in conf
    assert "auth-user-pass-verify" in conf
    assert "via-file" in conf
    ovpn = render_client_ovpn(
        server,
        {"username": "alice", "password": "pw", "address": "10.8.0.2"},
        endpoint_host="vpn.example.com",
        ca_crt="-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----",
        tls_crypt="STATIC",
    )
    assert "remote vpn.example.com 1194" in ovpn
    assert "<ca>" in ovpn
    assert "<tls-crypt>" in ovpn
    assert "\nauth-user-pass\n" in ovpn
    assert "# username: alice" in ovpn
    assert "# password: pw" in ovpn


def test_parse_status_v2():
    text = """
TITLE,OpenVPN
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since
CLIENT_LIST,alice,1.2.3.4:1194,10.8.0.2,100,200,Thu
HEADER,ROUTING_TABLE
END
"""
    rows = parse_status_v2(text)
    assert len(rows) == 1
    assert rows[0]["username"] == "alice"
    assert rows[0]["bytes_received"] == 100
    assert rows[0]["bytes_sent"] == 200


def test_parse_status_v2_with_virtual_ipv6_column():
    text = """
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
CLIENT_LIST,alice,1.2.3.4:1194,10.8.0.2,,10485760,31457280,2026-09-25 12:00:00,1,alice,0,0,AES-256-GCM
"""
    rows = parse_status_v2(text)
    assert rows[0]["username"] == "alice"
    assert rows[0]["virtual_address"] == "10.8.0.2"
    assert rows[0]["bytes_received"] == 10_485_760
    assert rows[0]["bytes_sent"] == 31_457_280


def test_openvpn_crud_users(tmp_path: Path, monkeypatch):
    async def _noop_egress(*_a, **_k):
        return {"ok": True}

    monkeypatch.setattr(
        "agent.support.peer_egress.reconcile_core_egress",
        _noop_egress,
    )
    drv = _driver(tmp_path)
    drv._pki_texts = lambda _server: {  # type: ignore[method-assign]
        "ca_crt": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
        "tls_crypt": "STATICKEY",
    }
    async def scenario():
        server = await drv.create_server({"name": "main", "subnet": "10.8.1.0/24", "public_host": "1.2.3.4"})
        user = await drv.add_user(1, {"email": "u1@test", "exit_interface": "us"})
        updated = await drv.update_user(1, user["id"], {"exit_interface": "de", "is_enabled": True})
        bundle = await drv.user_config_bundle(1, user["id"], endpoint_host="vpn.test")
        deleted = await drv.delete_user(1, user["id"])
        listed = await drv.list_servers()
        remaining = await drv.get_server(1)
        return server, user, updated, bundle, deleted, listed, remaining

    server, user, updated, bundle, deleted, listed, remaining = asyncio.run(scenario())
    assert server["id"] == 1
    assert server["gateway"] == "10.8.1.1"
    assert user["username"]
    assert user["address"].startswith("10.8.1.")
    assert user["exit_interface"] == "us"

    assert len(listed) == 1
    assert listed[0]["users"] == []

    assert updated["exit_interface"] == "de"
    assert updated["address"] == user["address"]
    assert bundle["type"] == "OpenVPN"
    assert "remote vpn.test" in bundle["ovpn"]
    assert "TEST" in bundle["ovpn"]
    assert deleted is True
    assert remaining["users"] == []


def test_openvpn_batch_users_commits_runtime_once(tmp_path: Path):
    drv = _driver(tmp_path)
    calls = {"auth": 0, "egress": 0}

    async def _count_auth(_server):
        calls["auth"] += 1

    async def _count_egress(drop_keys=None):
        calls["egress"] += 1

    drv._apply_server_auth_files = _count_auth  # type: ignore[method-assign]
    drv._sync_peer_egress = _count_egress  # type: ignore[method-assign]

    async def scenario():
        server = await drv.create_server({"name": "main", "subnet": "10.8.1.0/24"})
        before = dict(calls)
        result = await drv.batch_users(
            server["id"],
            [{"email": f"u{i}@test"} for i in range(6)],
        )
        return before, result

    before, result = asyncio.run(scenario())
    assert result["applied"] == 6
    assert result["failed"] == 0
    assert calls["auth"] == before["auth"] + 1
    assert calls["egress"] == before["egress"] + 1


def test_openvpn_servers_as_interfaces_for_egress():
    servers = [
        {
            "id": 2,
            "tun_dev": "ovpn2",
            "users": [
                {"address": "10.8.2.10", "exit_interface": "us", "is_enabled": True},
            ],
        }
    ]
    ifaces = openvpn_servers_as_interfaces(servers)
    assert ifaces[0]["name"] == "ovpn2"
    assert ifaces[0]["peers"][0]["address"] == "10.8.2.10"


@patch("agent.drivers.openvpn.ensure_server_pki", new_callable=lambda: __import__("unittest.mock").mock.AsyncMock)
def test_user_config_bundle_uses_pki(mock_pki, tmp_path: Path):
    mock_pki.return_value = {
        "ca_crt": "CA",
        "tls_crypt": "TC",
        "ca_key": "",
        "server_crt": "",
        "server_key": "",
        "dh_pem": "",
    }
    drv = _driver(tmp_path)

    async def scenario():
        await drv.create_server({"name": "main"})
        user = await drv.add_user(1, {"email": "a@b"})
        bundle = await drv.user_config_bundle(1, user["id"], endpoint_host="h")
        return bundle

    bundle = asyncio.run(scenario())
    assert "CA" in bundle["ovpn"]
    assert "TC" in bundle["ovpn"]
