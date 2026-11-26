import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from agent.support import host_interfaces


def test_add_interface_address_is_idempotent_when_present():
    async def run():
        with patch.object(
            host_interfaces,
            "list_host_interfaces",
            return_value=[{"name": "eth0", "addresses": ["1.2.3.4/32"], "is_up": True}],
        ):
            return await host_interfaces.add_interface_address("eth0", "1.2.3.4", runner=object())

    result = asyncio.run(run())

    assert result["added"] is False
    assert result["already_present"] is True
    assert result["address"] == "1.2.3.4"


def test_add_interface_address_calls_ip_addr_add():
    calls = []

    async def fake_execute(_runner, args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stderr="")

    async def run():
        with patch.object(
            host_interfaces,
            "list_host_interfaces",
            return_value=[{"name": "eth0", "addresses": [], "is_up": True}],
        ), patch.object(host_interfaces, "execute", side_effect=fake_execute):
            return await host_interfaces.add_interface_address("eth0", "8.8.8.8", runner=object())

    result = asyncio.run(run())

    assert result["added"] is True
    assert calls == [["ip", "addr", "add", "8.8.8.8/32", "dev", "eth0"]]


def test_add_interface_address_rejects_private_or_bad_name():
    async def run():
        try:
            await host_interfaces.add_interface_address("eth0", "10.0.0.5", runner=object())
        except ValueError as exc:
            private = str(exc)
        else:
            private = ""

        try:
            await host_interfaces.add_interface_address("1bad", "1.1.1.1", runner=object())
        except ValueError as exc:
            bad_name = str(exc)
        else:
            bad_name = ""

        return private, bad_name

    private, bad_name = asyncio.run(run())
    assert "public" in private
    assert "invalid" in bad_name
