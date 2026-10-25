"""Sync entry points must consume coroutines, and bulk baselines stay one-shot."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from agent.api.xray import get_inbound, list_inbounds
from agent.asyncutil import run_sync

from agent.cli import cmd_peer_diagnose
from agent.drivers.xray import XrayDriver


def test_peer_diagnose_awaits_driver(monkeypatch, capsys):
    class Driver:
        async def diagnose_address(self, address: str) -> dict:
            assert address == "10.80.0.5"
            return {
                "found": True,
                "summary": {"healthy": True, "issue_count": 0, "warning_count": 0},
                "matches": [],
            }

    class Registry:
        def get(self, _core: str) -> Driver:
            return Driver()

    class Runtime:
        registry = Registry()

        def close(self) -> None:
            return None

    monkeypatch.setattr("agent.cli.open_runtime", lambda _env: Runtime())
    code = cmd_peer_diagnose(
        SimpleNamespace(env_file=None, core="wireguard", address="10.80.0.5", json=True)
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["found"] is True
    assert payload["summary"]["healthy"] is True


def test_sync_preferred_client_dns_does_not_nest_run_sync(monkeypatch):
    from agent.dns_leak import sync_preferred_client_dns

    def explode(*_args, **_kwargs):
        raise AssertionError("run_sync must not run while the event loop is active")

    monkeypatch.setattr("agent.dns_leak.run_sync", explode)

    async def on_loop() -> list[str]:
        return sync_preferred_client_dns()

    assert asyncio.run(on_loop())


def test_run_sync_does_not_block_a_running_loop():
    async def sample() -> str:
        return "ok"

    async def on_loop() -> None:
        run_sync(sample())

    with pytest.raises(RuntimeError, match="running event loop"):
        asyncio.run(on_loop())


def test_stamp_live_baseline_uses_grouped_counters():
    client = {"email": "a@b", "id": "node-1", "_incoming": 0, "_outgoing": 0}
    XrayDriver._stamp_live_baseline(
        client,
        {"a@b": {"downlink": 15, "uplink": 4}},
    )
    assert client["_incoming"] == 15
    assert client["_outgoing"] == 4


def test_stamp_live_baseline_keeps_nonzero_history():
    client = {"email": "a@b", "id": "node-1", "_incoming": 9, "_outgoing": 3}
    XrayDriver._stamp_live_baseline(
        client,
        {"a@b": {"downlink": 100, "uplink": 100}},
    )
    assert client["_incoming"] == 9
    assert client["_outgoing"] == 3


class _PresentingXray:
    async def list_inbounds(self) -> list[dict]:
        return [{"id": 3, "tag": "inbound-3"}]

    async def get_inbound(self, inbound_id: str, *, include_clients: bool = True) -> dict:
        return {"id": inbound_id, "tag": f"inbound-{inbound_id}"}

    async def present_inbounds(self, inbounds: list[dict]) -> list[dict]:
        for row in inbounds:
            row["presented"] = True
        return inbounds


async def test_inbound_gets_await_present_inbounds():
    listed = await list_inbounds(_PresentingXray())
    assert listed["inbounds"][0]["presented"] is True

    one = await get_inbound("9", include_clients=True, xray=_PresentingXray())
    assert one["inbound"]["id"] == "9"
    assert one["inbound"]["presented"] is True
