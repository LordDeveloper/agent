"""Sync entry points must consume coroutines, and bulk baselines stay one-shot."""

import json
from types import SimpleNamespace

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
