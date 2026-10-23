import asyncio
import json
from types import SimpleNamespace

from agent.support.l2tp_diagnose import _collect_ppp_sessions


def test_collect_ppp_sessions_awaits_runner_and_maps_peer_ip():
    payload = [
        {
            "ifname": "ppp0",
            "operstate": "UNKNOWN",
            "flags": ["UP", "POINTOPOINT"],
            "addr_info": [{"local": "10.8.128.1", "peer": "10.8.128.10", "family": "inet"}],
        }
    ]

    def runner(args, **_kwargs):
        assert args[:3] == ["ip", "-j", "addr"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    sessions = asyncio.run(_collect_ppp_sessions(runner))
    assert "10.8.128.10" in sessions
    assert sessions["10.8.128.10"]["is_up"] is True
    assert sessions["10.8.128.10"]["interface"] == "ppp0"


def test_collect_ppp_sessions_is_awaitable():
    assert asyncio.iscoroutinefunction(_collect_ppp_sessions)
