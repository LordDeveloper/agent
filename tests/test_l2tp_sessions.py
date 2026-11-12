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


def test_collect_ppp_sessions_uses_one_ip_dump(monkeypatch):
    from agent.support import l2tp_diagnose

    calls: list[list[str]] = []

    async def fake_run(_runner, args, **_kwargs):
        calls.append(list(args))
        return {
            "ok": True,
            "stdout": json.dumps(
                [
                    {
                        "ifname": "ppp0",
                        "operstate": "UP",
                        "flags": ["UP"],
                        "addr_info": [{"local": "10.8.128.1", "peer": "10.8.128.10"}],
                    }
                ]
            ),
            "stderr": "",
        }

    monkeypatch.setattr(l2tp_diagnose, "_ppp_iface_names", lambda: ["ppp0"])
    monkeypatch.setattr(l2tp_diagnose, "_run_cmd", fake_run)
    sessions = asyncio.run(_collect_ppp_sessions())
    assert calls == [["ip", "-j", "addr", "show"]]
    assert sessions["10.8.128.10"]["interface"] == "ppp0"

    calls.clear()
    monkeypatch.setattr(l2tp_diagnose, "_ppp_iface_names", lambda: [])
    idle = asyncio.run(_collect_ppp_sessions())
    assert calls == []
    assert idle == {}


def test_l2tp_usage_snapshot_reads_live_counters_without_rewriting_documents():
    from agent.drivers.l2tp import L2tpDriver

    class Fake:
        key = "l2tp"
        writes = 0
        synced = 0

        async def list_servers(self):
            return [
                {
                    "id": "1",
                    "name": "l2tp",
                    "users": [
                        {
                            "id": "user-1",
                            "email": "a@b.c",
                            "enable": True,
                            "address": "10.8.128.10",
                            "incoming": 9_000,
                            "outgoing": 8_000,
                        },
                        {
                            "id": "user-2",
                            "email": "linked@b.c",
                            "enable": True,
                            "address": "10.8.128.11",
                            "linked_peer_id": "peer-1",
                            "incoming": 50,
                        },
                    ],
                }
            ]

        async def _collect_ppp_sessions(self):
            return {"10.8.128.10": {"incoming": 100, "outgoing": 40, "is_up": True}}

        async def sync_user_stats(self):
            self.synced += 1

        async def put_doc(self, *_args, **_kwargs):
            self.writes += 1

        def _connected_unix(self, _user):
            return None

    fake = Fake()
    snapshot = asyncio.run(L2tpDriver.usage_snapshot(fake))
    assert fake.writes == 0
    assert fake.synced == 0
    clients = {client.id: client for client in snapshot.inbounds[0].clients}
    assert clients["user-1"].incoming == 100
    assert clients["user-1"].billing_key is None
    companion = clients["user-2"]
    assert companion.billing_key == "peer-1"
    assert companion.billing_core == "wireguard"
