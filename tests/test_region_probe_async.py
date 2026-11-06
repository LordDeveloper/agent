"""POST /network/nodes/probe must answer before the probes run."""

import asyncio
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient

import agent.drivers.xray  # noqa: F401 — import before the timed request
import agent.support.node_probe  # noqa: F401
from agent.main import create_app


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(("LISTEN", "AUTH_", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "XRAY_", "ENV_FILE")) or key in {
            "LISTEN",
            "DATA_DIR",
            "DB_PATH",
            "ENABLED_CORES",
            "ENV_FILE",
        }:
            os.environ.pop(key, None)


def test_region_probe_returns_before_the_probes_finish(tmp_path: Path, monkeypatch):
    async def slow_probe(nodes, outbounds=None, *, runner=None):
        await asyncio.sleep(0.6)
        node_id = nodes[0]["id"]
        return {
            "ok": True,
            "nodes": [{"id": node_id, "ok": True, "message": "ok", "latency_ms": 12}],
            "summary": {"total": 1, "passed": 1, "failed": 0},
        }

    async def no_outbounds(_registry):
        return []

    monkeypatch.setattr("agent.support.node_probe.probe_region_nodes", slow_probe)
    monkeypatch.setattr("agent.api.network._load_probe_outbounds", no_outbounds)

    _clear_env()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data.as_posix()}",
                "ENABLED_CORES=xray",
                "",
            ]
        ),
        encoding="utf-8",
    )
    headers = {"Authorization": "Bearer dev-token"}
    try:
        with TestClient(create_app(str(env))) as client:
            started = time.perf_counter()
            accepted = client.post(
                "/api/v1/network/nodes/probe",
                headers=headers,
                json={"nodes": [{"id": 7, "exit_interface": "tr0"}], "fallback": False},
            )
            assert accepted.status_code == 200, accepted.text
            body = accepted.json()
            # The body is the accept payload. Probe rows arrive on the poll.
            assert body["status"] == "running"
            assert body["success"] is True
            assert "nodes" not in body
            assert time.perf_counter() - started < 0.4
            probe_id = body["probe_id"]

            finished = None
            deadline = time.perf_counter() + 3
            while time.perf_counter() < deadline:
                polled = client.get(f"/api/v1/network/nodes/probe/{probe_id}", headers=headers)
                assert polled.status_code == 200, polled.text
                finished = polled.json()
                if finished["status"] == "done":
                    break
                time.sleep(0.05)
            assert finished is not None
            assert finished["status"] == "done"
            assert finished["nodes"][0]["id"] == 7
            assert finished["nodes"][0]["ok"] is True
    finally:
        _clear_env()
