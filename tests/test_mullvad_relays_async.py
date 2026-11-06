"""GET /mullvad/locations/{country}/relays returns the list before pings finish."""

import asyncio
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient

from agent.main import create_app
from agent.support.mullvad import MullvadService


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


def test_relay_list_returns_before_the_pings_finish(tmp_path: Path, monkeypatch):
    async def country_relays(self, country_code, *, ping=False, on_row=None):
        if ping:
            await asyncio.sleep(0.6)
            if on_row is not None:
                on_row({"hostname": "de-ber-wg-001", "ping_ms": 4, "measured": True})
            return {
                "country_code": "de",
                "relays": [{"hostname": "de-ber-wg-001", "ping_ms": 4, "measured": True}],
            }
        return {
            "country_code": "de",
            "iface": "de",
            "bound": False,
            "current_hostname": None,
            "current_fixed": False,
            "relay_metric": "ping",
            "relay_mode": "auto",
            "ping_via": "agent",
            "relays": [
                {"hostname": "de-fra-wg-001", "ping_ms": None},
                {"hostname": "de-ber-wg-001", "ping_ms": None},
            ],
        }

    monkeypatch.setattr(MullvadService, "country_relays", country_relays)

    _clear_env()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18444",
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
            accepted = client.get(
                "/api/v1/mullvad/locations/de/relays?ping=1",
                headers=headers,
            )
            assert accepted.status_code == 200, accepted.text
            body = accepted.json()
            assert time.perf_counter() - started < 0.4
            assert body["success"] is True
            assert body["ping_status"] == "running"
            assert body["ping_id"]
            assert [row["hostname"] for row in body["relays"]] == ["de-fra-wg-001", "de-ber-wg-001"]
            assert all(row["ping_ms"] is None for row in body["relays"])

            finished = None
            deadline = time.perf_counter() + 3
            while time.perf_counter() < deadline:
                polled = client.get(
                    f"/api/v1/mullvad/locations/de/relays/ping/{body['ping_id']}",
                    headers=headers,
                )
                assert polled.status_code == 200, polled.text
                finished = polled.json()
                if finished["status"] == "done":
                    break
                time.sleep(0.05)
            assert finished is not None
            assert finished["status"] == "done"
            assert finished["relays"][0]["hostname"] == "de-ber-wg-001"
            assert finished["relays"][0]["ping_ms"] == 4
    finally:
        _clear_env()
