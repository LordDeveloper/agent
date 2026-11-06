"""Core reads must answer or fail. A timeout is not an empty user list."""

import asyncio
from types import SimpleNamespace

import pytest

from agent.asyncutil import (
    READ_BUDGET_SECONDS,
    is_upstream_failure,
    panel_read_path,
    read_deadline,
    short_read_path,
)
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError
from agent.models import UsageSnapshotModel
from agent.registry import CoreRegistry


def test_short_read_paths_cover_every_stats_and_health_route():
    assert short_read_path("GET", "/api/v1/stats/live")
    assert short_read_path("GET", "/api/v1/stats/online/ips")
    assert short_read_path("GET", "/health")
    assert short_read_path("GET", "/cores/xray/health")
    assert short_read_path("GET", "/api/v1/wireguard/diagnose")
    assert short_read_path("GET", "/api/v1/mullvad/locations")
    assert not short_read_path("POST", "/api/v1/stats/clients/traffic/pending/ack")
    assert not short_read_path("GET", "/api/v1/xray/inbounds/1")


def test_panel_reads_are_the_routes_that_must_answer_quickly():
    assert panel_read_path("GET", "/health")
    assert panel_read_path("GET", "/api/v1/stats/clients/traffic/pending")
    assert panel_read_path("GET", "/api/v1/mullvad/locations")
    assert not panel_read_path("GET", "/api/v1/mullvad/locations/se/relays")
    assert not panel_read_path("POST", "/api/v1/stats/clients/traffic/pending/ack")


def test_upstream_failure_is_not_an_empty_result():
    assert is_upstream_failure(AgentError("UPSTREAM_TIMEOUT", "timed out", 503))
    assert is_upstream_failure(asyncio.TimeoutError())
    assert not is_upstream_failure(AgentError("CONFIG_NOT_FOUND", "missing", 404))


def test_read_budget_is_within_panel_client_timeouts():
    # Laravel HttpClient defaults to ~15s; stay below multi-second dead air but
    # above trivially fast paths so cores get a fair slice.
    assert 4.0 <= READ_BUDGET_SECONDS <= 20.0


def _driver() -> XrayDriver:
    driver = XrayDriver.__new__(XrayDriver)
    driver.settings = SimpleNamespace(traffic_sample_interval=30)
    driver._usage_gate = None
    driver._usage_flight = None
    driver._usage_waiters = 0
    driver._usage_cache = None
    return driver


@pytest.mark.asyncio
async def test_usage_snapshot_reuses_a_fresh_sample():
    driver = _driver()
    calls = 0

    async def load():
        nonlocal calls
        calls += 1
        return UsageSnapshotModel(inbounds=[])

    driver._build_usage_snapshot = load
    first = await driver.usage_snapshot()
    second = await driver.usage_snapshot()
    assert first is second
    assert calls == 1


@pytest.mark.asyncio
async def test_cancelling_the_only_waiter_cancels_the_snapshot():
    driver = _driver()
    started = asyncio.Event()

    async def load():
        started.set()
        await asyncio.sleep(30)
        return UsageSnapshotModel(inbounds=[])

    driver._build_usage_snapshot = load
    task = asyncio.create_task(driver.usage_snapshot())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert driver._usage_flight is None


@pytest.mark.asyncio
async def test_online_ip_timeout_is_not_an_empty_map():
    registry = CoreRegistry.__new__(CoreRegistry)
    registry.settings = SimpleNamespace(cores=lambda: ["xray", "wireguard"])
    registry._read_cache = {}
    registry._read_flights = {}
    registry._read_ttl = 3.0

    class Hung:
        key = "xray"

        async def online_ips_map(self):
            raise AgentError("UPSTREAM_TIMEOUT", "xray timed out", 503)

    class Idle:
        key = "wireguard"

        async def online_ips_map(self):
            return {}

    registry._drivers = {"xray": Hung(), "wireguard": Idle()}
    users, unavailable = await registry.online_ips_report()
    assert unavailable == ["xray"]
    assert "xray" not in users
    assert users["wireguard"] == {}


@pytest.mark.asyncio
async def test_iplist_fallback_deadline_is_an_error(monkeypatch):
    driver = _driver()

    async def running():
        return True

    async def api_call(name, *args, **kwargs):
        if name == "online_all":
            raise AgentError("CONFIG_NOT_FOUND", "missing", 404)
        if name == "online_users":
            return ["a@b"]
        await asyncio.sleep(30)
        return []

    async def aliases():
        return {}

    driver.running = running
    driver._api_call = api_call
    driver._client_email_aliases = aliases
    monkeypatch.setattr("agent.drivers.xray.read_deadline", read_deadline)
    token = read_deadline.set(0.05)
    try:
        with pytest.raises(AgentError) as caught:
            await driver.online_ips_map()
        assert caught.value.code == "UPSTREAM_TIMEOUT"
        assert caught.value.status == 503
    finally:
        read_deadline.reset(token)


@pytest.mark.asyncio
async def test_slow_panel_reads_return_json_within_the_deadline():
    """A stuck handler must not leave health or pending traffic with zero bytes."""
    import time

    from httpx import ASGITransport, AsyncClient

    from agent.http import AgentHttpMiddleware

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        await asyncio.sleep(5)
        body = b'{"success":true,"users":{"late":1}}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    wrapped = AgentHttpMiddleware(app, read_response_seconds=0.2, write_response_seconds=2.0)
    transport = ASGITransport(app=wrapped)
    async with AsyncClient(transport=transport, base_url="http://agent") as client:
        started = time.perf_counter()
        health, pending = await asyncio.gather(
            client.get("/health"),
            client.get("/api/v1/stats/clients/traffic/pending"),
        )
        elapsed = time.perf_counter() - started

    assert elapsed < 1.0
    for response in (health, pending):
        assert response.status_code == 200
        assert response.content
        body = response.json()
        assert body["success"] is True
        assert body["stale"] is True
    assert pending.json()["users"] == {}


@pytest.mark.asyncio
async def test_read_deadline_replays_the_last_json_body():
    import time

    from httpx import ASGITransport, AsyncClient

    from agent.http import AgentHttpMiddleware

    gate = {"slow": False}

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        if gate["slow"]:
            await asyncio.sleep(5)
        body = b'{"success":true,"users":{"node":{"uplink":4}}}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    wrapped = AgentHttpMiddleware(app, read_response_seconds=0.2, write_response_seconds=2.0)
    transport = ASGITransport(app=wrapped)
    async with AsyncClient(transport=transport, base_url="http://agent") as client:
        fresh = await client.get("/api/v1/stats/clients/traffic/pending")
        assert fresh.status_code == 200
        assert fresh.json()["users"]["node"]["uplink"] == 4
        assert "stale" not in fresh.json()
        gate["slow"] = True
        started = time.perf_counter()
        stale = await client.get("/api/v1/stats/clients/traffic/pending")
        elapsed = time.perf_counter() - started

    assert elapsed < 1.0
    assert stale.status_code == 200
    assert stale.content
    assert stale.json()["stale"] is True
    assert stale.json()["users"]["node"]["uplink"] == 4


@pytest.mark.asyncio
async def test_write_deadline_returns_a_json_body():
    from httpx import ASGITransport, AsyncClient

    from agent.http import AgentHttpMiddleware

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        await asyncio.sleep(5)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    wrapped = AgentHttpMiddleware(app, read_response_seconds=0.2, write_response_seconds=0.2)
    transport = ASGITransport(app=wrapped)
    async with AsyncClient(transport=transport, base_url="http://agent") as client:
        response = await client.post("/api/v1/cores/xray/inbounds", json={"name": "x"})

    assert response.status_code == 504
    assert response.content
    assert response.json()["error"]["code"] == "READ_DEADLINE"


@pytest.mark.asyncio
async def test_cached_mullvad_locations_do_not_fetch(tmp_path):
    from agent.db import Store
    from agent.support.mullvad import _CACHE, MullvadService

    _CACHE["rows"] = []
    _CACHE["at"] = 0.0
    store = Store(tmp_path / "agent.db")
    await store.open()
    try:
        async def fetch():
            raise AssertionError("mullvad network")

        service = MullvadService(store, fetch=fetch)
        empty = await service.locations(cached=True, ping=False)
        assert empty["locations"] == []
        assert empty["stale"] is True

        await service.persist_catalog(
            [
                {
                    "country_code": "se",
                    "country_name": "Sweden",
                    "active": True,
                    "city_code": "sto",
                    "city_name": "Stockholm",
                }
            ]
        )
        listed = await service.locations(cached=True, ping=False)
        assert listed.get("stale") is not True
        assert any(row["country_code"] == "se" for row in listed["locations"])
    finally:
        _CACHE["rows"] = []
        _CACHE["at"] = 0.0
        await store.close()
