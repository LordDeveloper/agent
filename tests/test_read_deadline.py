"""Core reads must answer or fail. A timeout is not an empty user list."""

import asyncio
from types import SimpleNamespace

import pytest

from agent.asyncutil import READ_BUDGET_SECONDS, is_upstream_failure, read_deadline, short_read_path
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
    assert not short_read_path("POST", "/api/v1/stats/clients/traffic/pending/ack")
    assert not short_read_path("GET", "/api/v1/xray/inbounds/1")


def test_upstream_failure_is_not_an_empty_result():
    assert is_upstream_failure(AgentError("UPSTREAM_TIMEOUT", "timed out", 503))
    assert is_upstream_failure(asyncio.TimeoutError())
    assert not is_upstream_failure(AgentError("CONFIG_NOT_FOUND", "missing", 404))


def test_read_budget_is_shorter_than_the_panel_poll():
    assert READ_BUDGET_SECONDS <= 4.0


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
