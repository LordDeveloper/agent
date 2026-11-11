"""Volume samples run on a fixed cadence and never overlap."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from agent.traffic.service import TrafficService
from agent.traffic_worker import traffic_worker_loop


def _empty_stats() -> dict[str, int]:
    return {"clients_seen": 0, "pending": 0, "initialized": 0, "regressed": 0}


async def test_second_sample_waits_until_the_lock_expires():
    traffic = TrafficService(None)  # type: ignore[arg-type]
    release = asyncio.Event()
    calls = 0

    async def slow(_registry):
        nonlocal calls
        calls += 1
        await release.wait()
        return _empty_stats()

    traffic.sample_all = slow  # type: ignore[method-assign]

    started = await traffic.sample_unless_overlapping(None, lock_seconds=0.05)  # type: ignore[arg-type]
    await asyncio.sleep(0)
    assert started == {"started": 1}
    assert calls == 1

    skipped = await traffic.sample_unless_overlapping(None, lock_seconds=120)  # type: ignore[arg-type]
    assert skipped is None
    assert calls == 1

    await asyncio.sleep(0.06)
    replacement = await traffic.sample_unless_overlapping(None, lock_seconds=0.05)  # type: ignore[arg-type]
    await asyncio.sleep(0)
    assert replacement == {"started": 1}
    assert calls == 2

    release.set()
    flight = traffic._sample_flight
    assert flight is not None
    assert await flight == _empty_stats()


async def test_finished_sample_does_not_block_the_next_cycle():
    traffic = TrafficService(None)  # type: ignore[arg-type]
    calls = 0

    async def once(_registry):
        nonlocal calls
        calls += 1
        return _empty_stats()

    traffic.sample_all = once  # type: ignore[method-assign]

    first = await traffic.sample_unless_overlapping(None, lock_seconds=120)  # type: ignore[arg-type]
    flight = traffic._sample_flight
    assert flight is not None
    await flight
    second = await traffic.sample_unless_overlapping(None, lock_seconds=120)  # type: ignore[arg-type]
    await asyncio.sleep(0)

    assert first == {"started": 1}
    assert second == {"started": 1}
    assert calls == 2


async def test_worker_runs_blocking_samples_on_interval():
    calls: list[float] = []

    class Traffic:
        def cancel_inflight_sample(self) -> None:
            calls.append(-1.0)

        async def sample_cores_blocking(self, _registry):
            calls.append(1.0)
            return {"clients_seen": 0, "pending": 0, "initialized": 0, "regressed": 0}

    settings = SimpleNamespace(traffic_sample_interval=1, cores=lambda: [])
    stop = asyncio.Event()
    task = asyncio.create_task(
        traffic_worker_loop(None, Traffic(), settings, stop)  # type: ignore[arg-type]
    )
    await asyncio.sleep(2.15)
    stop.set()
    await task

    samples = [value for value in calls if value > 0]
    assert len(samples) >= 2
    assert calls[-1] == -1.0
