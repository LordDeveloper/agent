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


async def test_worker_attempts_on_each_interval_with_the_overlap_lock():
    locks: list[float] = []

    class Traffic:
        def cancel_inflight_sample(self) -> None:
            locks.append(-1)

        async def sample_unless_overlapping(self, _registry, *, lock_seconds: float):
            locks.append(lock_seconds)
            return {"started": 1}

    settings = SimpleNamespace(traffic_sample_interval=1, traffic_sample_lock_seconds=120)
    stop = asyncio.Event()
    task = asyncio.create_task(
        traffic_worker_loop(None, Traffic(), settings, stop)  # type: ignore[arg-type]
    )
    await asyncio.sleep(2.15)
    stop.set()
    await task

    samples = [value for value in locks if value == 120]
    # Immediate attempt, then another each second. Three fits inside 2.15s.
    assert len(samples) >= 3
    assert locks[-1] == -1
