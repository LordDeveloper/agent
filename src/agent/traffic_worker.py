from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agent.logutil import get_logger
from agent.traffic.service import DEFAULT_SAMPLE_LOCK_SECONDS, TrafficService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry

log = get_logger("traffic.worker")


async def traffic_worker_loop(
    registry: CoreRegistry,
    traffic: TrafficService,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    """Sample volume every ``traffic_sample_interval`` seconds.

    A cycle that is still running is left alone (no overlap). After
    ``traffic_sample_lock_seconds`` it is cancelled so a stuck core walk
    cannot block later samples.
    """
    interval = max(1.0, float(settings.traffic_sample_interval))
    lock_seconds = max(
        interval,
        float(getattr(settings, "traffic_sample_lock_seconds", DEFAULT_SAMPLE_LOCK_SECONDS) or DEFAULT_SAMPLE_LOCK_SECONDS),
    )
    log.info(
        "traffic worker started interval=%ss without_overlapping=%ss",
        interval,
        lock_seconds,
    )

    try:
        while not stop_event.is_set():
            try:
                await traffic.sample_unless_overlapping(registry, lock_seconds=lock_seconds)
            except Exception:
                log.exception("traffic sample cycle failed")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                continue
    finally:
        traffic.cancel_inflight_sample()
        log.info("traffic worker stopped")
