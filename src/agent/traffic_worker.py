from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from agent.logutil import get_logger
from agent.traffic.service import TrafficService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry

log = get_logger("traffic.worker")


async def _usage_prewarm_loop(
    registry: CoreRegistry,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    """Keep xray stats cache warm so each sample reads counters without a cold API stall."""
    interval = max(1.0, float(settings.traffic_sample_interval))
    while not stop_event.is_set():
        try:
            for core_key in settings.cores():
                if core_key != "xray":
                    continue
                driver = registry.get("xray")
                warm = getattr(driver, "warm_usage_cache", None)
                if callable(warm):
                    await warm()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("usage prewarm failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            continue


async def traffic_worker_loop(
    registry: CoreRegistry,
    traffic: TrafficService,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    """Await one full sample cycle, then sleep so commits stay near ``traffic_sample_interval``."""
    interval = max(1.0, float(settings.traffic_sample_interval))
    log.info("traffic worker started interval=%ss", interval)

    prewarm = asyncio.create_task(_usage_prewarm_loop(registry, settings, stop_event))

    try:
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                stats = await traffic.sample_cores_blocking(registry)
                if stats.get("pending", 0) or stats.get("regressed", 0):
                    log.info(
                        "traffic sample clients=%s pending=%s initialized=%s regressed=%s",
                        stats.get("clients_seen", 0),
                        stats.get("pending", 0),
                        stats.get("initialized", 0),
                        stats.get("regressed", 0),
                    )
            except Exception:
                log.exception("traffic sample cycle failed")

            delay = max(0.0, interval - (time.monotonic() - started))
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=delay)
                break
            except asyncio.TimeoutError:
                continue
    finally:
        prewarm.cancel()
        await asyncio.gather(prewarm, return_exceptions=True)
        traffic.cancel_inflight_sample()
        log.info("traffic worker stopped")
