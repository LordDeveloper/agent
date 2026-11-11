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


async def _prewarm_xray_usage(registry: CoreRegistry, settings: AgentSettings) -> None:
    if "xray" not in settings.cores():
        return
    driver = registry.get("xray")
    warm = getattr(driver, "warm_usage_cache", None)
    if callable(warm):
        await warm()


async def traffic_worker_loop(
    registry: CoreRegistry,
    traffic: TrafficService,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    """Await one full sample cycle, then sleep so commits stay near ``traffic_sample_interval``."""
    interval = max(1.0, float(settings.traffic_sample_interval))
    log.info("traffic worker started interval=%ss", interval)

    try:
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                await _prewarm_xray_usage(registry, settings)
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
        traffic.cancel_inflight_sample()
        log.info("traffic worker stopped")
