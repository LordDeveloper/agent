from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from agent.logutil import get_logger
from agent.traffic.service import TrafficService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry

log = get_logger("traffic.worker")


async def _prefetch_xray_snapshot(registry: CoreRegistry, settings: AgentSettings) -> tuple[Any, int] | None:
    """Load xray usage once per cycle; merged sampling reuses it (avoids a second API pass)."""
    if "xray" not in settings.cores():
        return None
    driver = registry.get("xray")
    warm = getattr(driver, "warm_usage_cache", None)
    from agent.asyncutil import maybe_await

    started = time.monotonic()
    try:
        if callable(warm):
            await warm()
        else:
            await maybe_await(driver.usage_snapshot())
    except Exception:
        log.exception("xray usage prefetch failed")
        return None
    snapshot_ms = int((time.monotonic() - started) * 1000)
    cached = getattr(driver, "cached_usage_snapshot", lambda _a: None)
    max_age = getattr(driver, "_usage_cache_max_age", lambda: 30.0)()
    snapshot = cached(max_age) if callable(cached) else None
    if snapshot is None:
        try:
            snapshot = await maybe_await(driver.usage_snapshot())
        except Exception:
            log.exception("xray usage snapshot fallback failed")
            return None
        snapshot_ms = int((time.monotonic() - started) * 1000)
    return snapshot, snapshot_ms


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
                xray_prefetched = await _prefetch_xray_snapshot(registry, settings)
                stats = await traffic.sample_cores_blocking(registry, xray_prefetched=xray_prefetched)
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
