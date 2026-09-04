from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agent.logutil import get_logger
from agent.traffic.service import TrafficService

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
    interval = max(1.0, float(settings.traffic_sample_interval))
    log.info("traffic worker started interval=%ss", interval)

    while not stop_event.is_set():
        try:
            stats = traffic.sample_all(registry)
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

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            continue

    log.info("traffic worker stopped")
