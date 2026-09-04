from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agent.logutil import get_logger
from agent.support.quota import enforce_driver_quotas

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry

log = get_logger("quota")


def enforce_all(registry: CoreRegistry) -> int:
    disabled = 0

    for core_key in registry.settings.cores():
        try:
            driver = registry.get(core_key)
            disabled += enforce_driver_quotas(driver)
        except Exception:
            log.exception("quota enforce failed core=%s", core_key)

    return disabled


async def quota_enforcer_loop(
    registry: CoreRegistry,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    interval = max(1.0, float(settings.quota_enforce_interval))
    log.info("quota enforcer started interval=%ss", interval)

    while not stop_event.is_set():
        try:
            count = enforce_all(registry)
            if count:
                log.warning("quota exceeded — disabled clients=%s", count)
        except Exception:
            log.exception("quota enforce cycle failed")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            continue

    log.info("quota enforcer stopped")
