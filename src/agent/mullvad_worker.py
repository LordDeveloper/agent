from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agent.logutil import get_logger
from agent.support.mullvad import MullvadService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.db import Store

log = get_logger("mullvad.worker")


async def mullvad_worker_loop(
    store: Store,
    settings: AgentSettings,
    stop_event: asyncio.Event,
) -> None:
    interval = max(15.0, float(getattr(settings, "mullvad_fallback_interval", 60.0) or 0))
    log.info("mullvad fallback worker started interval=%ss", interval)
    service = MullvadService(store, config_dir=settings.wireguard_config_dir)

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

        try:
            result = await asyncio.to_thread(service.fallback)
            changed = len(result.get("changed") or [])
            failed = len(result.get("failed") or [])
            if changed or failed:
                log.info("mullvad fallback changed=%s failed=%s", changed, failed)
        except Exception:
            log.exception("mullvad fallback cycle failed")

    log.info("mullvad fallback worker stopped")
