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
    interval = max(15.0, float(getattr(settings, "mullvad_fallback_interval", 30.0) or 0))
    log.info("mullvad fallback worker started interval=%ss", interval)
    service = MullvadService(store, config_dir=settings.wireguard_config_dir)

    try:
        await asyncio.wait_for(stop_event.wait(), timeout=5)
        log.info("mullvad fallback worker stopped")
        return
    except asyncio.TimeoutError:
        pass

    while not stop_event.is_set():
        try:
            restored = await asyncio.to_thread(service.restore_interfaces)
            if restored.get("restored") or restored.get("failed"):
                log.info(
                    "mullvad restore restored=%s failed=%s",
                    restored.get("restored"),
                    restored.get("failed"),
                )
            result = await asyncio.to_thread(service.fallback)
            changed = len(result.get("changed") or [])
            failed = len(result.get("failed") or [])
            if changed or failed:
                log.info("mullvad fallback changed=%s failed=%s", changed, failed)
        except Exception:
            log.exception("mullvad fallback cycle failed")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            continue

    log.info("mullvad fallback worker stopped")
