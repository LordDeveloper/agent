"""Per-core volume snapshots in thread pool (isolated asyncio loop + SQLite reader)."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from agent.asyncutil import maybe_await
from agent.logutil import get_logger

if TYPE_CHECKING:
    from agent.config import AgentSettings

_log = get_logger("traffic.sample")

_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="traffic-sample")


def _snapshot_in_thread(settings: AgentSettings, core_key: str) -> tuple[str, Any, int]:
    started = time.monotonic()

    async def _run() -> Any:
        from agent.audit import AuditLog
        from agent.database.config import database_config_from_settings
        from agent.db import Store
        from agent.registry import CoreRegistry

        store = Store(
            database_config_from_settings(settings),
            slow_query_log_ms=float(settings.slow_query_log_ms or 0.0),
        )
        await store.open(migrate=False)
        try:
            audit = AuditLog(store)
            registry = CoreRegistry(settings, audit, store)
            driver = registry.get(core_key)
            return await maybe_await(driver.usage_snapshot())
        finally:
            await store.close()

    try:
        snapshot = asyncio.run(_run())
    except Exception:
        _log.exception("traffic snapshot thread failed core=%s", core_key)
        raise
    snapshot_ms = int((time.monotonic() - started) * 1000)
    return core_key, snapshot, snapshot_ms


async def gather_core_snapshots(
    settings: AgentSettings,
    core_keys: list[str],
) -> list[tuple[str, Any, int] | BaseException]:
    if not core_keys:
        return []
    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(_EXECUTOR, _snapshot_in_thread, settings, core_key) for core_key in core_keys
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
