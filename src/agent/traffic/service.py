"""Volume sampler.

The readable source of this module was truncated to an empty file. The body
below is the last compiled copy (Python 3.11), kept beside this loader so
import does not replace it.
"""

from __future__ import annotations

import marshal
from pathlib import Path

_BLOB = Path(__file__).with_name("_service_body.pyc")
_code = marshal.loads(_BLOB.read_bytes()[16:])
exec(_code, globals())


def _usage_snapshot_call(driver, reset_xray: bool):
    """``reset_stats`` exists only on the Xray stats query."""
    if reset_xray:
        return driver.usage_snapshot(reset_stats=True)
    return driver.usage_snapshot()


async def _read_core_usage_snapshot(self, registry, core_key):
    from agent.asyncutil import maybe_await

    started = time.monotonic()
    driver = registry.get(core_key)
    if core_key == "l2tp":
        await self._drop_linked_l2tp_billing(driver)
    reset_xray = core_key == "xray" and bool(
        getattr(registry.settings, "traffic_xray_reset_stats", False)
    )
    cache_hit = None
    if core_key == "xray" and not reset_xray:
        max_age = getattr(driver, "_usage_cache_max_age", lambda: 5.0)()
        cached = getattr(driver, "cached_usage_snapshot", lambda _age: None)(max_age)
        cache_hit = cached is not None
    snapshot = await maybe_await(_usage_snapshot_call(driver, reset_xray))
    if core_key == "xray" and cache_hit is not None:
        log.info("traffic sample xray cache=%s", "hit" if cache_hit else "miss")
    if reset_xray:
        log.info("traffic sample xray reset_stats=on")
    snapshot_ms = int((time.monotonic() - started) * 1000)
    return core_key, snapshot, snapshot_ms


async def _sample_core(self, registry, core_key, owners_task=None):
    from agent.asyncutil import gather_independent, maybe_await

    started = time.monotonic()
    driver = registry.get(core_key)
    if core_key == "l2tp":
        await self._drop_linked_l2tp_billing(driver)
    reset_xray = core_key == "xray" and bool(
        getattr(registry.settings, "traffic_xray_reset_stats", False)
    )
    if owners_task is not None:
        snapshot = await maybe_await(_usage_snapshot_call(driver, reset_xray))
        owners = await owners_task
    else:
        snapshot, owners = await gather_independent(
            maybe_await(_usage_snapshot_call(driver, reset_xray)),
            self.store.client_scopes(),
        )
    snapshot_ms = int((time.monotonic() - started) * 1000)
    store_started = time.monotonic()
    stats = await self._store_core_samples(
        core_key,
        snapshot,
        owners=owners,
        registry=registry,
    )
    store_ms = int((time.monotonic() - store_started) * 1000)
    total_ms = int((time.monotonic() - started) * 1000)
    log.info(
        "traffic sample timing core=%s clients=%s pending=%s snapshot_ms=%s sqlite_ms=%s total_ms=%s",
        core_key,
        stats.get("clients_seen", 0),
        stats.get("pending", 0),
        snapshot_ms,
        store_ms,
        total_ms,
    )
    stats["_timing"] = {
        "snapshot_ms": snapshot_ms,
        "sqlite_ms": store_ms,
        "total_ms": total_ms,
    }
    return stats


TrafficService._read_core_usage_snapshot = _read_core_usage_snapshot
TrafficService._sample_core = _sample_core
