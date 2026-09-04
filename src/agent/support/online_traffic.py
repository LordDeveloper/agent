from __future__ import annotations

from typing import Any

from agent.drivers.base import CoreDriver
from agent.models import UsageSnapshotModel


def online_traffic_from_snapshot(driver: CoreDriver) -> dict[str, dict[str, int]]:
    """Fallback for cores without Xray /api/stats/online/traffic."""
    online = set(driver.online_users())
    out: dict[str, dict[str, int]] = {}
    snapshot = driver.usage_snapshot()
    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            label = str(client.email or client.id or "")
            if not label:
                continue
            if online and label not in online:
                continue
            if int(client.incoming or 0) <= 0 and int(client.outgoing or 0) <= 0:
                continue
            out[label] = {
                "uplink": int(client.outgoing or 0),
                "downlink": int(client.incoming or 0),
            }
    for email in online:
        out.setdefault(email, {})
    return out


def collect_online_traffic(registry, core: str | None = None) -> dict[str, dict[str, int]]:
    if core:
        driver = registry.get(core)
        fn = getattr(driver, "online_traffic", None)
        if callable(fn):
            return fn()
        return online_traffic_from_snapshot(driver)

    merged: dict[str, dict[str, int]] = {}
    for key in registry.settings.cores():
        driver = registry.get(key)
        fn = getattr(driver, "online_traffic", None)
        rows = fn() if callable(fn) else online_traffic_from_snapshot(driver)
        for email, stats in rows.items():
            merged[str(email)] = stats
    return merged
