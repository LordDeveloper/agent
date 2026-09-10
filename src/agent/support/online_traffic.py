from __future__ import annotations

from typing import Any

from agent.drivers.base import CoreDriver
from agent.models import UsageSnapshotModel


def online_traffic_from_snapshot(driver: CoreDriver) -> dict[str, dict[str, int]]:
    """Fallback for cores without Xray /api/stats/online/traffic.

    Emits both peer id (panel node_id) and email keys so the panel enrich
    path can match the same way pending traffic does.
    """
    online = set(driver.online_users())
    out: dict[str, dict[str, int]] = {}
    snapshot = driver.usage_snapshot()
    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            email = str(client.email or "").strip()
            client_id = str(client.id or "").strip()
            labels = [label for label in (client_id, email) if label]
            if not labels:
                continue
            if online and not any(label in online for label in labels):
                continue
            if int(client.incoming or 0) <= 0 and int(client.outgoing or 0) <= 0:
                continue
            row = {
                "uplink": int(client.outgoing or 0),
                "downlink": int(client.incoming or 0),
            }
            for label in labels:
                out[label] = row
    for email in online:
        out.setdefault(str(email), {})
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
