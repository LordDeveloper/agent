from __future__ import annotations

from typing import Any

from agent.asyncutil import gather_independent, maybe_await
from agent.drivers.base import CoreDriver
from agent.models import UsageSnapshotModel


def traffic_from_snapshot(
    snapshot: UsageSnapshotModel,
    online: list[str] | set[str],
) -> dict[str, dict[str, int]]:
    """Build online traffic rows from an already-fetched snapshot + online list."""
    online_set = {str(item) for item in online}
    out: dict[str, dict[str, int]] = {}
    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            email = str(client.email or "").strip()
            client_id = str(client.id or "").strip()
            labels = [label for label in (client_id, email) if label]
            if not labels:
                continue
            if online_set and not any(label in online_set for label in labels):
                continue
            if int(client.incoming or 0) <= 0 and int(client.outgoing or 0) <= 0:
                continue
            row = {
                "uplink": int(client.outgoing or 0),
                "downlink": int(client.incoming or 0),
            }
            for label in labels:
                out[label] = row
    for email in online_set:
        out.setdefault(str(email), {})
    return out


async def online_traffic_from_snapshot(driver: CoreDriver) -> dict[str, dict[str, int]]:
    """Fallback for cores without Xray /api/stats/online/traffic.

    Emits both peer id (panel node_id) and email keys so the panel enrich
    path can match the same way pending traffic does.
    """
    snapshot, users = await gather_independent(
        maybe_await(driver.usage_snapshot()),
        maybe_await(driver.online_users()),
    )
    return traffic_from_snapshot(snapshot, users)


async def collect_online_traffic(registry, core: str | None = None) -> dict[str, dict[str, int]]:
    return await registry.online_traffic(core)
