from __future__ import annotations

from typing import Any

from agent.support import record_is_enabled
from agent.support.disable_reason import mark_quota_disabled


def has_volume_quota(client: dict[str, Any]) -> bool:
    """True when the panel tracks a finite byte quota for this client."""
    return "volume" in client


def quota_exceeded(client: dict[str, Any], live_incoming: int, live_outgoing: int) -> bool:
    """
    Compare live cumulative counters against the synced baseline and remaining quota.

    Contract (set by Laravel panel on each client update):
      - volume: remaining RAW bytes allowed since (_incoming, _outgoing) baseline
      - _incoming / _outgoing: last seen cumulative counters from stats snapshot
    """
    if not has_volume_quota(client) or not record_is_enabled(client):
        return False

    remaining = int(client.get("volume") or 0)
    if remaining <= 0:
        return True

    base_in = int(client.get("_incoming") or 0)
    base_out = int(client.get("_outgoing") or 0)

    delta_in = live_incoming - base_in if live_incoming >= base_in else live_incoming
    delta_out = live_outgoing - base_out if live_outgoing >= base_out else live_outgoing
    delta = max(0, delta_in) + max(0, delta_out)

    return delta >= remaining


def seed_stale_zero_baseline(client: dict[str, Any]) -> bool:
    """
    Panel/agent store can carry cumulative counters while _incoming/_outgoing stayed at 0.
    Treating the full total as post-baseline delta disables healthy peers — seed baseline first.
    """
    if int(client.get("_incoming") or 0) > 0 or int(client.get("_outgoing") or 0) > 0:
        return False

    store_in = int(client.get("incoming") or 0)
    store_out = int(client.get("outgoing") or 0)

    if store_in <= 0 and store_out <= 0:
        return False

    client["_incoming"] = store_in
    client["_outgoing"] = store_out
    client.pop("disabled_reason", None)
    client.pop("disabled_at", None)
    client.pop("disabled_detail", None)

    return True


def enforce_driver_quotas(driver: Any) -> int:
    if driver.key == "xray":
        return _enforce_xray(driver)
    if driver.key in {"wireguard", "amnezia"}:
        return _enforce_wireguard(driver)
    return 0


def _enforce_xray(driver: Any) -> int:
    if not driver.running():
        return 0

    snapshot = driver.usage_snapshot()
    traffic_by_email: dict[str, tuple[int, int]] = {}
    traffic_by_id: dict[str, tuple[int, int]] = {}

    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            if client.email:
                traffic_by_email[str(client.email)] = (int(client.incoming), int(client.outgoing))
            if client.id:
                traffic_by_id[str(client.id)] = (int(client.incoming), int(client.outgoing))

    disabled = 0

    for inbound in driver.list_inbounds():
        inbound_id = inbound.get("id")
        to_disable: list[dict[str, Any]] = []
        to_reseed: list[dict[str, Any]] = []

        for client in driver._clients_of(inbound):
            if not has_volume_quota(client) or not record_is_enabled(client):
                continue

            email = str(client.get("email") or "")
            cid = str(client.get("id") or "")
            live = traffic_by_email.get(email) or traffic_by_id.get(cid)
            if live is None:
                live = (
                    int(client.get("_incoming") or 0),
                    int(client.get("_outgoing") or 0),
                )

            row = dict(client)
            if seed_stale_zero_baseline(row):
                to_reseed.append(row)
                continue

            if not quota_exceeded(row, live[0], live[1]):
                continue

            mark_quota_disabled(row, live[0], live[1])
            to_disable.append(row)

        if to_reseed:
            driver.batch_clients(inbound_id, clients=to_reseed, mode="update")

        if not to_disable:
            continue

        driver.batch_clients(inbound_id, clients=to_disable, mode="update")
        disabled += len(to_disable)

    return disabled


def _enforce_wireguard(driver: Any) -> int:
    driver.sync_peer_stats()
    snapshot = driver.usage_snapshot()
    traffic_by_email: dict[str, tuple[int, int]] = {}
    traffic_by_id: dict[str, tuple[int, int]] = {}

    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            if client.email:
                traffic_by_email[str(client.email)] = (int(client.incoming), int(client.outgoing))
            if client.id:
                traffic_by_id[str(client.id)] = (int(client.incoming), int(client.outgoing))

    disabled = 0

    for iface in driver.list_interfaces():
        interface_id = iface.get("id")
        to_disable: list[dict[str, Any]] = []
        to_reseed: list[dict[str, Any]] = []

        for peer in iface.get("peers") or []:
            if not isinstance(peer, dict) or not has_volume_quota(peer):
                continue

            email = str(peer.get("email") or "")
            pid = str(peer.get("id") or "")
            live = traffic_by_email.get(email) or traffic_by_id.get(pid)
            if live is None:
                live = (
                    int(peer.get("_incoming") or 0),
                    int(peer.get("_outgoing") or 0),
                )

            row = dict(peer)
            if seed_stale_zero_baseline(row):
                if not quota_exceeded(row, live[0], live[1]):
                    row["is_enabled"] = True
                to_reseed.append(row)
                continue

            if not record_is_enabled(peer):
                continue

            if not quota_exceeded(row, live[0], live[1]):
                continue

            mark_quota_disabled(row, live[0], live[1])
            to_disable.append(row)

        if to_reseed:
            driver.batch_peers(interface_id, peers=to_reseed, mode="update")

        if not to_disable:
            continue

        driver.batch_peers(interface_id, peers=to_disable, mode="update")
        disabled += len(to_disable)

    return disabled
