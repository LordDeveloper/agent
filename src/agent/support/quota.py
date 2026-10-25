from __future__ import annotations

from typing import Any

from agent.asyncutil import gather_independent, maybe_await
from agent.support import record_is_enabled
from agent.support.disable_reason import baseline_looks_like_raw_kernel, mark_quota_disabled


def has_volume_quota(client: dict[str, Any]) -> bool:
    """True when the panel tracks a finite byte quota for this client."""
    if "volume" not in client:
        return False

    # Panel uses volume=0 for unlimited plans; only positive values are enforceable quota.
    return int(client.get("volume") or 0) > 0


def quota_delta_since_baseline(
    client: dict[str, Any],
    live_incoming: int,
    live_outgoing: int,
) -> int:
    base_in = int(client.get("_incoming") or 0)
    base_out = int(client.get("_outgoing") or 0)
    delta_in = max(0, live_incoming - base_in)
    delta_out = max(0, live_outgoing - base_out)
    return delta_in + delta_out


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
    delta = quota_delta_since_baseline(client, live_incoming, live_outgoing)

    return delta >= remaining


def seed_stale_zero_baseline(client: dict[str, Any]) -> bool:
    """
    Panel/agent store can carry cumulative counters while _incoming/_outgoing stayed at 0,
    or legacy WireGuard peers kept kernel raw counters in the quota baseline fields.
    """
    store_in = int(client.get("incoming") or 0)
    store_out = int(client.get("outgoing") or 0)
    base_in = int(client.get("_incoming") or 0)
    base_out = int(client.get("_outgoing") or 0)

    if store_in <= 0 and store_out <= 0:
        return False

    zero_baseline = base_in <= 0 and base_out <= 0
    raw_kernel_baseline = baseline_looks_like_raw_kernel(base_in, base_out, store_in, store_out)

    if not zero_baseline and not raw_kernel_baseline:
        return False

    client["_incoming"] = store_in
    client["_outgoing"] = store_out
    client.pop("disabled_reason", None)
    client.pop("disabled_at", None)
    client.pop("disabled_detail", None)

    return True


def seed_ahead_baseline(
    client: dict[str, Any],
    live_incoming: int,
    live_outgoing: int,
) -> bool:
    """
    Panel shadow counters can drift ahead of agent cumulative totals after desync or
    counter regression. When baseline exceeds live, quota math must treat delta as zero.
    """
    base_in = int(client.get("_incoming") or 0)
    base_out = int(client.get("_outgoing") or 0)
    changed = False

    if base_in > live_incoming:
        client["_incoming"] = live_incoming
        changed = True
    if base_out > live_outgoing:
        client["_outgoing"] = live_outgoing
        changed = True

    if not changed:
        return False

    client.pop("disabled_reason", None)
    client.pop("disabled_at", None)
    client.pop("disabled_detail", None)
    return True


def reseed_baseline_if_stale(
    client: dict[str, Any],
    live_incoming: int,
    live_outgoing: int,
) -> bool:
    return seed_stale_zero_baseline(client) or seed_ahead_baseline(
        client,
        live_incoming,
        live_outgoing,
    )


async def enforce_driver_quotas(driver: Any) -> int:
    if driver.key == "xray":
        return await _enforce_xray(driver)
    if driver.key in {"wireguard", "amnezia"}:
        return await _enforce_wireguard(driver)
    if driver.key == "l2tp":
        return await _enforce_l2tp(driver)
    return 0


async def _disabled_client_index(driver: Any) -> dict[str, dict[str, Any]]:
    """Clients the panel or a previous enforce already marked disabled."""
    docs = getattr(driver, "_disabled_docs", None)
    if not callable(docs):
        return {}
    index: dict[str, dict[str, Any]] = {}
    try:
        rows = await maybe_await(docs())
    except Exception:
        return {}
    for row in rows or []:
        if not isinstance(row, dict) or record_is_enabled(row):
            continue
        for key in (str(row.get("id") or "").strip(), str(row.get("email") or "").strip()):
            if key:
                index[key] = row
    return index


async def _enforce_xray(driver: Any) -> int:
    if not await maybe_await(driver.running()):
        return 0

    # The traffic worker already dumped user>>> . A second dump every 10s is
    # the call that makes the next panel request sit with zero bytes.
    snapshot = None
    cached = getattr(driver, "cached_usage_snapshot", None)
    if callable(cached):
        snapshot = cached()
    if snapshot is None:
        snapshot = await maybe_await(driver.usage_snapshot())
    traffic_by_email: dict[str, tuple[int, int]] = {}
    traffic_by_id: dict[str, tuple[int, int]] = {}

    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            if client.email:
                traffic_by_email[str(client.email)] = (int(client.incoming), int(client.outgoing))
            if client.id:
                traffic_by_id[str(client.id)] = (int(client.incoming), int(client.outgoing))

    disabled_index = await _disabled_client_index(driver)

    inbound_rows = getattr(driver, "list_quota_inbounds", None)
    if callable(inbound_rows):
        # Parses the whole on-disk client list. On the loop that stalls every
        # other request once the inbound is large.
        inbounds = await inbound_rows()
    else:
        inbounds = await maybe_await(driver.list_inbounds())

    async def handle(inbound: dict[str, Any]) -> int:
        inbound_id = inbound.get("id")
        to_disable: list[dict[str, Any]] = []
        to_reseed: list[dict[str, Any]] = []

        for client in driver._clients_of(inbound):
            email = str(client.get("email") or "")
            cid = str(client.get("id") or "")
            stored = disabled_index.get(cid) or disabled_index.get(email)
            # A disable flag on the inbound does not stop Xray. If the client is
            # still listed, pull them off so the credential cannot pass traffic.
            if stored is not None or not record_is_enabled(client):
                row = dict(client)
                row["is_enabled"] = False
                reason = str((stored or {}).get("disabled_reason") or row.get("disabled_reason") or "").strip()
                if reason:
                    row["disabled_reason"] = reason
                to_disable.append(row)
                continue

            if not has_volume_quota(client):
                continue

            live = traffic_by_email.get(email) or traffic_by_id.get(cid)
            if live is None:
                live = (
                    int(client.get("_incoming") or 0),
                    int(client.get("_outgoing") or 0),
                )

            row = dict(client)
            if reseed_baseline_if_stale(row, live[0], live[1]):
                if not quota_exceeded(row, live[0], live[1]):
                    row["is_enabled"] = True
                to_reseed.append(row)
                continue

            if not record_is_enabled(client):
                continue

            if not quota_exceeded(row, live[0], live[1]):
                continue

            mark_quota_disabled(row, live[0], live[1])
            to_disable.append(row)

        # Reseed then disable on the same inbound stay sequential.
        if to_reseed:
            await maybe_await(driver.batch_clients(inbound_id, clients=to_reseed, mode="update"))
        if not to_disable:
            return 0
        await maybe_await(driver.batch_clients(inbound_id, clients=to_disable, mode="update"))
        return len(to_disable)

    counts = await gather_independent(*(handle(inbound) for inbound in inbounds))
    return sum(int(count) for count in counts if isinstance(count, int))


async def _enforce_wireguard(driver: Any) -> int:
    await maybe_await(driver.sync_peer_stats())
    snapshot = await maybe_await(driver.usage_snapshot())
    traffic_by_email: dict[str, tuple[int, int]] = {}
    traffic_by_id: dict[str, tuple[int, int]] = {}

    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            if client.email:
                traffic_by_email[str(client.email)] = (int(client.incoming), int(client.outgoing))
            if client.id:
                traffic_by_id[str(client.id)] = (int(client.incoming), int(client.outgoing))

    async def handle(iface: dict[str, Any]) -> int:
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
            if reseed_baseline_if_stale(row, live[0], live[1]):
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
            await maybe_await(driver.batch_peers(interface_id, peers=to_reseed, mode="update"))
        if not to_disable:
            return 0
        await maybe_await(driver.batch_peers(interface_id, peers=to_disable, mode="update"))
        return len(to_disable)

    interfaces = await maybe_await(driver.list_interfaces())
    counts = await gather_independent(*(handle(iface) for iface in interfaces or []))
    return sum(int(count) for count in counts if isinstance(count, int))


async def _enforce_l2tp(driver: Any) -> int:
    await maybe_await(driver.sync_user_stats())
    snapshot = await maybe_await(driver.usage_snapshot())
    traffic_by_email: dict[str, tuple[int, int]] = {}
    traffic_by_id: dict[str, tuple[int, int]] = {}

    for inbound in snapshot.inbounds:
        for client in inbound.clients:
            if client.email:
                traffic_by_email[str(client.email)] = (int(client.incoming), int(client.outgoing))
            if client.id:
                traffic_by_id[str(client.id)] = (int(client.incoming), int(client.outgoing))

    async def handle(server: dict[str, Any]) -> int:
        server_id = server.get('id')
        to_disable: list[dict[str, Any]] = []
        to_reseed: list[dict[str, Any]] = []

        for user in server.get('users') or []:
            if not isinstance(user, dict) or not has_volume_quota(user):
                continue

            # Companion users share quota with the linked WireGuard/Amnezia peer.
            if str(user.get('linked_peer_id') or '').strip():
                continue

            email = str(user.get('email') or '')
            uid = str(user.get('id') or '')
            live = traffic_by_email.get(email) or traffic_by_id.get(uid)
            if live is None:
                live = (
                    int(user.get('_incoming') or 0),
                    int(user.get('_outgoing') or 0),
                )

            row = dict(user)
            if reseed_baseline_if_stale(row, live[0], live[1]):
                if not quota_exceeded(row, live[0], live[1]):
                    row['is_enabled'] = True
                to_reseed.append(row)
                continue

            if not record_is_enabled(user):
                continue

            if not quota_exceeded(row, live[0], live[1]):
                continue

            mark_quota_disabled(row, live[0], live[1])
            to_disable.append(row)

        if to_reseed:
            await maybe_await(driver.batch_users(server_id, users=to_reseed, mode='update'))
        if not to_disable:
            return 0
        await maybe_await(driver.batch_users(server_id, users=to_disable, mode='update'))
        return len(to_disable)

    servers = await maybe_await(driver.list_servers())
    counts = await gather_independent(*(handle(server) for server in servers or []))
    return sum(int(count) for count in counts if isinstance(count, int))


def quota_meta_from_client(client: dict[str, Any]) -> dict[str, Any]:
    """Panel quota fields to keep beside an Xray user.

    Xray's users API only accepts protocol fields, so volume never survives
    on the inbound user unless the agent stores it separately.
    """
    cid = str(client.get("id") or "").strip()
    email = str(client.get("email") or "").strip()
    volume = client.get("volume") if "volume" in client else None
    try:
        volume = int(volume) if volume is not None else None
    except (TypeError, ValueError):
        volume = None
    if volume is not None and volume <= 0:
        volume = None

    meta: dict[str, Any] = {
        "id": cid,
        "email": email,
        "volume": volume,
    }
    for key in ("_incoming", "_outgoing"):
        if key in client:
            try:
                meta[key] = int(client.get(key) or 0)
            except (TypeError, ValueError):
                meta[key] = 0
    if "expires_at" in client:
        meta["expires_at"] = client.get("expires_at")
    if "max_connection" in client and client.get("max_connection") is not None:
        try:
            meta["max_connection"] = int(client.get("max_connection") or 0)
        except (TypeError, ValueError):
            meta["max_connection"] = 0
    if "is_enabled" in client:
        meta["is_enabled"] = bool(client.get("is_enabled"))
    return meta


def apply_quota_meta(client: dict[str, Any], meta: dict[str, Any], *, include_flags: bool = False) -> None:
    """Merge a stored quota record onto a client read from Xray."""
    if not meta:
        return

    if "volume" in meta:
        volume = meta.get("volume")
        if volume is None:
            client.pop("volume", None)
        else:
            try:
                volume = int(volume)
            except (TypeError, ValueError):
                volume = 0
            if volume > 0:
                client["volume"] = volume
            else:
                client.pop("volume", None)

    for key in ("_incoming", "_outgoing"):
        if key in meta and meta[key] is not None:
            try:
                client[key] = int(meta[key])
            except (TypeError, ValueError):
                continue

    if not include_flags:
        return

    if "expires_at" in meta:
        client["expires_at"] = meta.get("expires_at")
    if meta.get("max_connection") is not None and "max_connection" in meta:
        try:
            client["max_connection"] = int(meta.get("max_connection") or 0)
        except (TypeError, ValueError):
            pass
    if "is_enabled" in meta and meta.get("is_enabled") is not None:
        client["is_enabled"] = bool(meta.get("is_enabled"))
