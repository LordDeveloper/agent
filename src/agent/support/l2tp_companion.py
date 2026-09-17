from __future__ import annotations

"""Keep L2TP companion users dependent on their linked WireGuard/Amnezia peer.

Source of truth is the WG/Amnezia peer document. Companion ``is_enabled`` and
``exit_interface`` are derived on reconcile so a stale L2TP copy cannot leak
to the region's main WAN.
"""

from typing import Any, Iterable

from agent.db import Store
from agent.logutil import get_logger
from agent.support import record_is_enabled
from agent.support.disable_reason import clear_disabled_metadata
from agent.support.peer_egress import normalize_exit_interface

log = get_logger("l2tp.companion")

_WG_CORES = ("wireguard", "amnezia")
_IFACE_KIND = "interface"
_L2TP_KIND = "server"
_MISSING_REASON = "linked_peer_missing"
_DISABLED_REASON = "linked_peer_disabled"


def companion_link_id(user: dict[str, Any]) -> str:
    return str(user.get("linked_peer_id") or "").strip()


def is_companion_user(user: dict[str, Any]) -> bool:
    return bool(companion_link_id(user))


def find_linked_peer(store: Store, user: dict[str, Any]) -> dict[str, Any] | None:
    needle = companion_link_id(user)
    if not needle:
        needle = str(user.get("id") or "").strip()
    if not needle:
        return None
    for core in _WG_CORES:
        for iface in store.list_docs(core, _IFACE_KIND):
            if not isinstance(iface, dict):
                continue
            for peer in iface.get("peers") or []:
                if not isinstance(peer, dict):
                    continue
                if needle in {
                    str(peer.get("id") or "").strip(),
                    str(peer.get("email") or "").strip(),
                }:
                    return peer
    return None


def apply_linked_state(user: dict[str, Any], store: Store) -> bool:
    """Mutate a companion user to match the linked WG peer. Pure L2TP is untouched."""
    linked = companion_link_id(user)
    peer = find_linked_peer(store, user)
    if not linked:
        if peer is None:
            return False
        user["linked_peer_id"] = str(peer.get("id") or user.get("id") or "")

    before_enabled = record_is_enabled(user)
    before_exit = str(user.get("exit_interface") or "")
    before_reason = str(user.get("disabled_reason") or "")
    before_expires = user.get("expires_at")
    if peer is None:
        user["is_enabled"] = False
        user.pop("exit_interface", None)
        user["disabled_reason"] = _MISSING_REASON
        changed = (
            before_enabled
            or before_exit != ""
            or before_reason != _MISSING_REASON
        )
        if changed:
            log.info(
                "l2tp companion %s disabled; linked wireguard peer missing",
                user.get("address") or user.get("id"),
            )
        return changed

    exit_iface = normalize_exit_interface(peer.get("exit_interface"))
    if exit_iface:
        user["exit_interface"] = exit_iface
    else:
        user.pop("exit_interface", None)

    if record_is_enabled(peer):
        user["is_enabled"] = True
        clear_disabled_metadata(user)
    else:
        user["is_enabled"] = False
        user["disabled_reason"] = _DISABLED_REASON

    if "expires_at" in peer:
        user["expires_at"] = peer.get("expires_at")
    else:
        user.pop("expires_at", None)

    changed = (
        record_is_enabled(user) != before_enabled
        or str(user.get("exit_interface") or "") != before_exit
        or str(user.get("disabled_reason") or "") != before_reason
        or user.get("expires_at") != before_expires
        or (not linked and bool(companion_link_id(user)))
    )
    if changed:
        log.info(
            "l2tp companion %s -> wg peer enabled=%s exit=%s",
            user.get("address") or user.get("id"),
            record_is_enabled(peer),
            user.get("exit_interface") or "",
        )
    return changed


def _user_keys(user: dict[str, Any]) -> set[str]:
    return {
        key
        for key in (
            str(user.get("id") or "").strip(),
            str(user.get("email") or "").strip(),
            companion_link_id(user),
        )
        if key
    }


def sync_companions(store: Store, *, drop_keys: Iterable[str] | None = None) -> dict[str, Any]:
    drop = {str(key).strip() for key in (drop_keys or []) if str(key).strip()}
    removed = 0
    updated = 0
    for server in store.list_docs("l2tp", _L2TP_KIND):
        if not isinstance(server, dict):
            continue
        users = [row for row in (server.get("users") or []) if isinstance(row, dict)]
        kept: list[dict[str, Any]] = []
        dirty = False
        for user in users:
            if drop and (_user_keys(user) & drop) and (
                is_companion_user(user) or find_linked_peer(store, user) is not None
            ):
                log.info(
                    "l2tp companion %s removed; linked wireguard peer deleted",
                    user.get("address") or user.get("id"),
                )
                removed += 1
                dirty = True
                continue
            if apply_linked_state(user, store):
                updated += 1
                dirty = True
            kept.append(user)
        if dirty:
            server["users"] = kept
            store.put_doc("l2tp", _L2TP_KIND, str(server.get("id")), server)
    return {"removed": removed, "updated": updated, "changed": (removed + updated) > 0}
