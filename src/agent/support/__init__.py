from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text == "":
        return default
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text == "":
        return default
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def _expiry_ms(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        nested = value.get("date") or value.get("datetime") or value.get("expires_at")
        return _expiry_ms(nested) if nested is not None and nested is not value else None
    if isinstance(value, (int, float)):
        number = int(value)
        # seconds → ms when looks like unix seconds
        return number * 1000 if number < 10_000_000_000 else number
    text = str(value).strip()
    try:
        if text.isdigit():
            return _expiry_ms(int(text))
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, OverflowError, OSError):
        return None


_XUI_KEYS = ("enable", "expiryTime", "totalGB", "limitIp", "up", "down", "subId", "tgId")


def record_is_enabled(row: dict[str, Any], default: bool = True) -> bool:
    if "is_enabled" in row:
        return _as_bool(row.get("is_enabled"), default)
    if "enable" in row:
        return _as_bool(row.get("enable"), default)
    return default


def _expires_at_iso(value: Any) -> str | None:
    ms = _expiry_ms(value)
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def normalize_xray_client(payload: dict[str, Any]) -> dict[str, Any]:
    """Canonical Netinja client fields. x-ui aliases are accepted then dropped."""
    client = deepcopy(payload)
    client.pop("format", None)

    client["is_enabled"] = record_is_enabled(client)

    if "max_connection" in client or "limitIp" in client:
        client["max_connection"] = _as_int(client.get("max_connection", client.get("limitIp")))

    if "volume" in client:
        client["volume"] = _as_int(client.get("volume"))
    elif "totalGB" in client:
        # 3x-ui `totalGB` is already bytes (same as Netinja `volume`).
        client["volume"] = _as_int(client.get("totalGB"))

    expires = client.get("expires_at", client.get("expiryTime"))
    if expires is not None:
        iso = _expires_at_iso(expires)
        if iso is not None:
            client["expires_at"] = iso
        elif expires in (0, "0", False, ""):
            client["expires_at"] = None

    if "incoming" in client or "down" in client:
        client["incoming"] = _as_int(client.get("incoming", client.get("down")))
    if "outgoing" in client or "up" in client:
        client["outgoing"] = _as_int(client.get("outgoing", client.get("up")))

    for key in _XUI_KEYS:
        client.pop(key, None)

    return client


def normalize_peer(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize bot-style client fields onto a WireGuard/Amnezia peer document."""
    peer = deepcopy(payload)
    peer.pop("format", None)

    if "name" in peer and "email" not in peer:
        peer["email"] = peer["name"]

    peer["is_enabled"] = record_is_enabled(peer)

    if "max_connection" in peer or "limitIp" in peer:
        peer["max_connection"] = _as_int(peer.get("max_connection", peer.get("limitIp")))

    expires = peer.get("expires_at", peer.get("expiryTime"))
    if expires is not None:
        iso = _expires_at_iso(expires)
        if iso is not None:
            peer["expires_at"] = iso
        elif expires in (0, "0", False, ""):
            peer["expires_at"] = None

    if "volume" in peer:
        peer["volume"] = _as_int(peer["volume"])
    elif "totalGB" in peer:
        peer["volume"] = _as_int(peer.get("totalGB"))

    if "incoming" in peer or "down" in peer:
        peer["incoming"] = _as_int(peer.get("incoming", peer.get("down")))
    if "outgoing" in peer or "up" in peer:
        peer["outgoing"] = _as_int(peer.get("outgoing", peer.get("up")))

    for key in _XUI_KEYS:
        peer.pop(key, None)

    return peer
