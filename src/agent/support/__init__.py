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


def normalize_xray_client(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Accept NetinjaBot / x-ui style aliases and produce Xray settings.clients fields.
    Unknown extras are kept so customized cores can persist them in config.json.
    """
    client = deepcopy(payload)
    client.pop("format", None)

    if "is_enabled" in client:
        client["enable"] = _as_bool(client.pop("is_enabled"))
    elif "enable" in client:
        client["enable"] = _as_bool(client["enable"])

    if "max_connection" in client and "limitIp" not in client:
        client["limitIp"] = _as_int(client.pop("max_connection"))
    elif "limitIp" in client:
        client["limitIp"] = _as_int(client["limitIp"])

    if "volume" in client and "totalGB" not in client:
        volume_f = _as_float(client.pop("volume"))
        # Bot remaining volume is usually bytes; x-ui style uses GB.
        client["totalGB"] = volume_f / (1024**3) if volume_f > 1024 else volume_f
    elif "totalGB" in client:
        client["totalGB"] = _as_float(client["totalGB"])

    if "expires_at" in client and "expiryTime" not in client:
        ms = _expiry_ms(client.pop("expires_at"))
        if ms is not None:
            client["expiryTime"] = ms
    elif "expiryTime" in client:
        ms = _expiry_ms(client["expiryTime"])
        client["expiryTime"] = ms if ms is not None else 0

    if "incoming" in client and "down" not in client:
        client["down"] = _as_int(client.get("incoming"))
    if "outgoing" in client and "up" not in client:
        client["up"] = _as_int(client.get("outgoing"))

    return client


def normalize_peer(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize bot-style client fields onto a WireGuard/Amnezia peer document."""
    peer = deepcopy(payload)
    peer.pop("format", None)

    if "name" in peer and "email" not in peer:
        peer["email"] = peer["name"]

    if "is_enabled" in peer:
        peer["enable"] = _as_bool(peer.pop("is_enabled"))
    elif "enable" in peer:
        peer["enable"] = _as_bool(peer["enable"])
    else:
        peer.setdefault("enable", True)

    if "max_connection" in peer:
        peer["limitIp"] = _as_int(peer.pop("max_connection"))

    if "expires_at" in peer:
        ms = _expiry_ms(peer["expires_at"])
        if ms is not None:
            peer["expires_at"] = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
    if "volume" in peer:
        peer["volume"] = _as_int(peer["volume"])

    return peer
