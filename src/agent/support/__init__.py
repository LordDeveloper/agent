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

    # Keep opaque per-client bag (e.g. Shadowsocks AEAD method) for round-trips.
    extra = client.get("extra")
    if isinstance(extra, dict):
        client["extra"] = {
            k: v for k, v in extra.items()
            if v is not None and str(v).strip() != ""
        }
    elif "extra" in client:
        client.pop("extra", None)

    method = str(client.get("method") or client.get("cipher") or "").strip()
    if method:
        client["method"] = method
    else:
        client.pop("method", None)
        client.pop("cipher", None)

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

    flow = client.get("flow")
    if not isinstance(flow, str) or not flow.strip():
        client.pop("flow", None)
    else:
        client["flow"] = flow.strip()

    # Inbound VLESS rejects encryption; share URIs add it client-side.
    client.pop("encryption", None)
    if client.get("reverse") in (None, "", {}, []):
        client.pop("reverse", None)

    return client


_VLESS_FLOWS = {"", "xtls-rprx-vision"}
_NETINJA_CLIENT_KEYS = {
    "is_enabled",
    "enable",
    "expires_at",
    "expiryTime",
    "volume",
    "totalGB",
    "incoming",
    "outgoing",
    "up",
    "down",
    "max_connection",
    "limitIp",
    "subscribe_id",
    "telegram_id",
    "subId",
    "tgId",
    "alterId",
    "alter_id",
    "disableInsecureEncryption",
    "format",
    "name",
}


def _copy_if_present(src: dict[str, Any], dest: dict[str, Any], key: str) -> None:
    value = src.get(key)
    if value is None or value == "":
        return
    dest[key] = value


def xray_protocol_user(protocol: str, client: dict[str, Any]) -> dict[str, Any]:
    """Fields Xray infra/conf accepts for an inbound user (no Netinja metadata)."""
    protocol = str(protocol or "").strip().lower()
    row = deepcopy(client)
    for key in list(row):
        if row[key] is None:
            row.pop(key)

    if protocol == "vless":
        user: dict[str, Any] = {}
        _copy_if_present(row, user, "id")
        _copy_if_present(row, user, "email")
        flow = str(row.get("flow") or "").strip()
        if flow and flow in _VLESS_FLOWS:
            user["flow"] = flow
        if "level" in row and row["level"] is not None and row["level"] != "":
            user["level"] = _as_int(row.get("level"))
        return user

    if protocol == "vmess":
        user = {}
        _copy_if_present(row, user, "id")
        _copy_if_present(row, user, "email")
        user["alterId"] = _as_int(row.get("alterId", row.get("alter_id")))
        _copy_if_present(row, user, "security")
        if "level" in row and row["level"] is not None and row["level"] != "":
            user["level"] = _as_int(row.get("level"))
        return user

    if protocol == "trojan":
        user = {}
        password = row.get("password") or row.get("id")
        if password:
            user["password"] = str(password)
        _copy_if_present(row, user, "email")
        flow = str(row.get("flow") or "").strip()
        if flow:
            user["flow"] = flow
        return user

    if protocol in {"shadowsocks", "ss"}:
        user = {}
        _copy_if_present(row, user, "email")
        password = row.get("password") or row.get("id")
        if password:
            user["password"] = str(password)
        method = row.get("method") or row.get("cipher")
        if not method:
            extra = row.get("extra")
            if isinstance(extra, dict):
                method = extra.get("method") or extra.get("cipher")
        method = str(method or "").strip()
        # Never emit blank cipher — Xray fails with "unsupported cipher method:".
        if method:
            user["method"] = method
        return user

    cleaned = {k: v for k, v in row.items() if k not in _NETINJA_CLIENT_KEYS and v is not None and v != ""}
    cleaned.pop("encryption", None)
    return cleaned


def xray_users_settings(
    protocol: str,
    inbound_settings: dict[str, Any] | None,
    clients: list[dict[str, Any]],
) -> dict[str, Any]:
    """Inbound settings fragment for users/add and users/edit."""
    settings: dict[str, Any] = {}
    if inbound_settings:
        for key, value in inbound_settings.items():
            if key not in {"clients", "users"}:
                settings[key] = deepcopy(value)
    protocol_key = str(protocol or "").strip().lower()
    if protocol_key == "vless":
        settings.setdefault("decryption", "none")
    if protocol_key in {"shadowsocks", "ss"}:
        method = str(settings.get("method") or "").strip()
        if method == "":
            settings.pop("method", None)
            if str(settings.get("password") or "").strip() == "":
                settings.pop("password", None)
        else:
            settings["method"] = method
        settings.setdefault("network", "tcp,udp")
    native = [xray_protocol_user(protocol, client) for client in clients]
    settings["clients"] = native
    settings["users"] = native
    return settings


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

    if "exit_interface" in peer:
        exit_iface = str(peer.get("exit_interface") or "").strip()
        if exit_iface:
            peer["exit_interface"] = exit_iface
        else:
            peer.pop("exit_interface", None)

    for key in _XUI_KEYS:
        peer.pop(key, None)

    return peer
