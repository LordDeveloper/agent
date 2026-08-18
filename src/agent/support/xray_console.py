from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

REDACTED = "***"
SECRET_KEYS = {
    "password",
    "passwd",
    "secret",
    "privatekey",
    "private_key",
    "encryptionkey",
    "encryption_key",
}
MANAGED_SECTIONS = {
    "log",
    "dns",
    "routing",
    "policy",
    "reverse",
    "observatory",
    "burstObservatory",
    "stats",
    "metrics",
    "transport",
}


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS and isinstance(item, str) and item not in ("", REDACTED):
                out[key] = REDACTED
            else:
                out[key] = redact_secrets(item)
        return out
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def restore_redacted_secrets(incoming: Any, current: Any) -> Any:
    if isinstance(incoming, dict) and isinstance(current, dict):
        out: dict[str, Any] = {}
        for key, item in incoming.items():
            if str(key).lower() in SECRET_KEYS and item in (REDACTED, "", None):
                out[key] = current.get(key, item)
            elif key in current:
                out[key] = restore_redacted_secrets(item, current.get(key))
            else:
                out[key] = item
        return out
    if isinstance(incoming, list) and isinstance(current, list):
        restored: list[Any] = []
        for idx, item in enumerate(incoming):
            restored.append(restore_redacted_secrets(item, current[idx] if idx < len(current) else None))
        return restored
    return incoming


def log_file_path(log: dict[str, Any], kind: str) -> Path | None:
    raw = log.get(kind) or log.get(f"{kind}Log") or log.get(f"{kind}log")
    text = str(raw or "").strip()
    if text == "" or text.lower() in {"none", "null", "false"}:
        return None
    return Path(text)


def tail_file(path: Path, lines: int, *, max_bytes: int = 2_000_000) -> str:
    if lines < 1:
        return ""
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(-max_bytes, 2)
            blob = handle.read()
    except OSError:
        return ""
    text = blob.decode("utf-8", errors="replace").replace("\r\n", "\n")
    rows = text.split("\n")
    if rows and rows[-1] == "":
        rows = rows[:-1]
    return "\n".join(rows[-lines:])


def routing_without_rules(routing: dict[str, Any] | None) -> dict[str, Any]:
    payload = deepcopy(routing or {})
    payload.pop("rules", None)
    return payload
