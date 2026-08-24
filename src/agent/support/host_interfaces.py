from __future__ import annotations

import json
import shutil
from typing import Any, Callable

from agent.support.process import run

Runner = Callable[..., Any]


def list_host_interfaces(*, runner: Runner | None = None) -> list[dict[str, Any]]:
    """Return host NICs (excluding loopback) for admin exit-interface selection."""
    execute = runner or run
    if not shutil.which("ip"):
        return []

    raw = _ip_json(["-j", "addr"], execute)
    if raw is None:
        raw = _ip_json(["-j", "link"], execute)
    if not isinstance(raw, list):
        return []

    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("ifname") or item.get("name") or "").strip()
        if not name or name == "lo" or name.startswith("lo:"):
            continue

        flags = item.get("flags") if isinstance(item.get("flags"), list) else []
        flags_upper = {str(flag).upper() for flag in flags}
        operstate = str(item.get("operstate") or "").strip().upper()
        is_up = "UP" in flags_upper or operstate in {"UP", "UNKNOWN"}

        addresses: list[str] = []
        for info in item.get("addr_info") or []:
            if not isinstance(info, dict):
                continue
            family = str(info.get("family") or "").strip().lower()
            local = str(info.get("local") or "").strip()
            if not local:
                continue
            if family == "inet6" and str(info.get("scope") or "").lower() == "link":
                continue
            prefix = info.get("prefixlen")
            if isinstance(prefix, int) and prefix > 0:
                addresses.append(f"{local}/{prefix}")
            else:
                addresses.append(local)

        linkinfo = item.get("linkinfo") if isinstance(item.get("linkinfo"), dict) else {}
        link_type = str(item.get("link_type") or linkinfo.get("info_kind") or "").strip() or None

        rows.append(
            {
                "name": name,
                "state": operstate or ("UP" if is_up else "DOWN"),
                "is_up": is_up,
                "addresses": addresses,
                "link_type": link_type,
            }
        )

    rows.sort(key=lambda row: (0 if row.get("is_up") else 1, str(row.get("name") or "")))
    return rows


def _ip_json(args: list[str], runner: Runner) -> Any:
    try:
        result = runner(["ip", *args], check=False, timeout=10)
    except Exception:
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    text = (getattr(result, "stdout", None) or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
