from __future__ import annotations

import json
import shutil
from typing import Any, Callable

from agent.support.process import execute

Runner = Callable[..., Any]


async def list_host_interfaces(*, runner: Runner | None = None) -> list[dict[str, Any]]:
    """Return host NICs (excluding loopback) for admin exit-interface selection."""
    if not shutil.which("ip"):
        return []

    raw = await _ip_json(["-j", "addr"], runner)
    if raw is None:
        raw = await _ip_json(["-j", "link"], runner)
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


async def add_interface_address(
    name: str,
    address: str,
    *,
    prefix: int = 32,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Assign a public IPv4 to a host NIC (`ip addr add`)."""
    iface = str(name or "").strip()
    ip = str(address or "").strip()
    if not iface or not _safe_iface_name(iface):
        raise ValueError("interface name is invalid")
    if not _is_public_ipv4(ip):
        raise ValueError("address must be a public IPv4")
    if prefix < 1 or prefix > 32:
        raise ValueError("prefix is invalid")

    rows = await list_host_interfaces(runner=runner)
    row = next((item for item in rows if str(item.get("name") or "") == iface), None)
    if row is None:
        raise ValueError(f"interface {iface} was not found")

    for existing in row.get("addresses") or []:
        if str(existing).split("/", 1)[0] == ip:
            return {
                "added": False,
                "already_present": True,
                "interface": iface,
                "address": ip,
                "prefix": prefix,
            }

    if runner is None and not shutil.which("ip"):
        raise ValueError("iproute2 is not installed")

    result = await execute(
        runner,
        ["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface],
        check=False,
        timeout=10,
    )
    code = int(getattr(result, "returncode", 1) or 0)
    stderr = str(getattr(result, "stderr", None) or "").strip()
    if code != 0 and "file exists" not in stderr.lower() and "exists" not in stderr.lower():
        raise ValueError(stderr or f"ip addr add failed ({code})")

    return {
        "added": code == 0,
        "already_present": code != 0,
        "interface": iface,
        "address": ip,
        "prefix": prefix,
    }


def _safe_iface_name(name: str) -> bool:
    if not name or len(name) > 15:
        return False
    first = name[0]
    if not (first.isalpha()):
        return False
    return all(char.isalnum() or char in "_.-" for char in name)


def _is_public_ipv4(value: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def _ip_json(args: list[str], runner: Runner | None) -> Any:
    try:
        result = await execute(runner, ["ip", *args], check=False, timeout=10)
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
