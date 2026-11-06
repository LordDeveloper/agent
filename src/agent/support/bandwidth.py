"""Per-subscription upload and download shaping for WireGuard, AmneziaWG, OpenVPN, and L2TP.

Objects created here use the ``njbw-`` prefix or the dedicated IFB devices
``ifb-nj-up`` and ``ifb-nj-down``. Nothing else is deleted.

WireGuard, AmneziaWG, and OpenVPN download is HTB on the tunnel device.
Upload for every core is HTB on ``ifb-nj-up`` after an ingress redirect.
L2TP download is HTB on ``ifb-nj-down``: each PPP session redirects its
unmarked egress there, the shaped packet is marked, and the second pass
on the PPP device sends it. Several sessions of one subscription share
one class. This is queue shaping, not a drop policer.

NULL bandwidth is unlimited and installs no class. Zero is invalid. 
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shlex
import shutil
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.logutil import get_logger

log = get_logger("bandwidth")

MAX_MBPS = 100000
SHAPED_CORES = frozenset({"wireguard", "amnezia", "openvpn", "l2tp"})
IFB_UP = "ifb-nj-up"
IFB_DOWN = "ifb-nj-down"
MARK = "0x6e6a"
PARENT_RATE = "10000mbit"
LOOP_SECONDS = 60
_OWNED = "njbw"


class BandwidthValueError(ValueError):
    pass


@dataclass
class Limit:
    key: str
    addresses: list[str]
    download_kbit: int | None
    upload_kbit: int | None
    minor: int = 0

    def fingerprint(self) -> tuple[Any, ...]:
        return (self.key, tuple(self.addresses), self.download_kbit, self.upload_kbit, self.minor)


@dataclass
class DevicePlan:
    name: str
    kind: str
    limits: list[Limit] = field(default_factory=list)


def mbps_to_kbit(mbps: int) -> int:
    """Decimal megabits: 1 Mbps = 1000 kbit/s."""
    return int(mbps) * 1000


def _positive_mbps(value: Any) -> int:
    if isinstance(value, bool) or isinstance(value, float):
        raise BandwidthValueError("bandwidth must be a positive integer")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise BandwidthValueError("bandwidth must be a positive integer") from exc
    if str(number) != str(value).strip() and not isinstance(value, int):
        raise BandwidthValueError("bandwidth must be a positive integer")
    if number < 1 or number > MAX_MBPS:
        raise BandwidthValueError("bandwidth out of range")
    return number


def _optional_mbps(value: Any, fallback: int | None) -> int | None:
    if value is None or value == "":
        return fallback
    return _positive_mbps(value)


def normalize_bandwidth(value: Any) -> dict[str, int | None] | None:
    """Return directional Mbps, or None when both directions are unlimited.

    A missing direction is unlimited unless ``mbps`` provides a shared fallback.
    """
    if value is None or value == "" or value == {}:
        return None
    if isinstance(value, bool):
        raise BandwidthValueError("bandwidth must be a positive integer")
    if isinstance(value, int) or (isinstance(value, str) and str(value).strip().isdigit()):
        mbps = _positive_mbps(value)
        return {"download_mbps": mbps, "upload_mbps": mbps}
    if not isinstance(value, dict):
        raise BandwidthValueError("bandwidth must be an object")

    shared = _optional_mbps(value.get("mbps"), None) if "mbps" in value else None
    if "download_mbps" not in value:
        download = shared
    else:
        download = _optional_mbps(value.get("download_mbps"), shared)
    if "upload_mbps" not in value:
        upload = shared
    else:
        upload = _optional_mbps(value.get("upload_mbps"), shared)
    if download is None and upload is None:
        return None
    return {"download_mbps": download, "upload_mbps": upload}


def ipv4_host(value: Any) -> str | None:
    host = str(value or "").split("/", 1)[0].strip()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def minor_for(key: str, used: set[int]) -> int:
    base = (zlib.crc32(key.encode()) % 9996) + 2
    minor = base
    while minor in used or minor in {1, 9999}:
        minor += 1
        if minor >= 9999:
            minor = 2
        if minor == base:
            raise BandwidthValueError("no free traffic class id")
    used.add(minor)
    return minor


def assign_minors(limits: list[Limit]) -> None:
    used: set[int] = set()
    for limit in sorted(limits, key=lambda item: item.key):
        limit.minor = minor_for(limit.key, used)


def _burst(kbit: int) -> str:
    amount = max(1600, (kbit * 1000 // 8) // 10)
    if amount >= 1024:
        return f"{max(1, amount // 1024)}k"
    return f"{amount}b"


def _class_tokens(device: str, minor: int, kbit: int) -> str:
    burst = _burst(kbit)
    return (
        f"class replace dev {device} parent 1:1 classid 1:{minor} "
        f"htb rate {kbit}kbit ceil {kbit}kbit burst {burst} cburst {burst}"
    )


def _has_root_qdisc(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("qdisc ") and " root" in f" {stripped}":
            return True
    return False


def _htb_root_lines(device: str, qdisc_text: str = "") -> list[str]:
    """Install HTB on the root hook without ``qdisc replace``.

    IFB and several other devices answer ``Change operation not supported by
    specified qdisc`` when the live root is pfifo_fast (or similar) and ``tc``
    tries to morph it into HTB. Delete the old root, then ``add`` HTB.
    """
    lines: list[str] = []
    if not _has_htb_root(qdisc_text):
        if _has_root_qdisc(qdisc_text):
            lines.append(f"qdisc del dev {device} root")
        lines.append(f"qdisc add dev {device} root handle 1: htb default 9999")
    lines.extend([
        f"class replace dev {device} parent 1: classid 1:1 htb rate {PARENT_RATE} ceil {PARENT_RATE}",
        f"class replace dev {device} parent 1:1 classid 1:9999 htb rate {PARENT_RATE} ceil {PARENT_RATE}",
    ])
    return lines


def _root_tokens(device: str, qdisc_text: str = "") -> list[str]:
    return _htb_root_lines(device, qdisc_text)


def peer_addresses(peer: dict[str, Any], extra: list[str] | None = None) -> list[str]:
    found: list[str] = []
    for raw in (peer.get("address"), peer.get("allowed_ips"), *(extra or [])):
        for part in str(raw or "").split(","):
            host = ipv4_host(part)
            if host and host not in found:
                found.append(host)
    return found


def limit_from_peer(peer: dict[str, Any], extra: list[str] | None = None) -> Limit | None:
    from agent.support import record_is_enabled

    if not isinstance(peer, dict) or not record_is_enabled(peer):
        return None
    try:
        bandwidth = normalize_bandwidth(peer.get("bandwidth"))
    except BandwidthValueError:
        log.warning("invalid bandwidth on client %s", peer.get("id") or peer.get("email"))
        return None
    if bandwidth is None:
        return None
    addresses = peer_addresses(peer, extra)
    if not addresses:
        return None
    download = bandwidth.get("download_mbps")
    upload = bandwidth.get("upload_mbps")
    key = str(peer.get("id") or peer.get("email") or addresses[0]).strip()
    if not key:
        return None
    return Limit(
        key=key,
        addresses=addresses,
        download_kbit=mbps_to_kbit(download) if download else None,
        upload_kbit=mbps_to_kbit(upload) if upload else None,
    )


def _merge_limits(limits: list[Limit]) -> list[Limit]:
    merged: dict[str, Limit] = {}
    for limit in limits:
        current = merged.get(limit.key)
        if current is None:
            merged[limit.key] = Limit(
                key=limit.key,
                addresses=list(limit.addresses),
                download_kbit=limit.download_kbit,
                upload_kbit=limit.upload_kbit,
                minor=limit.minor,
            )
            continue
        for address in limit.addresses:
            if address not in current.addresses:
                current.addresses.append(address)
        if current.download_kbit is None:
            current.download_kbit = limit.download_kbit
        if current.upload_kbit is None:
            current.upload_kbit = limit.upload_kbit
    rows = list(merged.values())
    if any(row.minor <= 0 for row in rows):
        assign_minors(rows)
    return rows


def collect_tunnel_plans(interfaces: list[dict[str, Any]]) -> list[DevicePlan]:
    plans: list[DevicePlan] = []
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        name = str(iface.get("name") or "").strip()
        if not name or name in {IFB_UP, IFB_DOWN}:
            continue
        limits = _merge_limits(
            [item for item in (limit_from_peer(peer) for peer in (iface.get("peers") or [])) if item is not None]
        )
        if limits:
            plans.append(DevicePlan(name=name, kind="tunnel", limits=limits))
    return plans


def collect_openvpn_plans(
    servers: list[dict[str, Any]],
    extra_addresses: dict[str, list[str]] | None = None,
) -> list[DevicePlan]:
    extras = extra_addresses or {}
    plans: list[DevicePlan] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        tun = str(server.get("tun_dev") or "").strip() or f"ovpn{server.get('id') or 0}"
        limits: list[Limit] = []
        for user in server.get("users") or []:
            if not isinstance(user, dict):
                continue
            username = str(user.get("username") or "").strip()
            extra = list(extras.get(username) or [])
            extra.extend(extras.get(str(user.get("id") or "")) or [])
            item = limit_from_peer(user, extra)
            if item is not None:
                limits.append(item)
        limits = _merge_limits(limits)
        if limits:
            plans.append(DevicePlan(name=tun, kind="tunnel", limits=limits))
    return plans


def collect_l2tp_plans(
    servers: list[dict[str, Any]],
    sessions: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[Limit], dict[str, list[tuple[str, Limit]]]]:
    """Return shared limits plus live PPP devices mapped to those limits."""
    limits: list[Limit] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        for user in server.get("users") or []:
            item = limit_from_peer(user if isinstance(user, dict) else {})
            if item is not None:
                limits.append(item)
    limits = _merge_limits(limits)
    by_ip = {address: limit for limit in limits for address in limit.addresses}
    devices: dict[str, list[tuple[str, Limit]]] = {}
    for ip, session in (sessions or {}).items():
        host = ipv4_host(ip)
        limit = by_ip.get(host or "")
        if limit is None or not isinstance(session, dict):
            continue
        iface = str(session.get("interface") or "").strip()
        if not iface.startswith("ppp"):
            continue
        devices.setdefault(iface, [])
        if not any(address == host for address, _item in devices[iface]):
            devices[iface].append((host or "", limit))
    return limits, devices


def filter_handle(minor: int, index: int, used: set[int] | None = None) -> int:
    """u32 node id in the default 800: hash table (1..0xfff).

    ``tc`` parses both the hash-table id and the node id as hexadecimal, and
    the node id must fit in 12 bits. A decimal token such as ``800::3654`` is
    read as ``0x3654`` (13908), which is rejected, so the HTB class is created
    and the classification filter is not.
    """
    slot = ((int(minor) * 17) + int(index)) % 0xFFE + 1
    taken = used if used is not None else set()
    start = slot
    while slot in taken or slot > 0xFFF:
        slot = slot % 0xFFE + 1
        if slot == start:
            raise BandwidthValueError("no free u32 filter handle")
    if used is not None:
        used.add(slot)
    return slot


def _handle_token(slot: int) -> str:
    node = int(slot)
    if node < 1 or node > 0xFFF:
        raise BandwidthValueError("u32 filter handle is outside the 12-bit node range")
    return f"800::{node:x}"


FILTER_PRIO = 10
HTB_FILTER_PARENT = "parent 1:0"
# clsact ingress filters attach at ffff:; some iproute2 builds reject the ``ingress`` alias.
CLSACT_INGRESS_PARENT = "parent ffff:"
CLSACT_INGRESS_ALT = "ingress"


def _ipv4_ip_match(address: str, direction: str) -> str:
    """High-level selector understood by all supported iproute2 builds."""
    return f"ip {direction} {address}/32"


def _ipv4_u32_match(address: str, direction: str) -> str:
    """Raw u32 selector at IPv4 destination (16) or source (12).

    Key and mask must be separate tokens; a single ``0a5a446c/ffffffff`` token
    is rejected by ``parse_u32`` even though ``tc filter show`` prints a slash.
    """
    offset = 16 if direction == "dst" else 12
    hexval = ipaddress.IPv4Address(address).packed.hex()
    return f"u32 {hexval} ffffffff at {offset}"


def _flowid_action(minor: int) -> str:
    return f"flowid 1:{minor}"


def _mirred_redirect_action(target: str) -> str:
    return f"action mirred egress redirect dev {target}"


def _ingress_redirect_add(device: str, address: str, *, target: str = IFB_UP) -> list[str]:
    """Install clsact ingress redirect (``parent ffff:``; ``ingress`` is a runtime fallback)."""
    match = _ipv4_ip_match(address, "src")
    action = _mirred_redirect_action(target)
    return [_filter_add(device, CLSACT_INGRESS_PARENT, match, action)]


def _filter_add(device: str, parent: str, match: str, action: str) -> str:
    """One u32 selector. The handle is left unset on purpose.

    ``tc filter add ... handle 800::node`` asks for a key inside hash table
    800. On current kernels that table id is only used for the first u32
    classifier, and a node id is rejected when the table is not already
    present (``Handle specified hash table address mismatch`` or an illegal
    handle). The HTB class command does not need that table, so the class is
    created and the filter is not. Omitting the handle makes ``tc`` create
    the root hash table and the key in the same command, which is the form
    documented by tc-u32(8).
    """
    return (
        f"filter add dev {device} {parent} protocol ip prio {FILTER_PRIO} "
        f"u32 match {match} {action}"
    )


def _filter_del(device: str, parent: str, handle: str) -> str:
    return (
        f"filter del dev {device} {parent} protocol ip prio {FILTER_PRIO} "
        f"handle {handle} u32"
    )


def _filter_lines(
    device: str,
    parent: str,
    slot: int,
    match: str,
    action: str,
    *,
    direction: str | None = None,
    address: str | None = None,
) -> list[str]:
    """Build filter add lines. Prefer raw u32 when ``direction`` and ``address`` are set."""
    del slot
    if direction and address:
        match = _ipv4_ip_match(address, direction)
    return [_filter_add(device, parent, match, action)]


def _purge_address_filters(
    device: str,
    text: str,
    address: str,
    *,
    mode: str,
) -> list[str]:
    """Drop prio-10 filters for one address so a broken rule cannot block reinstall."""
    lines: list[str] = []
    seen: set[str] = set()
    for item in _shown_filters(text):
        if item["pref"] != str(FILTER_PRIO):
            continue
        if _address_from_match(item["match"]) != address:
            continue
        if mode == "redirect":
            if not item["mirred"]:
                continue
        elif mode == "dst":
            if item["offset"] != "16" or item["mirred"]:
                continue
        elif mode == "src":
            if item["offset"] != "12" or item["mirred"]:
                continue
        else:
            continue
        parent = _delete_parent(item["parent"])
        line = _filter_del(device, parent, item["handle"])
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return lines


def tunnel_commands(device: str, limits: list[Limit], previous: dict[str, Any] | None = None) -> list[str]:
    lines: list[str] = []
    prior = previous or {}
    old_root = list(prior.get("root_filters") or prior.get("root") or [])
    old_ingress = list(prior.get("ingress_filters") or prior.get("ingress") or [])
    old_classes = list(prior.get("classes") or [])
    downloads = [item for item in limits if item.download_kbit]
    uploads = [item for item in limits if item.upload_kbit]
    root_used: set[int] = set()
    ingress_used: set[int] = set()
    classes: list[int] = []
    if downloads:
        lines.extend(_root_tokens(device))
        for limit in downloads:
            classes.append(limit.minor)
            lines.append(_class_tokens(device, limit.minor, int(limit.download_kbit)))
            for index, address in enumerate(limit.addresses):
                slot = filter_handle(limit.minor, index, root_used)
                lines.extend(
                    _filter_lines(
                        device,
                        HTB_FILTER_PARENT,
                        slot,
                        "",
                        _flowid_action(limit.minor),
                        direction="dst",
                        address=address,
                    )
                )
        for minor in old_classes:
            if minor not in classes:
                lines.append(f"class del dev {device} classid 1:{minor}")
    elif old_root or old_classes:
        lines.append(f"qdisc del dev {device} root")
    if uploads:
        lines.append(f"qdisc replace dev {device} clsact")
        for limit in uploads:
            for index, address in enumerate(limit.addresses):
                slot = filter_handle(limit.minor, index, ingress_used)
                lines.extend(_ingress_redirect_add(device, address))
    elif old_ingress:
        lines.append(f"qdisc del dev {device} clsact")
    return lines


def ifb_commands(device: str, limits: list[Limit], *, direction: str) -> list[str]:
    selected = [item for item in limits if (item.upload_kbit if direction == "upload" else item.download_kbit)]
    if not selected:
        return [f"qdisc del dev {device} root"]
    lines = _root_tokens(device)
    match = "src" if direction == "upload" else "dst"
    used: set[int] = set()
    for limit in selected:
        kbit = int(limit.upload_kbit if direction == "upload" else limit.download_kbit)
        lines.append(_class_tokens(device, limit.minor, kbit))
        for index, address in enumerate(limit.addresses):
            slot = filter_handle(limit.minor, index, used)
            lines.extend(
                _filter_lines(
                    device,
                    HTB_FILTER_PARENT,
                    slot,
                    "",
                    _flowid_action(limit.minor),
                    direction=match,
                    address=address,
                )
            )
    return lines


def ppp_commands(device: str, bindings: list[tuple[str, Limit]]) -> list[str]:
    """Redirect one PPP session into the shared IFB classes.

    Download packets are marked before the redirect. The shaped packet is
    injected again and the mark lets it leave on this PPP device instead of
    looping. Upload packets are redirected on ingress and never use the mark.
    """
    lines = [
        f"qdisc replace dev {device} clsact",
        f"filter replace dev {device} egress protocol ip prio 1 handle 1 "
        f"fw mark {MARK} action gact ok",
    ]
    egress_used: set[int] = set()
    ingress_used: set[int] = set()
    for index, (address, limit) in enumerate(bindings):
        if limit.download_kbit:
            slot = filter_handle(limit.minor, index, egress_used)
            lines.extend(
                _filter_lines(
                    device,
                    "egress",
                    slot,
                    f"ip dst {address}/32",
                    f"action skbedit mark {MARK} pipe mirred egress redirect dev {IFB_DOWN}",
                )
            )
        if limit.upload_kbit:
            lines.extend(_ingress_redirect_add(device, address))
    return lines


def _has_htb_root(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("qdisc htb 1:") and " root" in f" {stripped}":
            return True
    return False


def _clsact_state(text: str) -> str:
    """``clsact``, legacy ``ingress``, or ``absent``."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("qdisc clsact"):
            return "clsact"
        if stripped.startswith("qdisc ingress"):
            return "ingress"
    return "absent"


_FLOW_ID = re.compile(r"flowid\s+(\S+)")
_U32_MATCH = re.compile(
    r"match\s+([0-9a-fA-F]{8})(?:/[0-9a-fA-F]+|\s+[0-9a-fA-F]+)\s+at\s+(\d+)",
    re.IGNORECASE,
)
_MIRRED_DEV = re.compile(r"\b(?:to\s+device|dev)\s+([A-Za-z0-9_.:-]+)", re.IGNORECASE)


def _shown_filters(text: str) -> list[dict[str, str]]:
    """Parse ``tc filter show`` into the key nodes, skipping hash-table headers."""
    found: list[dict[str, str]] = []
    for block in _filter_blocks(text):
        head = next((line.strip() for line in block.splitlines() if line.strip()), "")
        if not head.startswith("filter parent "):
            continue
        parts = head.split()
        parent = parts[2] if len(parts) > 2 else ""
        pref = ""
        handle = ""
        if "pref" in parts:
            pref = parts[parts.index("pref") + 1]
        if "fh" in parts:
            handle = parts[parts.index("fh") + 1]
        # A hash table is printed as ``fh 800:`` with no node. Deleting it removes every key.
        if "::" not in handle:
            continue
        flow = _FLOW_ID.search(block)
        match = _U32_MATCH.search(block)
        mirred = _MIRRED_DEV.search(block)
        found.append({
            "parent": parent,
            "pref": pref,
            "handle": handle,
            "flowid": flow.group(1) if flow else "",
            "match": match.group(1).lower() if match else "",
            "offset": match.group(2) if match else "",
            "mirred": mirred.group(1) if mirred else "",
        })
    return found


def _address_from_match(value: str) -> str | None:
    if len(value) != 8:
        return None
    try:
        return str(ipaddress.IPv4Address(bytes.fromhex(value)))
    except ValueError:
        return None


def _delete_parent(shown: str) -> str:
    if shown in {"ffff:", "ingress"} or shown.startswith("ffff:"):
        return "ingress" if shown in {"ffff:", "ingress"} else f"parent {shown}"
    if shown.startswith("1:"):
        return "parent 1:"
    return f"parent {shown}" if shown else "parent 1:"


def _obsolete_filter_deletes(
    device: str,
    text: str,
    *,
    mode: str,
    keep: set[str],
) -> list[str]:
    """Delete prio-10 filters of one kind whose address is no longer shaped.

    ``mode`` is ``dst``, ``src``, or ``redirect``. Other kinds on the same
    device are left alone, so a download repair cannot remove an upload redirect.
    """
    lines: list[str] = []
    seen: set[str] = set()
    for item in _shown_filters(text):
        if item["pref"] != str(FILTER_PRIO):
            continue
        address = _address_from_match(item["match"])
        if address is None:
            continue
        if mode == "redirect":
            drop = bool(item["mirred"]) and item["mirred"] in {IFB_UP, IFB_DOWN} and address not in keep
        elif mode == "dst":
            drop = item["offset"] == "16" and not item["mirred"] and address not in keep
        elif mode == "src":
            drop = item["offset"] == "12" and not item["mirred"] and address not in keep
        else:
            drop = False
        if not drop:
            continue
        parent = _delete_parent(item["parent"])
        # clsact egress is not the ingress parent. Keep the printed parent for egress.
        if item["parent"].startswith("ffff:") and item["parent"] != "ffff:" and item["offset"] == "16":
            parent = f"parent {item['parent']}"
        line = _filter_del(device, parent, item["handle"])
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return lines


def repair_tunnel_commands(
    device: str,
    limits: list[Limit],
    *,
    qdisc_text: str,
    filter_text: str,
    previous: dict[str, Any] | None = None,
) -> list[str]:
    """Install missing objects without replacing a qdisc that is already correct.

    ``qdisc replace`` on an existing HTB root deletes every class and filter.
    A missing classifier is added on its own. A filter whose address is still
    in the plan is not deleted.
    """
    prior = previous or {}
    downloads = [item for item in limits if item.download_kbit]
    uploads = [item for item in limits if item.upload_kbit]
    lines: list[str] = []
    fresh_root = not _has_htb_root(qdisc_text)
    if downloads:
        if fresh_root:
            lines.extend(_htb_root_lines(device, qdisc_text))
        for limit in downloads:
            lines.append(_class_tokens(device, limit.minor, int(limit.download_kbit)))
            for address in limit.addresses:
                present = (not fresh_root) and filter_show_has(
                    filter_text, address, minor=limit.minor, kind="dst", parent="1:0",
                )
                if not present:
                    lines.extend(_purge_address_filters(
                        device, filter_text, address, mode="dst",
                    ))
                    lines.append(_filter_add(
                        device,
                        HTB_FILTER_PARENT,
                        _ipv4_ip_match(address, "dst"),
                        _flowid_action(limit.minor),
                    ))
        if not fresh_root:
            keep_dst = {address for limit in downloads for address in limit.addresses}
            lines.extend(_obsolete_filter_deletes(device, filter_text, mode="dst", keep=keep_dst))
            current = {item.minor for item in downloads}
            for minor in prior.get("classes") or []:
                if int(minor) not in current:
                    lines.append(f"class del dev {device} classid 1:{int(minor)}")
    elif not fresh_root and (prior.get("classes") or prior.get("root_filters") or prior.get("root")):
        lines.append(f"qdisc del dev {device} root")

    clsact = _clsact_state(qdisc_text)
    if uploads:
        rebuild_ingress = clsact != "clsact"
        if clsact != "clsact":
            # ``replace`` creates clsact or upgrades legacy ingress in one step.
            lines.append(f"qdisc replace dev {device} clsact")
        keep_redirect = {address for limit in uploads for address in limit.addresses}
        for limit in uploads:
            for address in limit.addresses:
                present = (not rebuild_ingress) and _redirect_present(
                    filter_text, address, IFB_UP,
                )
                if not present:
                    lines.extend(_purge_address_filters(
                        device, filter_text, address, mode="redirect",
                    ))
                    lines.extend(_ingress_redirect_add(device, address))
        if not rebuild_ingress:
            lines.extend(_obsolete_filter_deletes(
                device, filter_text, mode="redirect", keep=keep_redirect,
            ))
    elif clsact != "absent" and (prior.get("ingress_filters") or prior.get("ingress")):
        lines.append(f"qdisc del dev {device} clsact")
    return lines


def repair_ifb_commands(
    device: str,
    limits: list[Limit],
    *,
    direction: str,
    qdisc_text: str,
    filter_text: str,
) -> list[str]:
    selected = [item for item in limits if (item.upload_kbit if direction == "upload" else item.download_kbit)]
    fresh = not _has_htb_root(qdisc_text)
    if not selected:
        return [f"qdisc del dev {device} root"] if not fresh else []
    lines: list[str] = []
    if fresh:
        lines.extend(_htb_root_lines(device, qdisc_text))
    match = "src" if direction == "upload" else "dst"
    kind = "src" if direction == "upload" else "dst"
    for limit in selected:
        kbit = int(limit.upload_kbit if direction == "upload" else limit.download_kbit)
        lines.append(_class_tokens(device, limit.minor, kbit))
        for address in limit.addresses:
            present = (not fresh) and filter_show_has(
                filter_text, address, minor=limit.minor, kind=kind, parent="1:0",
            )
            if not present:
                lines.extend(_purge_address_filters(
                    device, filter_text, address, mode=kind,
                ))
                lines.append(_filter_add(
                    device,
                    HTB_FILTER_PARENT,
                    _ipv4_ip_match(address, match),
                    _flowid_action(limit.minor),
                ))
    if not fresh:
        keep = {address for limit in selected for address in limit.addresses}
        lines.extend(_obsolete_filter_deletes(
            device,
            filter_text,
            mode="src" if direction == "upload" else "dst",
            keep=keep,
        ))
    return lines


def repair_ppp_commands(
    device: str,
    bindings: list[tuple[str, Limit]],
    *,
    qdisc_text: str,
    filter_text: str,
) -> list[str]:
    """Same chain as ``ppp_commands``, without replacing clsact when it is already there."""
    if _clsact_state(qdisc_text) != "clsact":
        return ppp_commands(device, bindings)
    lines: list[str] = []
    if MARK not in filter_text:
        lines.append(
            f"filter add dev {device} egress protocol ip prio 1 handle 1 "
            f"fw mark {MARK} action gact ok"
        )
    for index, (address, limit) in enumerate(bindings):
        if limit.download_kbit and not _redirect_present(filter_text, address, IFB_DOWN):
            slot = filter_handle(limit.minor, index)
            lines.extend(_filter_lines(
                device,
                "egress",
                slot,
                f"ip dst {address}/32",
                f"action skbedit mark {MARK} pipe mirred egress redirect dev {IFB_DOWN}",
            ))
        if limit.upload_kbit and not _redirect_present(filter_text, address, IFB_UP):
            lines.extend(_ingress_redirect_add(device, address))
    return lines


def _status_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / "bandwidth" / "status.json"


def _state_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / "bandwidth" / "state.json"


def read_status(data_dir: str | Path) -> dict[str, Any]:
    path = _status_path(data_dir)
    if not path.is_file():
        return {
            "state": "pending",
            "download_mode": None,
            "upload_mode": None,
            "dependencies": {},
            "last_reconcile_at": None,
            "last_error": None,
            "clients": {},
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"state": "error", "last_error": "status file is unreadable"}
    return payload if isinstance(payload, dict) else {"state": "error", "last_error": "status file is invalid"}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _read_state(data_dir: str | Path) -> dict[str, Any]:
    path = _state_path(data_dir)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _client_status(limits: list[Limit], state: str, error: str | None, mode: str) -> dict[str, Any]:
    clients: dict[str, Any] = {}
    for limit in limits:
        clients[limit.key] = {
            "state": state,
            "download_mbps": None if limit.download_kbit is None else limit.download_kbit // 1000,
            "upload_mbps": None if limit.upload_kbit is None else limit.upload_kbit // 1000,
            "addresses": list(limit.addresses),
            "class_id": f"1:{limit.minor}",
            "download_mode": mode if limit.download_kbit else None,
            "upload_mode": "shape" if limit.upload_kbit else None,
            "last_error": error,
        }
    return clients


_lock: asyncio.Lock | None = None


def _reconcile_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def _run(args: list[str], *, timeout: float = 30) -> tuple[int, str]:
    from agent.support.process import run

    try:
        result = await run(args, timeout=timeout, check=False)
    except FileNotFoundError:
        return 127, f"missing command {args[0]}"
    except Exception as exc:
        return 1, str(exc)
    text = "\n".join(part for part in ((getattr(result, "stdout", None) or ""), (getattr(result, "stderr", None) or "")) if part).strip()
    return int(getattr(result, "returncode", 1) or 0), text


def _partition_batch(lines: list[str]) -> tuple[list[str], list[str]]:
    """Run every delete before any add/replace inside one reconcile pass."""
    cleanup: list[str] = []
    apply: list[str] = []
    for line in lines:
        if line.startswith(("filter del", "class del", "qdisc del")):
            cleanup.append(line)
        else:
            apply.append(line)
    return cleanup, apply


def _batch_failed(code: int, text: str) -> bool:
    if code != 0:
        return True
    if "RTNETLINK" in text or "Error" in text or "Command failed" in text:
        return True
    return False


def _object_absent(text: str) -> bool:
    folded = text.lower()
    return any(part in folded for part in (
        "no such file",
        "cannot find",
        "not found",
        "invalid handle",
        "no such device",
    ))


def _filter_add_fallbacks(line: str) -> list[str]:
    """Retry clsact parent spelling and raw u32 matches when ``tc`` rejects the first form."""
    if not line.startswith("filter add "):
        return [line]
    alts = [line]
    if "mirred egress redirect" in line:
        if CLSACT_INGRESS_PARENT in line:
            alts.append(line.replace(CLSACT_INGRESS_PARENT, CLSACT_INGRESS_ALT, 1))
        elif f" {CLSACT_INGRESS_ALT} " in f" {line} ":
            alts.append(line.replace(f" {CLSACT_INGRESS_ALT} ", f" {CLSACT_INGRESS_PARENT} ", 1))
    match = re.search(r"match ip (dst|src) (\d+\.\d+\.\d+\.\d+)/32", line)
    if match:
        direction, address = match.group(1), match.group(2)
        raw = _ipv4_u32_match(address, direction)
        alts.append(re.sub(r"match ip (?:dst|src) \d+\.\d+\.\d+\.\d+/32", f"match {raw}", line, count=1))
    seen: set[str] = set()
    ordered: list[str] = []
    for item in alts:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


async def _run_tc_lines(lines: list[str]) -> tuple[int, str]:
    """Run each tc command on its own and keep the failing command with its stderr.

    Deletes of an object that is already gone are not failures. A failed add,
    class, or qdisc is. Later lines still run, so one bad filter does not hide
    the result of the next command. Every delete is applied before any add so a
    stale handle from an earlier snapshot cannot remove a filter we just added.
    """
    if not lines:
        return 0, ""
    cleanup, apply = _partition_batch(lines)
    lines = cleanup + apply
    errors: list[str] = []
    for line in lines:
        optional = line.startswith(("filter del", "class del", "qdisc del"))
        attempts = _filter_add_fallbacks(line) if line.startswith("filter add ") else [line]
        last_code, last_text = 0, ""
        for attempt in attempts:
            last_code, last_text = await _run(["tc", *shlex.split(attempt)])
            if not _batch_failed(last_code, last_text):
                log.info("bandwidth tc ok: %s", attempt)
                break
            log.warning(
                "bandwidth tc failed code=%s line=%s output=%s",
                last_code,
                attempt,
                last_text[-500:],
            )
        else:
            if optional and (_object_absent(last_text) or not last_text):
                log.info("bandwidth tc delete skipped code=%s line=%s", last_code, line)
                continue
            errors.append(f"{attempts[-1]} (exit {last_code}): {last_text or 'tc failed'}")
            continue
        if optional:
            continue
    if errors:
        return 1, " | ".join(errors)[:800]
    return 0, ""


async def _run_batch(lines: list[str], *, strict: bool = True) -> tuple[int, str]:
    """Retained for the dependency probe. Enforcement uses ``_run_tc_lines``."""
    if not strict:
        for line in lines:
            await _run(["tc", *shlex.split(line)])
        return 0, ""
    return await _run_tc_lines(lines)


def _linux() -> bool:
    return sys.platform.startswith("linux")


_deps_cache: dict[str, Any] | None = None


async def ensure_dependencies(*, install: bool = False) -> dict[str, Any]:
    """Load the kernel pieces this shaper needs.

    Package installation runs only from agent startup or maintenance.
    A client provisioning request must never reach apt/dnf from here.
    Success is reported only after ``tc`` can show an HTB class on the IFB device.
    """
    global _deps_cache
    if _deps_cache is not None and _deps_cache.get("state") == "active":
        return dict(_deps_cache)
    if not _linux():
        return {"state": "unsupported", "error": "bandwidth shaping requires Linux", "tc": False, "ifb": False, "htb": False}
    if not shutil.which("tc"):
        if not install:
            return {
                "state": "error",
                "error": "tc (iproute2) is not installed; dependency installation runs at agent startup",
                "tc": False,
                "ifb": False,
                "htb": False,
            }
        installed = await _install_iproute()
        if not installed:
            return {"state": "error", "error": "tc (iproute2) is not installed", "tc": False, "ifb": False, "htb": False}
    for module in ("ifb", "sch_htb", "sch_ingress", "cls_u32", "act_mirred", "act_skbedit", "act_gact"):
        await _run(["modprobe", "-q", module], timeout=15)
    _persist_modules()
    for name in (IFB_UP, IFB_DOWN):
        code, text = await _run(["ip", "link", "add", name, "type", "ifb"])
        if code != 0 and "File exists" not in text and "exists" not in text.lower():
            return {"state": "unsupported", "error": f"IFB device {name} is unavailable: {text}", "tc": True, "ifb": False, "htb": False}
        await _run(["ip", "link", "set", name, "up"])
    probe_qdisc = await _tc_show(["tc", "qdisc", "show", "dev", IFB_UP])
    probe = _htb_root_lines(IFB_UP, probe_qdisc) + [
        f"class replace dev {IFB_UP} parent 1:1 classid 1:2 htb rate 1000kbit ceil 1000kbit",
    ]
    code, text = await _run_batch(probe)
    shown, shown_text = await _run(["tc", "class", "show", "dev", IFB_UP, "classid", "1:2"])
    await _run(["tc", "class", "del", "dev", IFB_UP, "classid", "1:2"])
    if code != 0 or shown != 0 or "htb" not in shown_text:
        detail = text or shown_text or "HTB probe failed"
        return {"state": "unsupported", "error": detail[-500:], "tc": True, "ifb": True, "htb": False}
    _deps_cache = {"state": "active", "error": None, "tc": True, "ifb": True, "htb": True}
    return dict(_deps_cache)


async def _install_iproute() -> bool:
    if shutil.which("apt-get"):
        code, _text = await _run(["apt-get", "install", "-y", "iproute2"], timeout=180)
        if code != 0:
            await _run(["apt-get", "update"], timeout=180)
            code, _text = await _run(["apt-get", "install", "-y", "iproute2"], timeout=180)
        return code == 0 and shutil.which("tc") is not None
    if shutil.which("dnf"):
        code, _text = await _run(["dnf", "install", "-y", "iproute"], timeout=180)
        return code == 0 and shutil.which("tc") is not None
    if shutil.which("yum"):
        code, _text = await _run(["yum", "install", "-y", "iproute"], timeout=180)
        return code == 0 and shutil.which("tc") is not None
    return False


def _persist_modules() -> None:
    path = Path("/etc/modules-load.d/netinja-bandwidth.conf")
    content = "# Managed by Netinja Agent — bandwidth shaping\n" + "\n".join(
        ["ifb", "sch_htb", "sch_ingress", "cls_u32", "act_mirred", "act_skbedit", "act_gact"]
    ) + "\n"
    try:
        if path.is_file() and path.read_text(encoding="utf-8") == content:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        log.warning("bandwidth module persistence skipped: %s", exc)


def _write_apply_script(data_dir: Path) -> Path:
    script = data_dir / "bandwidth" / "apply.sh"
    content = f"""#!/bin/sh
# Managed by Netinja Agent — reapply njbw qdiscs after interface up
IFACE="$1"
BATCH="{data_dir / "bandwidth" / "batches"}/$IFACE.batch"
if [ -n "$IFACE" ] && [ -f "$BATCH" ]; then
  tc -force -batch "$BATCH" >>"{data_dir / "bandwidth" / "apply.log"}" 2>&1 || true
fi
"""
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(content, encoding="utf-8")
    script.chmod(0o755)
    return script


def _ordered_batch_lines(lines: list[str]) -> list[str]:
    cleanup, apply = _partition_batch(lines)
    return cleanup + apply


def _write_batches(data_dir: Path, batches: dict[str, list[str]]) -> None:
    root = data_dir / "bandwidth" / "batches"
    root.mkdir(parents=True, exist_ok=True)
    wanted = set(batches)
    for path in root.glob("*.batch"):
        if path.stem not in wanted:
            path.unlink(missing_ok=True)
    for name, lines in batches.items():
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        ordered = _ordered_batch_lines(lines) if lines else []
        (root / f"{safe}.batch").write_text(("\n".join(ordered) + "\n") if ordered else "", encoding="utf-8")


def _ensure_upload_on_tunnel_limits(plan_limits: list[Limit], upload_limits: list[Limit]) -> list[Limit]:
    """Copy upload rates from the IFB plan when a tunnel row only carried download."""
    by_key = {item.key: item for item in upload_limits if item.upload_kbit}
    merged: list[Limit] = []
    for limit in plan_limits:
        if limit.upload_kbit or limit.key not in by_key:
            merged.append(limit)
            continue
        upl = by_key[limit.key]
        merged.append(
            Limit(
                key=limit.key,
                addresses=list(limit.addresses),
                download_kbit=limit.download_kbit,
                upload_kbit=upl.upload_kbit,
                minor=limit.minor or upl.minor,
            )
        )
    return merged


def _write_ppp_hook(data_dir: Path, limits: list[Limit]) -> None:
    if not _linux():
        return
    by_ip = {address: limit for limit in limits for address in limit.addresses}
    script = _ppp_up_script(by_ip)
    down = """#!/bin/sh
# Managed by Netinja Agent — drop njbw filters when the PPP device disappears
IFACE="$1"
if [ -n "$IFACE" ]; then
  tc qdisc del dev "$IFACE" clsact >/dev/null 2>&1 || true
fi
"""
    target_dir = data_dir / "bandwidth"
    target_dir.mkdir(parents=True, exist_ok=True)
    up_path = target_dir / "ppp-up.sh"
    down_path = target_dir / "ppp-down.sh"
    up_path.write_text(script, encoding="utf-8")
    down_path.write_text(down, encoding="utf-8")
    up_path.chmod(0o755)
    down_path.chmod(0o755)
    for folder, source in ((Path("/etc/ppp/ip-up.d"), up_path), (Path("/etc/ppp/ip-down.d"), down_path)):
        try:
            folder.mkdir(parents=True, exist_ok=True)
            hook = folder / "98-netinja-bandwidth"
            content = f"#!/bin/sh\n# Managed by Netinja Agent\nexec {source.as_posix()} \"$@\"\n"
            if not hook.is_file() or hook.read_text(encoding="utf-8") != content:
                hook.write_text(content, encoding="utf-8")
            hook.chmod(0o755)
        except OSError as exc:
            log.warning("bandwidth ppp hook install failed: %s", exc)


def _ppp_up_script(by_ip: dict[str, Limit]) -> str:
    blocks: list[str] = [
        "#!/bin/sh",
        "# Managed by Netinja Agent — one shared class per subscription across PPP sessions",
        'IFACE="$1"',
        'IP="$5"',
        'case "$IP" in',
    ]
    for address, limit in sorted(by_ip.items()):
        blocks.append(f"{address})")
        for line in ppp_commands('"$IFACE"', [(address, limit)]):
            blocks.append(f"  tc {line}")
        blocks.append("  ;;")
    blocks.extend(["esac", ""])
    return "\n".join(blocks)


def apply_script_path(data_dir: str | Path | None) -> Path:
    root = Path(data_dir or "/var/lib/agent")
    return root / "bandwidth" / "apply.sh"


def _fingerprint(plans: list[DevicePlan], l2tp: list[Limit], sessions: dict[str, list[tuple[str, Limit]]]) -> str:
    payload = {
        "tunnels": [
            {"name": plan.name, "limits": [limit.fingerprint() for limit in plan.limits]}
            for plan in plans
        ],
        "l2tp": [limit.fingerprint() for limit in l2tp],
        "sessions": {
            name: [(address, limit.key) for address, limit in rows]
            for name, rows in sorted(sessions.items())
        },
    }
    return json.dumps(payload, sort_keys=True)


def _ip_match_hex(address: str) -> str:
    return ipaddress.IPv4Address(address).packed.hex()


def _filter_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("filter ") and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks or [text]


def _block_has_address(block: str, address: str) -> bool:
    folded = block.lower().replace(" ", "")
    return _ip_match_hex(address) in folded or address in block


def _flowid_in_block(block: str, minor: int) -> bool:
    """Accept the class id spelling tc prints (hex) and the decimal minor."""
    lowered = block.lower()
    token = f"1:{int(minor)}"
    hex_token = f"1:{int(minor):x}"
    if hex_token in lowered or token in lowered:
        return True
    return f"classid {hex_token}" in lowered or f"classid {token}" in lowered


def _parent_matches(block: str, parent: str) -> bool:
    found = re.search(r"\bparent\s+(\S+)", block)
    if not found:
        return False
    shown = found.group(1)
    if parent in {"1:", "1:0"}:
        return shown in {"1:", "1:0"}
    if parent in {"ffff:", "ingress"}:
        return shown == "ffff:" or shown.startswith("ffff:")
    return shown == parent


def _redirect_present(text: str, address: str, target: str) -> bool:
    """True when this address is redirected to ``target`` in one filter block."""
    for block in _filter_blocks(text):
        if not _block_has_address(block, address):
            continue
        if target in block and "mirred" in block.lower():
            return True
    return False


def filter_show_has(
    text: str,
    address: str,
    *,
    minor: int | None = None,
    kind: str,
    parent: str | None = None,
) -> bool:
    """True when one filter block classifies this address.

    ``kind`` is ``dst`` (download flowid), ``src`` (upload flowid), or
    ``redirect`` (ingress mirred, no flowid). The address and the flowid must
    be in the same block so another client's filter cannot satisfy the check.
    ``parent`` is the qdisc parent printed by ``tc`` (``1:`` or ``ffff:``).
    A filter attached somewhere else does not count.
    """
    for block in _filter_blocks(text):
        if parent is not None and not _parent_matches(block, parent):
            continue
        if not _block_has_address(block, address):
            continue
        lowered = block.lower()
        if kind == "redirect":
            if "mirred" in lowered or IFB_UP in block or IFB_DOWN in block:
                return True
            continue
        if minor is None or not _flowid_in_block(block, minor):
            continue
        if kind == "dst" and ("at 16" in lowered or "dst" in lowered):
            return True
        if kind == "src" and ("at 12" in lowered or "src" in lowered):
            return True
    return False


async def _tc_show(args: list[str]) -> str:
    code, text = await _run(args)
    return text if code == 0 else ""


async def _class_present(device: str, minor: int) -> bool:
    text = await _tc_show(["tc", "class", "show", "dev", device, "classid", f"1:{minor}"])
    return f"1:{minor}" in text and "htb" in text


async def _filter_show(device: str, parent: list[str]) -> str:
    chunks: list[str] = []
    if parent:
        chunks.append(await _tc_show(["tc", "filter", "show", "dev", device, *parent]))
    chunks.append(await _tc_show(["tc", "filter", "show", "dev", device]))
    if parent == ["ingress"] or parent == ["parent", "ffff:"]:
        for extra in (["parent", "ffff:"], ["ingress"]):
            if parent != extra:
                chunks.append(await _tc_show(["tc", "filter", "show", "dev", device, *extra]))
    return "\n".join(part for part in chunks if part)


async def _device_snapshot(device: str) -> tuple[str, str]:
    qdisc = await _tc_show(["tc", "qdisc", "show", "dev", device])
    filters = await _filter_show(device, [])
    return qdisc, filters


def _check_detail(
    *,
    interface: str,
    parent: str,
    classid: str | None,
    match: str | None,
    observed: str,
) -> dict[str, Any]:
    return {
        "interface": interface,
        "parent": parent,
        "protocol": "ip",
        "priority": FILTER_PRIO,
        "classid": classid,
        "match": match,
        "observed": observed,
    }


async def _filters_present(device: str, limit: Limit, *, parent: list[str], kind: str) -> str | None:
    text = await _filter_show(device, parent)
    if parent == ["ingress"]:
        parent_token = "ffff:"
    else:
        parent_token = "1:0"
    for address in limit.addresses:
        if not filter_show_has(text, address, minor=limit.minor, kind=kind, parent=parent_token):
            where = " ".join(parent)
            direction = "dst" if kind == "dst" else "src"
            return (
                f"filter for {address} missing on {device} {where} "
                f"protocol ip prio {FILTER_PRIO} match ip {direction} {address}/32 "
                f"flowid 1:{limit.minor}"
            )
    return None


def resolve_enforcement_status(
    *,
    configured: bool,
    verified: bool,
    task: str | None = None,
    dependency_state: str | None = None,
    waiting: bool = False,
) -> str:
    """Kernel verification is the only path to ``active``.

    A stored plan, a status file, or a previous successful reconcile is not
    enough. ``waiting`` covers a shaped class whose PPP session is not up yet.
    """
    if not configured:
        return "unlimited"
    if dependency_state == "unsupported":
        return "unsupported"
    # A queued change is not active yet, even if an older class is still installed.
    if task == "running":
        return "installing"
    if task in {"queued", "pending"}:
        return "pending"
    if verified:
        return "active"
    if waiting:
        return "pending"
    return "error"


def _placements(
    tunnels: list[DevicePlan],
    l2tp_limits: list[Limit],
    l2tp_sessions: dict[str, list[tuple[str, Limit]]],
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for plan in tunnels:
        for limit in plan.limits:
            row = rows.setdefault(limit.key, {"limit": limit, "tunnels": [], "ppp": []})
            row["tunnels"].append(plan.name)
    l2tp_keys = {item.key for item in l2tp_limits}
    for limit in l2tp_limits:
        rows.setdefault(limit.key, {"limit": limit, "tunnels": [], "ppp": []})
    for name, bindings in l2tp_sessions.items():
        for _address, limit in bindings:
            if limit.key not in l2tp_keys and limit.key not in rows:
                continue
            row = rows.setdefault(limit.key, {"limit": limit, "tunnels": [], "ppp": []})
            if name not in row["ppp"]:
                row["ppp"].append(name)
    return rows


async def _verify_placement(row: dict[str, Any]) -> tuple[bool, str | None, bool]:
    """Read-only kernel check. The third value means the session is not up yet."""
    limit: Limit = row["limit"]
    tunnels: list[str] = list(row.get("tunnels") or [])
    ppp: list[str] = list(row.get("ppp") or [])
    objects: dict[str, bool | None] = {
        "download_class": None,
        "download_filter": None,
        "upload_class": None,
        "upload_filter": None,
        "ingress_redirect": None,
    }
    missing: list[str] = []
    details: dict[str, Any] = {}
    waiting = False
    if limit.download_kbit and tunnels:
        objects["download_class"] = True
        objects["download_filter"] = True
        for device in tunnels:
            if not await _class_present(device, limit.minor):
                objects["download_class"] = False
                details["download_class"] = _check_detail(
                    interface=device,
                    parent="1:1",
                    classid=f"1:{limit.minor}",
                    match=None,
                    observed="htb class not found",
                )
                missing.append(
                    f"download class 1:{limit.minor} missing on {device} parent 1:1"
                )
            reason = await _filters_present(device, limit, parent=["parent", "1:0"], kind="dst")
            if reason:
                objects["download_filter"] = False
                details["download_filter"] = _check_detail(
                    interface=device,
                    parent="1:0",
                    classid=f"1:{limit.minor}",
                    match=f"ip dst {limit.addresses[0]}/32" if limit.addresses else None,
                    observed="no u32 filter with that destination and flowid",
                )
                missing.append(reason)
    if limit.download_kbit and not tunnels:
        objects["download_class"] = await _class_present(IFB_DOWN, limit.minor)
        reason = await _filters_present(IFB_DOWN, limit, parent=["parent", "1:0"], kind="dst")
        objects["download_filter"] = reason is None
        if not objects["download_class"]:
            details["download_class"] = _check_detail(
                interface=IFB_DOWN, parent="1:1", classid=f"1:{limit.minor}", match=None,
                observed="htb class not found",
            )
            missing.append(f"download class 1:{limit.minor} missing on {IFB_DOWN} parent 1:1")
        if reason:
            details["download_filter"] = _check_detail(
                interface=IFB_DOWN, parent="1:0", classid=f"1:{limit.minor}",
                match=f"ip dst {limit.addresses[0]}/32" if limit.addresses else None,
                observed="no u32 filter with that destination and flowid",
            )
            missing.append(reason)
        if not ppp:
            waiting = True
            objects["ingress_redirect"] = False
        else:
            objects["ingress_redirect"] = True
            for device in ppp:
                text = await _filter_show(device, ["egress"])
                for address in limit.addresses:
                    if not _redirect_present(text, address, IFB_DOWN):
                        objects["ingress_redirect"] = False
                        details["ingress_redirect"] = _check_detail(
                            interface=device, parent="egress", classid=None,
                            match=f"ip dst {address}/32",
                            observed=f"mirred redirect to {IFB_DOWN} not found",
                        )
                        missing.append(
                            f"download redirect for {address} missing on {device} egress "
                            f"protocol ip prio {FILTER_PRIO} action mirred egress redirect dev {IFB_DOWN}"
                        )
    if limit.upload_kbit:
        objects["upload_class"] = await _class_present(IFB_UP, limit.minor)
        reason = await _filters_present(IFB_UP, limit, parent=["parent", "1:0"], kind="src")
        objects["upload_filter"] = reason is None
        if not objects["upload_class"]:
            details["upload_class"] = _check_detail(
                interface=IFB_UP, parent="1:1", classid=f"1:{limit.minor}", match=None,
                observed="htb class not found",
            )
            missing.append(f"upload class 1:{limit.minor} missing on {IFB_UP} parent 1:1")
        if reason:
            details["upload_filter"] = _check_detail(
                interface=IFB_UP, parent="1:0", classid=f"1:{limit.minor}",
                match=f"ip src {limit.addresses[0]}/32" if limit.addresses else None,
                observed="no u32 filter with that source and flowid",
            )
            missing.append(reason)
        redirects = tunnels or ppp
        if not redirects:
            waiting = True
            objects["ingress_redirect"] = False
        else:
            objects["ingress_redirect"] = True
            for device in redirects:
                text = await _filter_show(device, ["ingress"])
                for address in limit.addresses:
                    if not _redirect_present(text, address, IFB_UP):
                        objects["ingress_redirect"] = False
                        details["ingress_redirect"] = _check_detail(
                            interface=device, parent="ffff:", classid=None,
                            match=f"ip src {address}/32",
                            observed=f"mirred redirect to {IFB_UP} not found",
                        )
                        missing.append(
                            f"upload redirect for {address} missing on {device} ingress "
                            f"protocol ip prio {FILTER_PRIO} action mirred egress redirect dev {IFB_UP}"
                        )
    row["objects"] = objects
    row["details"] = details
    if missing:
        return False, "; ".join(missing), False
    if waiting:
        return False, "session interface is not up yet", True
    return True, None, False


async def _verified_clients(
    tunnels: list[DevicePlan],
    l2tp_limits: list[Limit],
    l2tp_sessions: dict[str, list[tuple[str, Limit]]],
    *,
    apply_error: str | None = None,
) -> tuple[dict[str, Any], bool]:
    clients: dict[str, Any] = {}
    all_ok = True
    for key, row in _placements(tunnels, l2tp_limits, l2tp_sessions).items():
        limit: Limit = row["limit"]
        verified, reason, waiting = await _verify_placement(row)
        if apply_error and not verified:
            reason = apply_error
            waiting = False
        state = resolve_enforcement_status(
            configured=True,
            verified=verified,
            waiting=waiting and not apply_error,
        )
        if state != "active":
            all_ok = False
        device = (row.get("tunnels") or row.get("ppp") or [IFB_UP if limit.upload_kbit else IFB_DOWN])[0]
        clients[key] = {
            "state": state,
            "verified": verified,
            "download_mbps": None if limit.download_kbit is None else limit.download_kbit // 1000,
            "upload_mbps": None if limit.upload_kbit is None else limit.upload_kbit // 1000,
            "addresses": list(limit.addresses),
            "class_id": f"1:{limit.minor}",
            "interface": device,
            "method": "htb_ifb" if limit.upload_kbit or not row.get("tunnels") else "htb",
            "download_mode": "shape" if limit.download_kbit else None,
            "upload_mode": "shape" if limit.upload_kbit else None,
            "objects": dict(row.get("objects") or {}),
            "details": dict(row.get("details") or {}),
            "last_error": None if verified else reason,
        }
    return clients, all_ok and bool(clients)


async def reconcile(
    *,
    data_dir: str | Path,
    tunnels: list[DevicePlan] | None = None,
    l2tp_limits: list[Limit] | None = None,
    l2tp_sessions: dict[str, list[tuple[str, Limit]]] | None = None,
) -> dict[str, Any]:
    """Make kernel classes match the desired subscription limits. Idempotent."""
    async with _reconcile_lock():
        return await _reconcile_locked(
            data_dir=data_dir,
            tunnels=tunnels or [],
            l2tp_limits=l2tp_limits or [],
            l2tp_sessions=l2tp_sessions or {},
        )


async def _reconcile_locked(
    *,
    data_dir: str | Path,
    tunnels: list[DevicePlan],
    l2tp_limits: list[Limit],
    l2tp_sessions: dict[str, list[tuple[str, Limit]]],
) -> dict[str, Any]:
    root = Path(data_dir)
    all_limits = [limit for plan in tunnels for limit in plan.limits]
    all_limits.extend(l2tp_limits)
    fingerprint = _fingerprint(tunnels, l2tp_limits, l2tp_sessions)
    previous = _read_state(root)
    if previous.get("fingerprint") == fingerprint and all_limits and _linux():
        clients, verified = await _verified_clients(tunnels, l2tp_limits, l2tp_sessions)
        if verified:
            status = read_status(root)
            status["state"] = "active"
            status["clients"] = clients
            status["last_error"] = None
            status["last_reconcile_at"] = int(time.time())
            _write_json(_status_path(root), status)
            return status

    if not all_limits and not previous:
        status = {
            "state": "idle",
            "download_mode": None,
            "upload_mode": None,
            "dependencies": {"tc": shutil.which("tc") is not None, "ifb": False, "htb": False},
            "last_reconcile_at": int(time.time()),
            "last_error": None,
            "clients": {},
            "note": "no limited subscriptions",
        }
        _write_json(_status_path(root), status)
        return status

    deps = await ensure_dependencies(install=False)
    if deps.get("state") != "active":
        status = {
            "state": deps.get("state") or "error",
            "download_mode": None,
            "upload_mode": None,
            "dependencies": {"tc": deps.get("tc"), "ifb": deps.get("ifb"), "htb": deps.get("htb")},
            "last_reconcile_at": int(time.time()),
            "last_error": deps.get("error"),
            "clients": _client_status(all_limits, str(deps.get("state") or "error"), deps.get("error"), "shape"),
        }
        _write_json(_status_path(root), status)
        return status

    upload_limits = _merge_limits([
        Limit(
            key=item.key,
            addresses=list(item.addresses),
            download_kbit=None,
            upload_kbit=item.upload_kbit,
            minor=item.minor,
        )
        for item in all_limits
        if item.upload_kbit
    ])
    download_limits = _merge_limits([
        Limit(
            key=item.key,
            addresses=list(item.addresses),
            download_kbit=item.download_kbit,
            upload_kbit=None,
            minor=item.minor,
        )
        for item in l2tp_limits
        if item.download_kbit
    ])

    batches: dict[str, list[str]] = {}
    errors: list[str] = []

    async def _apply(name: str, full: list[str], repair: list[str]) -> None:
        # The batch file is the full chain for a newly created interface.
        # The live reconcile only adds what is missing.
        batches[name] = full
        code, text = await _run_tc_lines(repair)
        if code != 0:
            errors.append(f"{name}: {text}")
            code, text = await _run_tc_lines(full)
            if code != 0:
                errors.append(f"{name} (full): {text}")

    if upload_limits:
        qdisc_text, filter_text = await _device_snapshot(IFB_UP)
        await _apply(
            IFB_UP,
            ifb_commands(IFB_UP, upload_limits, direction="upload"),
            repair_ifb_commands(
                IFB_UP, upload_limits, direction="upload",
                qdisc_text=qdisc_text, filter_text=filter_text,
            ),
        )
    if download_limits:
        qdisc_text, filter_text = await _device_snapshot(IFB_DOWN)
        await _apply(
            IFB_DOWN,
            ifb_commands(IFB_DOWN, download_limits, direction="download"),
            repair_ifb_commands(
                IFB_DOWN, download_limits, direction="download",
                qdisc_text=qdisc_text, filter_text=filter_text,
            ),
        )
    if not upload_limits and previous.get("ifb_up"):
        code, text = await _run_tc_lines([f"qdisc del dev {IFB_UP} root"])
        if code != 0:
            errors.append(f"{IFB_UP}: {text}")
    if not download_limits and previous.get("ifb_down"):
        code, text = await _run_tc_lines([f"qdisc del dev {IFB_DOWN} root"])
        if code != 0:
            errors.append(f"{IFB_DOWN}: {text}")

    owned = previous.get("devices") if isinstance(previous.get("devices"), dict) else {}
    seen: set[str] = set()
    for plan in tunnels:
        seen.add(plan.name)
        prior = owned.get(plan.name) if isinstance(owned.get(plan.name), dict) else {}
        prior = prior if isinstance(prior, dict) else {}
        qdisc_text, filter_text = await _device_snapshot(plan.name)
        limits = _ensure_upload_on_tunnel_limits(plan.limits, upload_limits)
        await _apply(
            plan.name,
            tunnel_commands(plan.name, limits, prior),
            repair_tunnel_commands(
                plan.name, limits,
                qdisc_text=qdisc_text, filter_text=filter_text, previous=prior,
            ),
        )
    for name, bindings in l2tp_sessions.items():
        seen.add(name)
        qdisc_text, filter_text = await _device_snapshot(name)
        await _apply(
            name,
            ppp_commands(name, bindings),
            repair_ppp_commands(name, bindings, qdisc_text=qdisc_text, filter_text=filter_text),
        )

    for name, meta in owned.items():
        if name in seen or name in {IFB_UP, IFB_DOWN}:
            continue
        if isinstance(meta, dict) and meta.get("owned") == _OWNED:
            code, text = await _run_tc_lines([
                f"qdisc del dev {name} clsact",
                f"qdisc del dev {name} root",
            ])
            if code != 0:
                errors.append(f"{name}: {text}")

    _write_apply_script(root)
    _write_batches(root, batches)
    _write_ppp_hook(root, l2tp_limits)

    apply_error = "; ".join(errors)[:800] or None
    if all_limits:
        clients, verified = await _verified_clients(
            tunnels,
            l2tp_limits,
            l2tp_sessions,
            apply_error=apply_error,
        )
    else:
        clients, verified = {}, True
    state_name = "active" if verified and not apply_error else ("idle" if not all_limits else "error")
    if state_name != "active" and not apply_error:
        apply_error = next(
            (str(row.get("last_error")) for row in clients.values() if row.get("last_error")),
            None,
        )
    status = {
        "state": state_name,
        "download_mode": "shape" if state_name == "active" else None,
        "upload_mode": "shape" if state_name == "active" else None,
        "dependencies": {"tc": True, "ifb": True, "htb": True},
        "last_reconcile_at": int(time.time()),
        "last_error": apply_error,
        "clients": clients,
    }
    devices_state: dict[str, Any] = {}
    for plan in tunnels:
        devices_state[plan.name] = {
            "owned": _OWNED,
            "classes": [item.minor for item in plan.limits if item.download_kbit],
            "root_filters": [
                filter_handle(item.minor, index)
                for item in plan.limits if item.download_kbit
                for index, _address in enumerate(item.addresses)
            ],
            "ingress_filters": [
                filter_handle(item.minor, index)
                for item in plan.limits if item.upload_kbit
                for index, _address in enumerate(item.addresses)
            ],
        }
    for name in l2tp_sessions:
        devices_state[name] = {"owned": _OWNED, "root": [], "ingress": []}
    _write_json(_state_path(root), {
        "fingerprint": fingerprint if state_name == "active" else None,
        "probed": state_name == "active",
        "ifb_up": bool(upload_limits),
        "ifb_down": bool(download_limits),
        "devices": devices_state,
    })
    _write_json(_status_path(root), status)
    if status.get("state") not in {"active", "idle"}:
        log.error("bandwidth reconcile error: %s", status["last_error"])
    else:
        log.info("bandwidth reconcile state=%s clients=%s", status.get("state"), len(all_limits))
    return status


async def reconcile_tunnels(interfaces: list[dict[str, Any]], *, data_dir: str | Path) -> dict[str, Any]:
    return await reconcile(data_dir=data_dir, tunnels=collect_tunnel_plans(interfaces))


async def reconcile_openvpn(
    servers: list[dict[str, Any]],
    *,
    data_dir: str | Path,
    extra_addresses: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    return await reconcile(
        data_dir=data_dir,
        tunnels=collect_openvpn_plans(servers, extra_addresses),
    )


async def reconcile_l2tp(
    servers: list[dict[str, Any]],
    sessions: dict[str, dict[str, Any]] | None,
    *,
    data_dir: str | Path,
) -> dict[str, Any]:
    limits, devices = collect_l2tp_plans(servers, sessions)
    return await reconcile(data_dir=data_dir, l2tp_limits=limits, l2tp_sessions=devices)


_runtime: tuple[Any, str] | None = None
_manager: BandwidthManager | None = None


def get_manager() -> BandwidthManager | None:
    return _manager


def reset_runtime_for_tests() -> None:
    """Drop the process-wide manager so tests do not leak into each other."""
    global _runtime, _manager, _deps_cache
    _runtime = None
    _manager = None
    _deps_cache = None


def configure_runtime(registry: Any, data_dir: str | Path) -> BandwidthManager:
    global _runtime, _manager
    _runtime = (registry, str(data_dir))
    _manager = BandwidthManager(registry, Path(data_dir))
    return _manager


def _client_id(client: dict[str, Any] | str | None) -> str:
    if isinstance(client, str):
        return client.strip()
    if not isinstance(client, dict):
        return ""
    return str(client.get("id") or client.get("email") or client.get("username") or "").strip()


def core_supports_bandwidth(core: str | None) -> bool:
    """True only for the four cores that install traffic-control objects."""
    return str(core or "").strip().lower() in SHAPED_CORES


def _core_may_enqueue(core: str | None) -> bool:
    text = str(core or "").strip().lower()
    return text == "" or text in SHAPED_CORES


def unsupported_bandwidth_report() -> dict[str, Any]:
    """Diagnostics for a core that must not be shaped. Nothing is installed."""
    return {
        "configured": False,
        "status": "not_applicable",
        "applicable": False,
        "verified": False,
        "download_mbps": None,
        "upload_mbps": None,
        "method": None,
        "interface": None,
        "class_id": None,
        "last_error": None,
    }


def schedule_bandwidth(
    *client_ids: Any,
    core: str = "",
    interface: str = "",
    action: str = "reconcile",
) -> dict[str, Any] | None:
    """Queue a coalesced reconcile. This does not apply traffic control itself."""
    if not _core_may_enqueue(core):
        return {"status": "unsupported", "enqueued": False}
    manager = get_manager()
    if manager is None:
        return None
    ids = [str(item) for item in client_ids if item]
    if action == "remove" and ids:
        return manager.remove(ids[0], core=core, interface=interface)
    if action == "apply" and ids:
        return manager.apply({"id": ids[0]}, core=core, interface=interface)
    if ids and action == "update":
        return manager.update({"id": ids[0]}, core=core, interface=interface)
    if ids:
        return manager.update({"id": ids[0]}, core=core, interface=interface)
    return manager.reconcile()


def with_provisioning(payload: dict[str, Any], *client_ids: Any) -> dict[str, Any]:
    """Attach background-task state without waiting for it.

    ``provisioning_status`` describes the essential client configuration.
    Bandwidth failure stays in ``background_tasks`` and does not flip success.
    """
    manager = get_manager()
    status = "not_required"
    if manager is not None:
        status = manager.bandwidth_status([str(item) for item in client_ids if item])
    return {
        **payload,
        "provisioning_status": "completed",
        "background_tasks": {"bandwidth": status},
    }


async def reconcile_current() -> dict[str, Any] | None:
    """Queue a reconcile. Kept for callers that used to wait on traffic control."""
    manager = get_manager()
    if manager is None:
        return None
    return manager.reconcile()


async def reconcile_enabled(registry: Any, data_dir: str | Path) -> dict[str, Any]:
    """Rebuild every enabled non-Xray core from the agent store. Xray is not read."""
    tunnels: list[DevicePlan] = []
    l2tp_limits: list[Limit] = []
    l2tp_sessions: dict[str, list[tuple[str, Limit]]] = {}
    enabled = {key for key, _driver in registry.enabled_drivers()}
    if "wireguard" in enabled:
        driver = registry.get("wireguard")
        tunnels.extend(collect_tunnel_plans(await driver.list_interfaces()))
    if "amnezia" in enabled:
        driver = registry.get("amnezia")
        tunnels.extend(collect_tunnel_plans(await driver.list_interfaces()))
    if "openvpn" in enabled:
        driver = registry.get("openvpn")
        servers = await driver.list_servers()
        tunnels.extend(collect_openvpn_plans(servers, _openvpn_extra_addresses(driver, servers)))
    if "l2tp" in enabled:
        driver = registry.get("l2tp")
        servers = await driver.list_servers()
        try:
            sessions = await driver._collect_ppp_sessions()
        except Exception:
            sessions = {}
        l2tp_limits, l2tp_sessions = collect_l2tp_plans(servers, sessions)
    return await reconcile(
        data_dir=data_dir,
        tunnels=tunnels,
        l2tp_limits=l2tp_limits,
        l2tp_sessions=l2tp_sessions,
    )


def _openvpn_extra_addresses(driver: Any, servers: list[dict[str, Any]]) -> dict[str, list[str]]:
    from agent.support.openvpn_config import parse_status_v2

    grouped: dict[str, list[str]] = {}
    for server in servers:
        text = ""
        try:
            paths = driver._status_log_paths(server)
        except Exception:
            paths = []
        for path in paths:
            if path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    text = ""
                if text.strip():
                    break
        for row in parse_status_v2(text):
            username = str(row.get("username") or "").strip()
            host = ipv4_host(row.get("virtual_address"))
            if not username or not host:
                continue
            bucket = grouped.setdefault(username, [])
            if host not in bucket:
                bucket.append(host)
    return grouped


class BandwidthManager:
    """Desired-state bandwidth enforcement for every non-Xray core.

    Client APIs enqueue work here and return. One worker applies the store,
    so duplicate updates collapse into a single reconcile and a slow client
    does not hold the request that created it. The worker reads the store
    when it runs. A newer generation, a deletion, or a disable is what the
    next pass sees; an older queued payload is never applied.
    """

    def __init__(self, registry: Any, data_dir: str | Path, *, retry_delay: float | None = None) -> None:
        self.registry = registry
        self.data_dir = Path(data_dir)
        self.retry_delay = retry_delay
        self.generation = 0
        self._wake = asyncio.Event()
        self._tasks: dict[str, dict[str, Any]] = {}
        self._load_tasks()

    def _task_path(self) -> Path:
        return self.data_dir / "bandwidth" / "tasks.json"

    def _load_tasks(self) -> None:
        path = self._task_path()
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        rows = payload.get("tasks") if isinstance(payload, dict) else None
        if isinstance(rows, dict):
            self._tasks = {str(key): value for key, value in rows.items() if isinstance(value, dict)}
            self.generation = int(payload.get("generation") or 0)

    def _save_tasks(self) -> None:
        _write_json(self._task_path(), {"generation": self.generation, "tasks": self._tasks})

    def _enqueue(self, client_ids: list[str], *, action: str, core: str, interface: str) -> dict[str, Any]:
        if not _core_may_enqueue(core):
            return {"status": "unsupported", "generation": self.generation, "task": None}
        self.generation += 1
        now = time.time()
        ids = [item for item in client_ids if item] or ["*"]
        record: dict[str, Any] | None = None
        for cid in ids:
            current = self._tasks.get(cid)
            if current and current.get("status") == "queued" and current.get("action") == action:
                current["generation"] = self.generation
                current["updated_at"] = now
                current["core"] = core or current.get("core")
                current["interface"] = interface or current.get("interface")
                record = current
                continue
            record = {
                "task_type": "bandwidth",
                "action": action,
                "client_id": cid,
                "core": core or None,
                "interface": interface or None,
                "status": "queued",
                "retries": int((current or {}).get("retries") or 0) if current and current.get("status") == "failed" else 0,
                "duration_ms": None,
                "last_error": None,
                "generation": self.generation,
                "created_at": (current or {}).get("created_at") or now,
                "updated_at": now,
            }
            self._tasks[cid] = record
        self._save_tasks()
        self._wake.set()
        log.info(
            "bandwidth task queued action=%s clients=%s generation=%s",
            action,
            ",".join(ids),
            self.generation,
        )
        return {"status": "queued", "generation": self.generation, "task": record}

    def apply(self, client: dict[str, Any], *, core: str = "", interface: str = "") -> dict[str, Any]:
        return self._enqueue([_client_id(client)], action="apply", core=core, interface=interface)

    def update(self, client: dict[str, Any], *, core: str = "", interface: str = "") -> dict[str, Any]:
        return self._enqueue([_client_id(client)], action="update", core=core, interface=interface)

    def remove(self, client_id: str, *, core: str = "", interface: str = "") -> dict[str, Any]:
        return self._enqueue([str(client_id)], action="remove", core=core, interface=interface)

    def reconcile(self) -> dict[str, Any]:
        return self._enqueue([], action="reconcile", core="", interface="")

    def bandwidth_status(self, client_ids: list[str] | None = None) -> str:
        ids = [item for item in (client_ids or []) if item]
        rows: list[Any] = [self._tasks.get(cid) for cid in ids] if ids else []
        bulk = self._tasks.get("*")
        if isinstance(bulk, dict) and (not ids or bulk.get("status") in {"queued", "running", "failed"} or not any(rows)):
            rows.append(bulk)
        statuses = [str(row.get("status")) for row in rows if isinstance(row, dict)]
        if "running" in statuses:
            return "running"
        if "queued" in statuses or "pending" in statuses:
            return "pending"
        if "failed" in statuses:
            return "failed"
        if "completed" in statuses:
            return "completed"
        return "not_required"

    async def _run(self) -> dict[str, Any]:
        return await reconcile_enabled(self.registry, self.data_dir)

    async def get_status(
        self,
        client: dict[str, Any],
        *,
        interface: str | None = None,
        kind: str = "tunnel",
    ) -> dict[str, Any]:
        return await self.get_diagnostics(client, interface=interface, kind=kind)

    async def get_diagnostics(
        self,
        client: dict[str, Any],
        *,
        interface: str | None = None,
        kind: str = "tunnel",
    ) -> dict[str, Any]:
        cid = _client_id(client)
        task = self._tasks.get(cid) or self._tasks.get("*")
        report = await _diagnose_client(
            client,
            interface=interface,
            kind=kind,
            task=str(task.get("status")) if isinstance(task, dict) else None,
            data_dir=self.data_dir,
        )
        if isinstance(task, dict):
            report["task"] = {
                "type": task.get("task_type"),
                "action": task.get("action"),
                "status": task.get("status"),
                "retries": task.get("retries"),
                "duration_ms": task.get("duration_ms"),
                "last_error": task.get("last_error"),
                "created_at": task.get("created_at"),
                "updated_at": task.get("updated_at"),
                "core": task.get("core"),
                "interface": task.get("interface") or interface,
                "generation": task.get("generation"),
            }
        stored = read_status(self.data_dir)
        report["last_reconcile_at"] = stored.get("last_reconcile_at")
        clients = stored.get("clients") if isinstance(stored.get("clients"), dict) else {}
        stored_client = clients.get(cid) if isinstance(clients, dict) else None
        if isinstance(stored_client, dict) and not report.get("verified"):
            report["stored_state"] = stored_client.get("state")
            if stored_client.get("state") == "active" and report.get("status") not in {"pending", "installing", "unlimited"}:
                report["discrepancy"] = "stored state is active but the kernel check failed"
                report["status"] = "error"
                report["last_error"] = report.get("last_error") or report["discrepancy"]
        return report

    def requeue_unfinished(self) -> int:
        restored = 0
        now = time.time()
        for row in self._tasks.values():
            if row.get("status") in {"queued", "running"}:
                row["status"] = "queued"
                row["updated_at"] = now
                restored += 1
        if restored:
            self._save_tasks()
            self._wake.set()
        return restored

    async def serve(self, stop: asyncio.Event) -> None:
        try:
            deps = await ensure_dependencies(install=True)
            log.info("bandwidth dependencies state=%s error=%s", deps.get("state"), deps.get("error"))
        except Exception:
            log.exception("bandwidth dependency setup failed")
        restored = self.requeue_unfinished()
        if restored:
            log.info("bandwidth recovered unfinished tasks=%s", restored)
        self.reconcile()
        while not stop.is_set():
            if not self._wake.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=LOOP_SECONDS)
                except asyncio.TimeoutError:
                    self.reconcile()
                    continue
                if stop.is_set():
                    break
            await self._drain(stop)

    async def _drain(self, stop: asyncio.Event) -> None:
        while self._wake.is_set() and not stop.is_set():
            self._wake.clear()
            generation = self.generation
            started = time.perf_counter()
            self._mark_running(generation)
            try:
                status = await asyncio.wait_for(self._run(), timeout=90)
            except Exception as exc:
                duration = int((time.perf_counter() - started) * 1000)
                self._fail(generation, str(exc), duration)
                if self.generation == generation and not stop.is_set():
                    await self._retry(generation, stop)
                continue
            duration = int((time.perf_counter() - started) * 1000)
            if self.generation != generation or self._wake.is_set():
                log.info(
                    "bandwidth task superseded duration_ms=%s generation=%s current=%s",
                    duration,
                    generation,
                    self.generation,
                )
                self._wake.set()
                continue
            state = str((status or {}).get("state") or "error")
            if state == "error":
                self._fail(generation, str((status or {}).get("last_error") or "kernel verification failed"), duration)
                if self.generation == generation and not stop.is_set():
                    await self._retry(generation, stop)
                continue
            self._mark_finished(generation, "completed", duration, None)
            log.info(
                "bandwidth task completed duration_ms=%s state=%s generation=%s",
                duration,
                state,
                generation,
            )

    async def _retry(self, generation: int, stop: asyncio.Event) -> None:
        retries = 0
        for item in self._tasks.values():
            if item.get("generation") == generation:
                retries = max(retries, int(item.get("retries") or 0))
        if retries >= 3:
            return
        delay = self.retry_delay if self.retry_delay is not None else float(2 ** retries)
        for item in self._tasks.values():
            if item.get("generation") == generation and item.get("status") == "failed":
                item["retries"] = retries + 1
                item["status"] = "queued"
                item["updated_at"] = time.time()
        self._save_tasks()
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
            return
        except asyncio.TimeoutError:
            pass
        if self.generation == generation:
            self._wake.set()

    def _mark_running(self, generation: int) -> None:
        now = time.time()
        for item in self._tasks.values():
            if item.get("status") == "queued" and int(item.get("generation") or 0) <= generation:
                item["status"] = "running"
                item["updated_at"] = now
        self._save_tasks()

    def _mark_finished(self, generation: int, status: str, duration: int, error: str | None) -> None:
        now = time.time()
        for item in self._tasks.values():
            if item.get("status") == "running" and int(item.get("generation") or 0) <= generation:
                item["status"] = status
                item["duration_ms"] = duration
                item["last_error"] = error
                item["updated_at"] = now
        self._save_tasks()

    def _fail(self, generation: int, error: str, duration: int) -> None:
        self._mark_finished(generation, "failed", duration, error)
        log.error("bandwidth task failed generation=%s duration_ms=%s error=%s", generation, duration, error)


def _filter_handle_tokens(limit: Limit) -> list[str]:
    used: set[int] = set()
    return [_handle_token(filter_handle(limit.minor, index, used)) for index, _address in enumerate(limit.addresses)]


async def _diagnose_client(
    client: dict[str, Any],
    *,
    interface: str | None,
    kind: str,
    task: str | None,
    data_dir: str | Path | None,
) -> dict[str, Any]:
    """Read-only bandwidth section. This function never changes qdiscs."""
    from agent.support import record_is_enabled

    try:
        normalized = normalize_bandwidth(client.get("bandwidth") if isinstance(client, dict) else None)
    except BandwidthValueError as exc:
        return {
            "configured": True,
            "status": "error",
            "verified": False,
            "download_mbps": None,
            "upload_mbps": None,
            "method": None,
            "interface": interface,
            "last_error": str(exc),
        }
    if normalized is None:
        return {
            "configured": False,
            "status": "unlimited",
            "download_mbps": None,
            "upload_mbps": None,
            "verified": False,
            "method": None,
            "interface": interface,
            "class_id": None,
            "last_error": None,
        }
    download = normalized.get("download_mbps")
    upload = normalized.get("upload_mbps")
    report: dict[str, Any] = {
        "configured": True,
        "download_mbps": download,
        "upload_mbps": upload,
        "method": "htb_ifb" if upload or kind == "l2tp" else "htb",
        "interface": interface,
        "verified": False,
        "last_error": None,
    }
    if not record_is_enabled(client):
        report["status"] = resolve_enforcement_status(configured=True, verified=False, task=task, waiting=task not in {"running"})
        if task == "running":
            report["status"] = "installing"
        report["last_error"] = "client is disabled; bandwidth is not enforced"
        report["verified"] = False
        return report
    limit = limit_from_peer(client)
    if limit is None:
        report["status"] = "error"
        report["last_error"] = "bandwidth is configured but the client has no IPv4 address"
        return report
    limit = _merge_limits([limit])[0]
    report["class_id"] = f"1:{limit.minor}"
    report["filter_handles"] = _filter_handle_tokens(limit)
    label = f"njbw-{limit.minor}"
    if limit.download_kbit:
        report["download_class"] = label
    if limit.upload_kbit:
        report["upload_class"] = label
    if not _linux():
        report["status"] = resolve_enforcement_status(
            configured=True,
            verified=False,
            task=task,
            dependency_state="unsupported",
        )
        report["last_error"] = "bandwidth shaping requires Linux; kernel enforcement was not verified on this host"
        return report
    tunnels: list[DevicePlan] = []
    l2tp_limits: list[Limit] = []
    sessions: dict[str, list[tuple[str, Limit]]] = {}
    if kind == "l2tp":
        l2tp_limits = [limit]
        if interface and str(interface).startswith("ppp"):
            sessions[str(interface)] = [(limit.addresses[0], limit)]
    elif interface:
        tunnels = [DevicePlan(name=str(interface), kind="tunnel", limits=[limit])]
    clients, _ok = await _verified_clients(tunnels, l2tp_limits, sessions)
    row = clients.get(limit.key) or {}
    verified = bool(row.get("verified"))
    waiting = row.get("state") == "pending"
    report["verified"] = verified
    report["status"] = resolve_enforcement_status(
        configured=True,
        verified=verified,
        task=task,
        waiting=waiting,
    )
    report["interface"] = row.get("interface") or interface
    report["method"] = row.get("method") or report["method"]
    report["objects"] = dict(row.get("objects") or {})
    report["details"] = dict(row.get("details") or {})
    report["last_error"] = None if verified and report["status"] == "active" else row.get("last_error")
    if data_dir is not None:
        stored = read_status(data_dir)
        report["last_reconcile_at"] = stored.get("last_reconcile_at")
        tc_error = stored.get("last_error")
        if tc_error and not verified:
            live = str(report.get("last_error") or "")
            if str(tc_error) not in live:
                report["last_error"] = f"{live}; tc: {tc_error}" if live else str(tc_error)
    return report


async def diagnose_bandwidth(
    client: dict[str, Any],
    *,
    interface: str | None = None,
    kind: str = "tunnel",
) -> dict[str, Any]:
    manager = get_manager()
    if manager is not None:
        return await manager.get_diagnostics(client, interface=interface, kind=kind)
    return await _diagnose_client(client, interface=interface, kind=kind, task=None, data_dir=None)


async def bandwidth_reconcile_loop(registry: Any, settings: Any, stop: asyncio.Event) -> None:
    """Startup maintenance: install dependencies once, then drain desired state."""
    if get_manager() is None:
        configure_runtime(registry, settings.data_dir)
    manager = get_manager()
    if manager is None:
        return
    await manager.serve(stop)
