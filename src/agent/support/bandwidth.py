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


def _root_tokens(device: str) -> list[str]:
    return [
        f"qdisc replace dev {device} root handle 1: htb default 9999",
        f"class replace dev {device} parent 1: classid 1:1 htb rate {PARENT_RATE} ceil {PARENT_RATE}",
        f"class replace dev {device} parent 1:1 classid 1:9999 htb rate {PARENT_RATE} ceil {PARENT_RATE}",
    ]


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


def filter_handle(minor: int, index: int) -> int:
    """One handle per address. Replacing a single handle would drop the other addresses."""
    return minor * 100 + index


def tunnel_commands(device: str, limits: list[Limit], previous: dict[str, Any] | None = None) -> list[str]:
    lines: list[str] = []
    prior = previous or {}
    old_root = list(prior.get("root_filters") or prior.get("root") or [])
    old_ingress = list(prior.get("ingress_filters") or prior.get("ingress") or [])
    old_classes = list(prior.get("classes") or [])
    downloads = [item for item in limits if item.download_kbit]
    uploads = [item for item in limits if item.upload_kbit]
    root_filters: list[int] = []
    ingress_filters: list[int] = []
    classes: list[int] = []
    if downloads:
        lines.extend(_root_tokens(device))
        for limit in downloads:
            classes.append(limit.minor)
            lines.append(_class_tokens(device, limit.minor, int(limit.download_kbit)))
            for index, address in enumerate(limit.addresses):
                handle = filter_handle(limit.minor, index)
                root_filters.append(handle)
                lines.append(f"filter del dev {device} parent 1: protocol ip prio 10 handle {handle} u32")
                lines.append(
                    f"filter add dev {device} parent 1: protocol ip prio 10 handle {handle} "
                    f"u32 match ip dst {address}/32 flowid 1:{limit.minor}"
                )
        for handle in old_root:
            if handle not in root_filters:
                lines.append(f"filter del dev {device} parent 1: protocol ip prio 10 handle {handle} u32")
        for minor in old_classes:
            if minor not in classes:
                lines.append(f"class del dev {device} classid 1:{minor}")
    elif old_root or old_classes:
        lines.append(f"qdisc del dev {device} root")
    if uploads:
        lines.append(f"qdisc replace dev {device} clsact")
        for limit in uploads:
            for index, address in enumerate(limit.addresses):
                handle = filter_handle(limit.minor, index)
                ingress_filters.append(handle)
                lines.append(f"filter del dev {device} ingress protocol ip prio 10 handle {handle} u32")
                lines.append(
                    f"filter add dev {device} ingress protocol ip prio 10 handle {handle} "
                    f"u32 match ip src {address}/32 action mirred egress redirect dev {IFB_UP}"
                )
        for handle in old_ingress:
            if handle not in ingress_filters:
                lines.append(f"filter del dev {device} ingress protocol ip prio 10 handle {handle} u32")
    elif old_ingress:
        lines.append(f"qdisc del dev {device} clsact")
    return lines


def ifb_commands(device: str, limits: list[Limit], *, direction: str) -> list[str]:
    selected = [item for item in limits if (item.upload_kbit if direction == "upload" else item.download_kbit)]
    if not selected:
        return [f"qdisc del dev {device} root"]
    lines = _root_tokens(device)
    match = "src" if direction == "upload" else "dst"
    for limit in selected:
        kbit = int(limit.upload_kbit if direction == "upload" else limit.download_kbit)
        lines.append(_class_tokens(device, limit.minor, kbit))
        for index, address in enumerate(limit.addresses):
            handle = filter_handle(limit.minor, index)
            lines.append(f"filter del dev {device} parent 1: protocol ip prio 10 handle {handle} u32")
            lines.append(
                f"filter add dev {device} parent 1: protocol ip prio 10 handle {handle} "
                f"u32 match ip {match} {address}/32 flowid 1:{limit.minor}"
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
        "filter del dev " + device + " egress protocol ip prio 1 handle 1 fw",
        f"filter add dev {device} egress protocol ip prio 1 handle 1 "
        f"fw mark {MARK} action gact ok",
    ]
    for index, (address, limit) in enumerate(bindings):
        handle = filter_handle(limit.minor, index)
        if limit.download_kbit:
            lines.append(f"filter del dev {device} egress protocol ip prio 10 handle {handle} u32")
            lines.append(
                f"filter add dev {device} egress protocol ip prio 10 handle {handle} "
                f"u32 match ip dst {address}/32 "
                f"action skbedit mark {MARK} pipe mirred egress redirect dev {IFB_DOWN}"
            )
        if limit.upload_kbit:
            lines.append(f"filter del dev {device} ingress protocol ip prio 10 handle {handle} u32")
            lines.append(
                f"filter add dev {device} ingress protocol ip prio 10 handle {handle} "
                f"u32 match ip src {address}/32 action mirred egress redirect dev {IFB_UP}"
            )
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


async def _run_batch(lines: list[str]) -> tuple[int, str]:
    if not lines:
        return 0, ""
    script = "\n".join(lines) + "\n"
    directory = Path(os.environ.get("TMPDIR") or "/tmp")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"njbw-{os.getpid()}-{time.time_ns()}.batch"
    path.write_text(script, encoding="utf-8")
    try:
        code, text = await _run(["tc", "-force", "-batch", str(path)], timeout=60)
    finally:
        path.unlink(missing_ok=True)
    if code != 0 or "Error" in text or "error" in text.lower() and "RTNETLINK" in text:
        log.warning("bandwidth tc batch failed code=%s output=%s", code, text[-800:])
    return code, text


def _linux() -> bool:
    return sys.platform.startswith("linux")


async def ensure_dependencies() -> dict[str, Any]:
    """Install iproute2 and load the kernel pieces this shaper needs.

    Success is reported only after ``tc`` can show an HTB class on the IFB device.
    """
    if not _linux():
        return {"state": "unsupported", "error": "bandwidth shaping requires Linux", "tc": False, "ifb": False, "htb": False}
    if not shutil.which("tc"):
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
    probe = [
        f"qdisc replace dev {IFB_UP} root handle 1: htb default 9999",
        f"class replace dev {IFB_UP} parent 1: classid 1:1 htb rate {PARENT_RATE} ceil {PARENT_RATE}",
        "class replace dev " + IFB_UP + " parent 1:1 classid 1:2 htb rate 1000kbit ceil 1000kbit",
    ]
    code, text = await _run_batch(probe)
    shown, shown_text = await _run(["tc", "class", "show", "dev", IFB_UP, "classid", "1:2"])
    await _run(["tc", "class", "del", "dev", IFB_UP, "classid", "1:2"])
    if code != 0 or shown != 0 or "htb" not in shown_text:
        detail = text or shown_text or "HTB probe failed"
        return {"state": "unsupported", "error": detail[-500:], "tc": True, "ifb": True, "htb": False}
    return {"state": "active", "error": None, "tc": True, "ifb": True, "htb": True}


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
  tc -force -batch "$BATCH" >/dev/null 2>&1 || true
fi
"""
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(content, encoding="utf-8")
    script.chmod(0o755)
    return script


def _write_batches(data_dir: Path, batches: dict[str, list[str]]) -> None:
    root = data_dir / "bandwidth" / "batches"
    root.mkdir(parents=True, exist_ok=True)
    wanted = set(batches)
    for path in root.glob("*.batch"):
        if path.stem not in wanted:
            path.unlink(missing_ok=True)
    for name, lines in batches.items():
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        (root / f"{safe}.batch").write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


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


async def _probe_class(device: str, minor: int) -> bool:
    code, text = await _run(["tc", "class", "show", "dev", device, "classid", f"1:{minor}"])
    return code == 0 and f"1:{minor}" in text


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
    if previous.get("fingerprint") == fingerprint and previous.get("probed") is True and _linux():
        status = read_status(root)
        if status.get("state") == "active":
            return status

    if not all_limits and not previous:
        status = {
            "state": "active",
            "download_mode": "shape",
            "upload_mode": "shape",
            "dependencies": {"tc": shutil.which("tc") is not None, "ifb": False, "htb": False},
            "last_reconcile_at": int(time.time()),
            "last_error": None,
            "clients": {},
            "note": "no limited subscriptions",
        }
        _write_json(_status_path(root), status)
        return status

    deps = await ensure_dependencies()
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
        Limit(key=item.key, addresses=list(item.addresses), download_kbit=None, upload_kbit=item.upload_kbit)
        for item in all_limits
        if item.upload_kbit
    ])
    download_limits = _merge_limits([
        Limit(key=item.key, addresses=list(item.addresses), download_kbit=item.download_kbit, upload_kbit=None)
        for item in l2tp_limits
        if item.download_kbit
    ])

    batches: dict[str, list[str]] = {}
    errors: list[str] = []
    if upload_limits:
        lines = ifb_commands(IFB_UP, upload_limits, direction="upload")
        batches[IFB_UP] = lines
        code, text = await _run_batch(lines)
        if code != 0:
            errors.append(text[-400:] or f"{IFB_UP} batch failed")
    if download_limits:
        lines = ifb_commands(IFB_DOWN, download_limits, direction="download")
        batches[IFB_DOWN] = lines
        code, text = await _run_batch(lines)
        if code != 0:
            errors.append(text[-400:] or f"{IFB_DOWN} batch failed")
    if not upload_limits and previous.get("ifb_up"):
        await _run_batch([f"qdisc del dev {IFB_UP} root"])
    if not download_limits and previous.get("ifb_down"):
        await _run_batch([f"qdisc del dev {IFB_DOWN} root"])

    owned = previous.get("devices") if isinstance(previous.get("devices"), dict) else {}
    seen: set[str] = set()
    for plan in tunnels:
        seen.add(plan.name)
        prior = owned.get(plan.name) if isinstance(owned.get(plan.name), dict) else {}
        lines = tunnel_commands(plan.name, plan.limits, prior if isinstance(prior, dict) else {})
        batches[plan.name] = lines
        code, text = await _run_batch(lines)
        if code != 0:
            errors.append(f"{plan.name}: {(text or 'tc failed')[-300:]}")
    for name, bindings in l2tp_sessions.items():
        seen.add(name)
        lines = ppp_commands(name, bindings)
        batches[name] = lines
        code, text = await _run_batch(lines)
        if code != 0:
            errors.append(f"{name}: {(text or 'tc failed')[-300:]}")

    for name, meta in owned.items():
        if name in seen or name in {IFB_UP, IFB_DOWN}:
            continue
        if isinstance(meta, dict) and meta.get("owned") == _OWNED:
            await _run_batch([
                f"qdisc del dev {name} clsact",
                f"qdisc del dev {name} root",
            ])

    _write_apply_script(root)
    _write_batches(root, batches)
    _write_ppp_hook(root, l2tp_limits)

    probed = True
    probe_error = None
    sample = next((item for item in upload_limits), None) or next((item for item in download_limits), None)
    sample_device = IFB_UP if upload_limits else IFB_DOWN
    if tunnels and any(item.download_kbit for plan in tunnels for item in plan.limits):
        sample_device = tunnels[0].name
        sample = next(item for plan in tunnels for item in plan.limits if item.download_kbit)
    if sample is not None:
        probed = await _probe_class(sample_device, sample.minor)
        if not probed:
            probe_error = f"class 1:{sample.minor} missing on {sample_device}"
            errors.append(probe_error)

    state_name = "active" if probed and not errors else "error"
    status = {
        "state": state_name,
        "download_mode": "shape" if state_name == "active" else None,
        "upload_mode": "shape" if state_name == "active" else None,
        "dependencies": {"tc": True, "ifb": True, "htb": True},
        "last_reconcile_at": int(time.time()),
        "last_error": "; ".join(errors)[:800] or None,
        "clients": _client_status(all_limits, state_name, "; ".join(errors)[:400] or None, "shape"),
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
        "probed": probed and not errors,
        "ifb_up": bool(upload_limits),
        "ifb_down": bool(download_limits),
        "devices": devices_state,
    })
    _write_json(_status_path(root), status)
    if errors:
        log.error("bandwidth reconcile error: %s", status["last_error"])
    else:
        log.info("bandwidth reconcile active clients=%s", len(all_limits))
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


def configure_runtime(registry: Any, data_dir: str | Path) -> None:
    global _runtime
    _runtime = (registry, str(data_dir))


async def reconcile_current() -> dict[str, Any] | None:
    """Reconcile every enabled non-Xray core. No-op until the process configures it."""
    if _runtime is None:
        return None
    registry, data_dir = _runtime
    return await reconcile_enabled(registry, data_dir)


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


async def bandwidth_reconcile_loop(registry: Any, settings: Any, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await reconcile_enabled(registry, settings.data_dir)
        except Exception:
            log.exception("bandwidth reconcile loop failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=LOOP_SECONDS)
        except asyncio.TimeoutError:
            continue
