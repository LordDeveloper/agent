"""Host metrics for the authenticated system-status endpoint.

Bandwidth and packet rates are deltas of kernel counters. The first sample, a
counter reset (including a 32-bit wrap), a missing interface, or a gap that is
too small to measure returns null rates. Gauges such as memory and disk come
from the current sample only.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent import __version__

MIN_INTERVAL_SECONDS = 0.25
_PROC_ESCAPE = re.compile(r"\\([0-7]{3})")
_DISK_FS = {
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "zfs",
    "f2fs",
    "jfs",
    "reiserfs",
    "ntfs",
    "ntfs3",
    "vfat",
    "exfat",
}
_SKIP_ROOT_FS = {"tmpfs", "devtmpfs", "proc", "sysfs", "devpts", "cgroup", "cgroup2"}
_PROC_STATE = {
    "R": "running",
    "S": "sleeping",
    "D": "disk-sleep",
    "Z": "zombie",
    "T": "stopped",
    "t": "tracing-stop",
    "I": "idle",
    "X": "dead",
}

DiskUsageFn = Callable[[str], Any]


@dataclass(frozen=True)
class NetCounters:
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0


@dataclass(frozen=True)
class DiskSample:
    mount: str
    device: str | None
    fstype: str | None
    total_bytes: int
    used_bytes: int
    available_bytes: int


@dataclass(frozen=True)
class MemorySample:
    total_bytes: int
    used_bytes: int
    available_bytes: int


@dataclass(frozen=True)
class AgentSample:
    pid: int | None
    state: str | None
    cpu_seconds: float | None
    memory_rss_bytes: int | None
    threads: int | None
    uptime_seconds: float | None
    fd_count: int | None
    handle_count: int | None


@dataclass
class HostSample:
    cpu_idle: int | None = None
    cpu_total: int | None = None
    load: tuple[float, float, float] | None = None
    memory: MemorySample | None = None
    disks: list[DiskSample] = field(default_factory=list)
    net: dict[str, NetCounters] = field(default_factory=dict)
    tcp_established: int | None = None
    tcp_inuse: int | None = None
    udp_inuse: int | None = None
    sockets_used: int | None = None
    uptime_seconds: float | None = None
    agent: AgentSample | None = None


def _round(value: float | None, digits: int) -> float | None:
    if value is None:
        return None
    if value != value or value in (float("inf"), float("-inf")) or value < 0:
        return None
    return round(value, digits)


def _percent(used: int | None, total: int | None) -> float | None:
    if used is None or total is None or total <= 0 or used < 0:
        return None
    return _round(min(100.0, (used / total) * 100.0), 2)


def _rate(current: int, previous: int | None, elapsed: float | None) -> float | None:
    if previous is None or elapsed is None or elapsed <= 0:
        return None
    delta = current - previous
    if delta < 0:
        return None
    return delta / elapsed


def _mbps(bytes_per_sec: float | None) -> float | None:
    if bytes_per_sec is None:
        return None
    return _round((bytes_per_sec * 8.0) / 1_000_000.0, 3)


def _unescape_proc(value: str) -> str:
    return _PROC_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _cpu_times(text: str) -> tuple[int, int] | None:
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        parts = line.split()
        # user nice system idle iowait irq softirq steal [guest guest_nice]
        # guest is already included in user/nice — sum only the first 8.
        nums: list[int] = []
        for raw in parts[1:9]:
            try:
                nums.append(int(raw))
            except ValueError:
                return None
        if len(nums) < 4:
            return None
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        return idle, sum(nums)
    return None


def _loadavg(text: str) -> tuple[float, float, float] | None:
    parts = text.split()
    if len(parts) < 3:
        return None
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return None


def _meminfo(text: str) -> MemorySample | None:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        token = raw.strip().split()
        if not token:
            continue
        try:
            amount = int(token[0])
        except ValueError:
            continue
        if len(token) > 1 and token[1].lower() == "kb":
            amount *= 1024
        values[key.strip()] = amount

    total = values.get("MemTotal")
    if total is None or total < 0:
        return None
    available = values.get("MemAvailable")
    if available is None:
        available = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    if available < 0:
        return None
    available = min(available, total)
    return MemorySample(total_bytes=total, used_bytes=total - available, available_bytes=available)


def _parse_netdev(text: str) -> dict[str, NetCounters]:
    rows: dict[str, NetCounters] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        iface = name.strip()
        if not iface or iface.lower() in {"lo", "face"} or iface.lower().startswith("lo"):
            continue
        nums: list[int] = []
        valid = True
        for token in rest.split():
            try:
                nums.append(int(token))
            except ValueError:
                valid = False
                break
        if not valid or len(nums) < 16:
            continue
        rows[iface] = NetCounters(
            rx_bytes=nums[0],
            rx_packets=nums[1],
            rx_errors=nums[2],
            rx_dropped=nums[3],
            tx_bytes=nums[8],
            tx_packets=nums[9],
            tx_errors=nums[10],
            tx_dropped=nums[11],
        )
    return rows


def _sockstat(text: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        family = parts[0].rstrip(":").upper()
        index = 1
        while index + 1 < len(parts):
            key = parts[index]
            try:
                value = int(parts[index + 1])
            except ValueError:
                index += 1
                continue
            if family == "SOCKETS" and key == "used":
                found["sockets_used"] = found.get("sockets_used", 0) + value
            elif family == "TCP" and key == "inuse":
                found["tcp_inuse"] = found.get("tcp_inuse", 0) + value
            elif family == "UDP" and key == "inuse":
                found["udp_inuse"] = found.get("udp_inuse", 0) + value
            index += 2
    return found


def _snmp_established(text: str) -> int | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("Tcp:"):
            continue
        headers = line.split()
        if index + 1 >= len(lines) or not lines[index + 1].startswith("Tcp:"):
            continue
        values = lines[index + 1].split()
        try:
            column = headers.index("CurrEstab")
            return int(values[column])
        except (ValueError, IndexError):
            return None
    return None


def _count_tcp_established(text: str) -> int | None:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    count = 0
    saw_row = False
    for line in lines[1:] if lines[0].lower().startswith("sl") or "local_address" in lines[0] else lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        saw_row = True
        if parts[3] == "01":
            count += 1
    return count if saw_row or len(lines) > 1 else 0


def _relevant_mounts(text: str) -> list[tuple[str, str, str]]:
    chosen: dict[str, tuple[str, str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        device = _unescape_proc(parts[0])
        mount = _unescape_proc(parts[1])
        fstype = parts[2]
        if not mount.startswith("/"):
            continue
        if mount != "/" and (mount.startswith(("/proc", "/sys", "/dev", "/run", "/snap"))):
            continue
        include = fstype in _DISK_FS
        if fstype == "overlay":
            include = mount == "/"
        if mount == "/" and fstype not in _SKIP_ROOT_FS:
            include = True
        if not include:
            continue
        key = device or mount
        current = chosen.get(key)
        if current is None or len(mount) < len(current[1]):
            chosen[key] = (device, mount, fstype)
    rows = list(chosen.values())
    rows.sort(key=lambda row: (row[1] != "/", row[1]))
    return rows[:32]


def _parse_proc_stat(text: str) -> tuple[int | None, str | None, int | None, int | None, int | None, int | None]:
    """Return pid, state, utime, stime, threads, rss pages from /proc/self/stat."""
    start = text.find("(")
    end = text.rfind(")")
    if start < 0 or end < start:
        return None, None, None, None, None, None
    try:
        pid = int(text[:start].strip())
    except ValueError:
        pid = None
    rest = text[end + 1 :].split()
    # rest[0] is state (field 3). utime is field 14.
    def at(field: int) -> int | None:
        index = field - 3
        if index < 0 or index >= len(rest):
            return None
        try:
            return int(rest[index])
        except ValueError:
            return None

    state = rest[0] if rest else None
    return pid, state, at(14), at(15), at(20), at(24)


def _status_value(text: str, key: str) -> str | None:
    prefix = key + ":"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def read_linux(proc: Path, disk_usage: DiskUsageFn = shutil.disk_usage) -> HostSample:
    sample = HostSample()
    stat_text = _read_text(proc / "stat")
    if stat_text:
        times = _cpu_times(stat_text)
        if times is not None:
            sample.cpu_idle, sample.cpu_total = times

    load_text = _read_text(proc / "loadavg")
    if load_text:
        sample.load = _loadavg(load_text)
    elif hasattr(os, "getloadavg"):
        try:
            sample.load = tuple(os.getloadavg())  # type: ignore[assignment]
        except OSError:
            sample.load = None

    mem_text = _read_text(proc / "meminfo")
    if mem_text:
        sample.memory = _meminfo(mem_text)

    mounts = _read_text(proc / "mounts")
    if mounts is None:
        mounts = _read_text(proc / "self" / "mounts")
    if mounts:
        disks: list[DiskSample] = []
        for device, mount, fstype in _relevant_mounts(mounts):
            try:
                usage = disk_usage(mount)
            except OSError:
                continue
            total = int(getattr(usage, "total", 0) or 0)
            used = int(getattr(usage, "used", 0) or 0)
            free = int(getattr(usage, "free", 0) or 0)
            if total < 0 or used < 0 or free < 0:
                continue
            disks.append(
                DiskSample(
                    mount=mount,
                    device=device or None,
                    fstype=fstype or None,
                    total_bytes=total,
                    used_bytes=used,
                    available_bytes=free,
                )
            )
        sample.disks = disks

    net_text = _read_text(proc / "net" / "dev")
    if net_text:
        sample.net = _parse_netdev(net_text)

    sockets: dict[str, int] = {}
    for name in ("sockstat", "sockstat6"):
        text = _read_text(proc / "net" / name)
        if not text:
            continue
        for key, value in _sockstat(text).items():
            sockets[key] = sockets.get(key, 0) + value
    if "tcp_inuse" in sockets:
        sample.tcp_inuse = sockets["tcp_inuse"]
    if "udp_inuse" in sockets:
        sample.udp_inuse = sockets["udp_inuse"]
    if "sockets_used" in sockets:
        sample.sockets_used = sockets["sockets_used"]

    established = None
    snmp = _read_text(proc / "net" / "snmp")
    if snmp:
        established = _snmp_established(snmp)
    tcp6 = _read_text(proc / "net" / "tcp6")
    v6 = _count_tcp_established(tcp6) if tcp6 is not None else None
    if established is None:
        tcp4 = _read_text(proc / "net" / "tcp")
        established = _count_tcp_established(tcp4) if tcp4 is not None else None
    if established is not None or v6 is not None:
        sample.tcp_established = (established or 0) + (v6 or 0)

    uptime_text = _read_text(proc / "uptime")
    uptime = None
    if uptime_text:
        token = uptime_text.split()
        try:
            uptime = float(token[0]) if token else None
        except ValueError:
            uptime = None
    sample.uptime_seconds = uptime if uptime is not None and uptime >= 0 else None

    sample.agent = _read_linux_agent(proc, uptime)
    return sample


def _clock_ticks() -> int:
    try:
        ticks = int(os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, AttributeError):
        ticks = 100
    return ticks if ticks > 0 else 100


def _page_size() -> int:
    try:
        size = int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, AttributeError):
        size = 4096
    return size if size > 0 else 4096


def _read_linux_agent(proc: Path, uptime: float | None) -> AgentSample | None:
    stat_text = _read_text(proc / "self" / "stat")
    status_text = _read_text(proc / "self" / "status")
    if stat_text is None and status_text is None:
        return None

    pid, state_code, utime, stime, threads, rss_pages = (None, None, None, None, None, None)
    if stat_text:
        pid, state_code, utime, stime, threads, rss_pages = _parse_proc_stat(stat_text)

    ticks = _clock_ticks()
    cpu_seconds = None
    if utime is not None and stime is not None:
        cpu_seconds = (utime + stime) / ticks

    rss = None
    if rss_pages is not None and rss_pages >= 0:
        rss = rss_pages * _page_size()
    if rss is None and status_text:
        raw = _status_value(status_text, "VmRSS")
        if raw:
            token = raw.split()
            try:
                rss = int(token[0]) * 1024
            except (ValueError, IndexError):
                rss = None

    if threads is None and status_text:
        raw_threads = _status_value(status_text, "Threads")
        if raw_threads:
            try:
                threads = int(raw_threads.split()[0])
            except (ValueError, IndexError):
                threads = None

    if pid is None and status_text:
        raw_pid = _status_value(status_text, "Pid")
        if raw_pid:
            try:
                pid = int(raw_pid.split()[0])
            except (ValueError, IndexError):
                pid = None

    agent_uptime = None
    if stat_text and uptime is not None:
        starttime = _proc_field(stat_text, 22)
        if starttime is not None:
            agent_uptime = uptime - (starttime / ticks)
            if agent_uptime < 0:
                agent_uptime = None

    fd_count = None
    fd_dir = proc / "self" / "fd"
    if fd_dir.is_dir():
        try:
            fd_count = sum(1 for _entry in fd_dir.iterdir())
        except OSError:
            fd_count = None

    state = _PROC_STATE.get(state_code or "", None)
    if state is None and pid is not None:
        state = "running"

    return AgentSample(
        pid=pid if pid is not None else os.getpid(),
        state=state,
        cpu_seconds=cpu_seconds,
        memory_rss_bytes=rss,
        threads=threads,
        uptime_seconds=agent_uptime,
        fd_count=fd_count,
        handle_count=None,
    )


def _proc_field(text: str, field_number: int) -> int | None:
    end = text.rfind(")")
    if end < 0:
        return None
    rest = text[end + 1 :].split()
    index = field_number - 3
    if index < 0 or index >= len(rest):
        return None
    try:
        return int(rest[index])
    except ValueError:
        return None


class RateTracker:
    """Process-local counter baseline. Not safe to share across processes."""

    def __init__(self) -> None:
        self.mono: float | None = None
        self.cpu_idle: int | None = None
        self.cpu_total: int | None = None
        self.net: dict[str, NetCounters] = {}
        self.agent_cpu: float | None = None
        self.last_rates: dict[str, Any] | None = None
        self.last_elapsed: float | None = None

    def reset(self) -> None:
        self.__init__()

    def consume(self, sample: HostSample, now: float) -> dict[str, Any]:
        elapsed: float | None
        if self.mono is None:
            elapsed = None
        elif now < self.mono:
            self.reset()
            elapsed = None
        else:
            elapsed = now - self.mono

        reuse = elapsed is not None and elapsed < MIN_INTERVAL_SECONDS and self.mono is not None
        if reuse and self.last_rates is not None:
            return _render(sample, self.last_rates, self.last_elapsed)

        rates = _compute_rates(sample, self, None if self.mono is None else elapsed)
        if self.mono is not None and elapsed is not None and elapsed >= MIN_INTERVAL_SECONDS:
            published = elapsed
        else:
            published = None
        self.last_rates = rates
        self.last_elapsed = published
        self.mono = now
        self.cpu_idle = sample.cpu_idle
        self.cpu_total = sample.cpu_total
        self.net = dict(sample.net)
        self.agent_cpu = sample.agent.cpu_seconds if sample.agent is not None else None
        return _render(sample, rates, published)


def _compute_rates(sample: HostSample, previous: RateTracker, elapsed: float | None) -> dict[str, Any]:
    cpu_percent = None
    if (
        elapsed is not None
        and elapsed >= MIN_INTERVAL_SECONDS
        and sample.cpu_idle is not None
        and sample.cpu_total is not None
        and previous.cpu_idle is not None
        and previous.cpu_total is not None
    ):
        total_delta = sample.cpu_total - previous.cpu_total
        idle_delta = sample.cpu_idle - previous.cpu_idle
        if total_delta > 0 and idle_delta >= 0 and idle_delta <= total_delta:
            cpu_percent = _round((1.0 - (idle_delta / total_delta)) * 100.0, 2)

    common = [name for name in sample.net if name in previous.net] if previous.net else []
    measurable = elapsed is not None and elapsed >= MIN_INTERVAL_SECONDS and bool(common)

    def direction(attr: str) -> float | None:
        if not measurable:
            return None
        total = 0
        for name in common:
            current = getattr(sample.net[name], attr)
            prior = getattr(previous.net[name], attr)
            if current < prior:
                return None
            total += current - prior
        return total / elapsed  # type: ignore[operator]

    rx_bps = direction("rx_bytes")
    tx_bps = direction("tx_bytes")
    rx_pps = direction("rx_packets")
    tx_pps = direction("tx_packets")

    per_iface: dict[str, dict[str, float | None]] = {}
    for name, counters in sample.net.items():
        prior = previous.net.get(name) if measurable else None
        rx_b = _rate(counters.rx_bytes, prior.rx_bytes if prior else None, elapsed if prior else None)
        tx_b = _rate(counters.tx_bytes, prior.tx_bytes if prior else None, elapsed if prior else None)
        rx_p = _rate(counters.rx_packets, prior.rx_packets if prior else None, elapsed if prior else None)
        tx_p = _rate(counters.tx_packets, prior.tx_packets if prior else None, elapsed if prior else None)
        per_iface[name] = {
            "rx_bytes_per_sec": _round(rx_b, 3),
            "tx_bytes_per_sec": _round(tx_b, 3),
            "rx_packets_per_sec": _round(rx_p, 3),
            "tx_packets_per_sec": _round(tx_p, 3),
            "rx_mbps": _mbps(rx_b),
            "tx_mbps": _mbps(tx_b),
        }

    agent_cpu = None
    if (
        elapsed is not None
        and elapsed >= MIN_INTERVAL_SECONDS
        and sample.agent is not None
        and sample.agent.cpu_seconds is not None
        and previous.agent_cpu is not None
    ):
        delta = sample.agent.cpu_seconds - previous.agent_cpu
        if delta >= 0:
            agent_cpu = _round((delta / elapsed) * 100.0, 2)
            if agent_cpu is not None and agent_cpu > 10000:
                agent_cpu = None

    return {
        "cpu_percent": cpu_percent,
        "rx_bytes_per_sec": _round(rx_bps, 3),
        "tx_bytes_per_sec": _round(tx_bps, 3),
        "rx_packets_per_sec": _round(rx_pps, 3),
        "tx_packets_per_sec": _round(tx_pps, 3),
        "rx_mbps": _mbps(rx_bps),
        "tx_mbps": _mbps(tx_bps),
        "interfaces": per_iface,
        "agent_cpu_percent": agent_cpu,
    }


def _render(sample: HostSample, rates: dict[str, Any], elapsed: float | None) -> dict[str, Any]:
    memory = None
    if sample.memory is not None:
        memory = {
            "total_bytes": sample.memory.total_bytes,
            "used_bytes": sample.memory.used_bytes,
            "available_bytes": sample.memory.available_bytes,
            "utilization_percent": _percent(sample.memory.used_bytes, sample.memory.total_bytes),
        }

    disks = [
        {
            "mount": disk.mount,
            "device": disk.device,
            "fstype": disk.fstype,
            "total_bytes": disk.total_bytes,
            "used_bytes": disk.used_bytes,
            "available_bytes": disk.available_bytes,
            "utilization_percent": _percent(disk.used_bytes, disk.total_bytes),
        }
        for disk in sample.disks
    ]

    iface_rates: dict[str, dict[str, Any]] = rates.get("interfaces") or {}
    interfaces = []
    rx_bytes = 0
    tx_bytes = 0
    rx_packets = 0
    tx_packets = 0
    for name in sorted(sample.net):
        counters = sample.net[name]
        rx_bytes += counters.rx_bytes
        tx_bytes += counters.tx_bytes
        rx_packets += counters.rx_packets
        tx_packets += counters.tx_packets
        rate = iface_rates.get(name) or {}
        interfaces.append(
            {
                "name": name,
                "rx_mbps": rate.get("rx_mbps"),
                "tx_mbps": rate.get("tx_mbps"),
                "rx_bytes": counters.rx_bytes,
                "tx_bytes": counters.tx_bytes,
                "rx_packets": counters.rx_packets,
                "tx_packets": counters.tx_packets,
                "rx_bytes_per_sec": rate.get("rx_bytes_per_sec"),
                "tx_bytes_per_sec": rate.get("tx_bytes_per_sec"),
                "rx_packets_per_sec": rate.get("rx_packets_per_sec"),
                "tx_packets_per_sec": rate.get("tx_packets_per_sec"),
                "rx_errors": counters.rx_errors,
                "tx_errors": counters.tx_errors,
                "rx_dropped": counters.rx_dropped,
                "tx_dropped": counters.tx_dropped,
            }
        )

    agent = None
    if sample.agent is not None:
        rss = sample.agent.memory_rss_bytes
        total = sample.memory.total_bytes if sample.memory is not None else None
        agent = {
            "version": __version__,
            "pid": sample.agent.pid,
            "state": sample.agent.state,
            "cpu_percent": rates.get("agent_cpu_percent"),
            "memory_rss_bytes": rss,
            "memory_percent": _percent(rss, total),
            "threads": sample.agent.threads,
            "uptime_seconds": _round(sample.agent.uptime_seconds, 3),
            "fd_count": sample.agent.fd_count,
            "handle_count": sample.agent.handle_count,
        }

    load = None
    if sample.load is not None:
        load = {
            "1": _round(sample.load[0], 2),
            "5": _round(sample.load[1], 2),
            "15": _round(sample.load[2], 2),
        }

    rates_ready = elapsed is not None and elapsed >= MIN_INTERVAL_SECONDS
    connections_present = any(
        value is not None
        for value in (sample.tcp_established, sample.tcp_inuse, sample.udp_inuse, sample.sockets_used)
    )

    return {
        "sampled_at": round(time.time(), 3),
        "interval_seconds": _round(elapsed, 3) if rates_ready else None,
        "rates_ready": rates_ready,
        "cpu": {
            "utilization_percent": rates.get("cpu_percent"),
            "load": load,
        },
        "memory": memory,
        "disks": disks,
        "network": {
            "rx_mbps": rates.get("rx_mbps"),
            "tx_mbps": rates.get("tx_mbps"),
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "interfaces": interfaces,
        },
        "traffic": {
            "rx_bytes_per_sec": rates.get("rx_bytes_per_sec"),
            "tx_bytes_per_sec": rates.get("tx_bytes_per_sec"),
            "rx_packets_per_sec": rates.get("rx_packets_per_sec"),
            "tx_packets_per_sec": rates.get("tx_packets_per_sec"),
            "rx_packets": rx_packets,
            "tx_packets": tx_packets,
        },
        "connections": {
            "tcp_established": sample.tcp_established,
            "tcp_inuse": sample.tcp_inuse,
            "udp_inuse": sample.udp_inuse,
            "sockets_used": sample.sockets_used,
        }
        if connections_present
        else None,
        "uptime_seconds": _round(sample.uptime_seconds, 3),
        "agent": agent,
    }


_tracker = RateTracker()
_lock = asyncio.Lock()


def reset_tracker() -> None:
    _tracker.reset()


def read_host_sample() -> HostSample:
    proc_stat = Path("/proc/stat")
    if proc_stat.is_file():
        return read_linux(Path("/proc"))
    if sys.platform == "win32":
        return _read_windows()
    return HostSample()


def collect_system_status_sync() -> dict[str, Any]:
    return _tracker.consume(read_host_sample(), time.monotonic())


async def collect_system_status() -> dict[str, Any]:
    async with _lock:
        return await asyncio.to_thread(collect_system_status_sync)


_windows_failures: set[str] = set()


def _guard_windows(name: str, fn: Callable[[], Any], default: Any) -> Any:
    try:
        return fn()
    except Exception as exc:
        if name not in _windows_failures:
            _windows_failures.add(name)
            from agent.logutil import get_logger

            get_logger("sysstatus").warning("system status %s unavailable: %s", name, exc)
        return default


def _read_windows() -> HostSample:
    sample = HostSample()
    cpu = _guard_windows("cpu", _windows_cpu, None)
    if cpu is not None:
        sample.cpu_idle, sample.cpu_total = cpu
    sample.memory = _guard_windows("memory", _windows_memory, None)
    sample.disks = _guard_windows("disks", _windows_disks, [])
    sample.net = _guard_windows("network", _windows_net, {})
    established, tcp_inuse, udp_inuse = _guard_windows(
        "connections",
        _windows_connections,
        (None, None, None),
    )
    sample.tcp_established = established
    sample.tcp_inuse = tcp_inuse
    sample.udp_inuse = udp_inuse
    sample.uptime_seconds = _guard_windows("uptime", _windows_uptime, None)
    sample.agent = _guard_windows("agent", _windows_agent, None)
    return sample


def _filetime_int(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _windows_kernel32() -> Any:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return ctypes, kernel32


def _windows_cpu() -> tuple[int, int] | None:
    try:
        ctypes, kernel32 = _windows_kernel32()

        class FILETIME(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", ctypes.c_uint32),
                ("dwHighDateTime", ctypes.c_uint32),
            ]

        idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
        if not kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        idle_v = _filetime_int(idle)
        # Kernel time includes idle time.
        total = _filetime_int(kernel) + _filetime_int(user)
        if total < idle_v:
            return None
        return idle_v, total
    except OSError:
        return None


def _windows_memory() -> MemorySample | None:
    try:
        ctypes, kernel32 = _windows_kernel32()

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(status)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        total = int(status.ullTotalPhys)
        available = int(status.ullAvailPhys)
        if total <= 0 or available < 0:
            return None
        available = min(available, total)
        return MemorySample(total_bytes=total, used_bytes=total - available, available_bytes=available)
    except OSError:
        return None


def _windows_disks() -> list[DiskSample]:
    try:
        ctypes, kernel32 = _windows_kernel32()
        kernel32.GetLogicalDrives.restype = ctypes.c_uint32
        kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetDriveTypeW.restype = ctypes.c_uint32
        mask = int(kernel32.GetLogicalDrives())
    except OSError:
        return []

    disks: list[DiskSample] = []
    for index in range(26):
        if mask & (1 << index) == 0:
            continue
        root = f"{chr(65 + index)}:\\"
        # DRIVE_FIXED = 3. Removable, remote, and optical volumes are skipped.
        if int(kernel32.GetDriveTypeW(root)) != 3:
            continue
        try:
            usage = shutil.disk_usage(root)
        except OSError:
            continue
        total = int(usage.total)
        used = int(usage.used)
        free = int(usage.free)
        if total < 0 or used < 0 or free < 0:
            continue
        disks.append(
            DiskSample(
                mount=root,
                device=root,
                fstype="fixed",
                total_bytes=total,
                used_bytes=used,
                available_bytes=free,
            )
        )
    return disks


def _windows_net() -> dict[str, NetCounters]:
    try:
        import ctypes

        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        iphlpapi.GetIfTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_int]
        iphlpapi.GetIfTable.restype = ctypes.c_ulong
        size = ctypes.c_ulong(0)
        error_insufficient = 122
        probe = int(iphlpapi.GetIfTable(None, ctypes.byref(size), False))
        if probe not in (0, error_insufficient) or size.value <= 0:
            return {}
        buffer = ctypes.create_string_buffer(size.value)
        if int(iphlpapi.GetIfTable(buffer, ctypes.byref(size), False)) != 0:
            return {}

        class MIB_IFROW(ctypes.Structure):
            _fields_ = [
                ("wszName", ctypes.c_wchar * 256),
                ("dwIndex", ctypes.c_ulong),
                ("dwType", ctypes.c_ulong),
                ("dwMtu", ctypes.c_ulong),
                ("dwSpeed", ctypes.c_ulong),
                ("dwPhysAddrLen", ctypes.c_ulong),
                ("bPhysAddr", ctypes.c_ubyte * 8),
                ("dwAdminStatus", ctypes.c_ulong),
                ("dwOperStatus", ctypes.c_ulong),
                ("dwLastChange", ctypes.c_ulong),
                ("dwInOctets", ctypes.c_ulong),
                ("dwInUcastPkts", ctypes.c_ulong),
                ("dwInNUcastPkts", ctypes.c_ulong),
                ("dwInDiscards", ctypes.c_ulong),
                ("dwInErrors", ctypes.c_ulong),
                ("dwInUnknownProtos", ctypes.c_ulong),
                ("dwOutOctets", ctypes.c_ulong),
                ("dwOutUcastPkts", ctypes.c_ulong),
                ("dwOutNUcastPkts", ctypes.c_ulong),
                ("dwOutDiscards", ctypes.c_ulong),
                ("dwOutErrors", ctypes.c_ulong),
                ("dwOutQLen", ctypes.c_ulong),
                ("dwDescrLen", ctypes.c_ulong),
                ("bDescr", ctypes.c_char * 256),
            ]

        count = int(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ulong))[0])
        row_size = ctypes.sizeof(MIB_IFROW)
        base_offset = ctypes.sizeof(ctypes.c_ulong)
        if count < 0 or count > 512 or base_offset + (count * row_size) > len(buffer):
            return {}
        base = ctypes.addressof(buffer) + base_offset
        candidates: list[tuple[str, NetCounters, int]] = []
        for index in range(count):
            row = MIB_IFROW.from_address(base + (index * row_size))
            # 24 = IF_TYPE_SOFTWARE_LOOPBACK
            if int(row.dwType) == 24:
                continue
            name = _windows_iface_name(row)
            if name is None or name.lower() in {"lo", "loopback"} or name.lower().startswith("loopback"):
                continue
            counters = NetCounters(
                rx_bytes=int(row.dwInOctets),
                tx_bytes=int(row.dwOutOctets),
                rx_packets=int(row.dwInUcastPkts) + int(row.dwInNUcastPkts),
                tx_packets=int(row.dwOutUcastPkts) + int(row.dwOutNUcastPkts),
                rx_errors=int(row.dwInErrors),
                tx_errors=int(row.dwOutErrors),
                rx_dropped=int(row.dwInDiscards),
                tx_dropped=int(row.dwOutDiscards),
            )
            candidates.append((name, counters, int(row.dwOperStatus)))
        return _dedupe_windows_interfaces(candidates)
    except OSError:
        return {}


_WINDOWS_FILTER_MARKERS = (
    "filter",
    "packet scheduler",
    "lightweight",
    "light weight",
    "wfp ",
    "virtual wifi",
    "native wifi",
    "mac layer",
    "npcap packet",
)


def _windows_filter_binding(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _WINDOWS_FILTER_MARKERS)


def _dedupe_windows_interfaces(candidates: list[tuple[str, NetCounters, int]]) -> dict[str, NetCounters]:
    """GetIfTable repeats one NIC once per NDIS filter. Count those bytes once."""
    groups: dict[Any, list[tuple[str, NetCounters, int]]] = {}
    for name, counters, oper in candidates:
        active = any(
            (
                counters.rx_bytes,
                counters.tx_bytes,
                counters.rx_packets,
                counters.tx_packets,
            )
        )
        key: Any = ("active", counters) if active else ("idle", name)
        groups.setdefault(key, []).append((name, counters, oper))

    selected: dict[str, NetCounters] = {}
    for items in groups.values():
        plain = [item for item in items if not _windows_filter_binding(item[0])]
        pool = plain or items
        pool.sort(key=lambda item: (0 if item[2] in {1, 5} else 1, len(item[0]), item[0]))
        name, counters, oper = pool[0]
        if not plain and _windows_filter_binding(name) and counters.rx_bytes == 0 and counters.tx_bytes == 0:
            continue
        unique = name
        suffix = 2
        while unique in selected and selected[unique] != counters:
            unique = f"{name} #{suffix}"
            suffix += 1
        selected[unique] = counters
        if len(selected) >= 64:
            break
    return selected


def _windows_text(value: str) -> str | None:
    name = value.split("\x00", 1)[0].strip()
    if not name or len(name) > 160:
        return None
    if any(ord(char) < 32 for char in name):
        return None
    return name


def _windows_iface_name(row: Any) -> str | None:
    description = None
    try:
        length = int(row.dwDescrLen)
    except (TypeError, ValueError):
        length = 0
    if 0 < length <= 256:
        description = _windows_text(bytes(row.bDescr[:length]).decode("mbcs", errors="replace"))

    device = _windows_text(str(row.wszName or ""))
    device_path = bool(device) and (device or "").lower().startswith("\\device\\")
    # wszName is an internal device path. The description is the adapter name.
    if description and (device_path or not device):
        return description
    return device or description


def _windows_table_count(fn: Any) -> int | None:
    import ctypes

    size = ctypes.c_ulong(0)
    error_insufficient = 122
    probe = int(fn(None, ctypes.byref(size), False))
    if probe == 0 and size.value <= 4:
        return 0
    if probe not in (0, error_insufficient) or size.value < 4:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if int(fn(buffer, ctypes.byref(size), False)) != 0:
        return None
    count = int(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ulong))[0])
    if count < 0:
        return None
    return count


def _windows_connections() -> tuple[int | None, int | None, int | None]:
    try:
        import ctypes

        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

        class MIB_TCPSTATS(ctypes.Structure):
            _fields_ = [
                ("dwRtoAlgorithm", ctypes.c_ulong),
                ("dwRtoMin", ctypes.c_ulong),
                ("dwRtoMax", ctypes.c_ulong),
                ("dwMaxConn", ctypes.c_ulong),
                ("dwActiveOpens", ctypes.c_ulong),
                ("dwPassiveOpens", ctypes.c_ulong),
                ("dwAttemptFails", ctypes.c_ulong),
                ("dwEstabResets", ctypes.c_ulong),
                ("dwCurrEstab", ctypes.c_ulong),
                ("dwInSegs", ctypes.c_ulong),
                ("dwOutSegs", ctypes.c_ulong),
                ("dwRetransSegs", ctypes.c_ulong),
                ("dwInErrs", ctypes.c_ulong),
                ("dwOutRsts", ctypes.c_ulong),
                ("dwNumConns", ctypes.c_ulong),
            ]

        stats = MIB_TCPSTATS()
        established = int(stats.dwCurrEstab) if int(iphlpapi.GetTcpStatistics(ctypes.byref(stats))) == 0 else None
        tcp_inuse = _windows_table_count(iphlpapi.GetTcpTable)
        udp_inuse = _windows_table_count(iphlpapi.GetUdpTable)
        return established, tcp_inuse, udp_inuse
    except OSError:
        return None, None, None


def _windows_uptime() -> float | None:
    try:
        _ctypes, kernel32 = _windows_kernel32()
        kernel32.GetTickCount64.restype = ctypes_ulonglong()
        ticks = int(kernel32.GetTickCount64())
    except OSError:
        return None
    if ticks < 0:
        return None
    return ticks / 1000.0


def ctypes_ulonglong() -> Any:
    import ctypes

    return ctypes.c_ulonglong


def _windows_agent() -> AgentSample | None:
    try:
        ctypes, kernel32 = _windows_kernel32()

        class FILETIME(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", ctypes.c_uint32),
                ("dwHighDateTime", ctypes.c_uint32),
            ]

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetCurrentProcessId.restype = ctypes.c_ulong
        kernel32.GetProcessTimes.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
        ]
        kernel32.GetProcessTimes.restype = ctypes.c_int
        kernel32.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(FILETIME)]
        kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel32.GetProcessHandleCount.restype = ctypes.c_int

        process = kernel32.GetCurrentProcess()
        pid = int(kernel32.GetCurrentProcessId())
        creation, _exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        cpu_seconds = None
        agent_uptime = None
        if kernel32.GetProcessTimes(
            process,
            ctypes.byref(creation),
            ctypes.byref(_exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            cpu_seconds = (_filetime_int(kernel_time) + _filetime_int(user_time)) / 10_000_000.0
            now = FILETIME()
            kernel32.GetSystemTimeAsFileTime(ctypes.byref(now))
            agent_uptime = (_filetime_int(now) - _filetime_int(creation)) / 10_000_000.0
            if agent_uptime < 0:
                agent_uptime = None

        rss = None
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            rss = int(counters.WorkingSetSize)

        handles = None
        handle_count = ctypes.c_ulong(0)
        if kernel32.GetProcessHandleCount(process, ctypes.byref(handle_count)):
            handles = int(handle_count.value)

        threads = _windows_thread_count(kernel32, ctypes, pid)
        return AgentSample(
            pid=pid,
            state="running",
            cpu_seconds=cpu_seconds,
            memory_rss_bytes=rss if rss is not None and rss >= 0 else None,
            threads=threads,
            uptime_seconds=agent_uptime,
            fd_count=None,
            handle_count=handles,
        )
    except OSError:
        return None


def _windows_thread_count(kernel32: Any, ctypes: Any, pid: int) -> int | None:
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ThreadID", ctypes.c_ulong),
            ("th32OwnerProcessID", ctypes.c_ulong),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
        ]

    th32cs_snapthread = 0x00000004
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    snapshot = kernel32.CreateToolhelp32Snapshot(th32cs_snapthread, 0)
    invalid = ctypes.c_void_p(-1).value
    if snapshot in (None, 0, invalid):
        return None
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
        kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
        kernel32.Thread32First.restype = ctypes.c_int
        kernel32.Thread32Next.restype = ctypes.c_int
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            return None
        count = 0
        while True:
            if int(entry.th32OwnerProcessID) == pid:
                count += 1
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
        return count
    finally:
        kernel32.CloseHandle(snapshot)
