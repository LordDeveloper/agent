"""Foreground volume / pending-queue monitor for CLI and menu debugging."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent.logutil import activity_log, resolve_log_path
from agent.tui import BOLD, CYAN, DIM, GREEN, RED, RESET, WHITE, YELLOW
from agent.traffic.service import (
    AGENT_META_CORE,
    LAST_SAMPLE_META_KEY,
    LAST_SAMPLE_TIMING_META_KEY,
    TrafficService,
)

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry
    from agent.runtime import Runtime

_LOG_FILTER = re.compile(r"(traffic|quota|pending|volume|ack|sample)", re.IGNORECASE)
_WATCH_TOP_PENDING = 10
_TIMING_META_KEYS = {
    "parallel_snapshot_ms",
    "cycle_ms",
    "sqlite_ms",
    "_sqlite_ms",
    "cursor_load_ms",
    "plan_ms",
    "write_ms",
    "chunk_count",
    "errors",
}


class _LiveScreen:
    """Overwrite the previous frame on TTYs instead of appending new blocks."""

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream or sys.stdout
        self._lines = 0
        self._tty = bool(getattr(self._stream, "isatty", lambda: False)())

    def draw(self, lines: list[str]) -> None:
        if not lines:
            return
        if self._tty:
            if self._lines > 0:
                self._stream.write(f"\033[{self._lines}A")
            for line in lines:
                self._stream.write("\033[2K\r" + line + "\n")
            for _ in range(max(0, self._lines - len(lines))):
                self._stream.write("\033[2K\n")
            self._stream.flush()
            self._lines = len(lines)
            return
        print("\n".join(lines), flush=True)

    def reset(self) -> None:
        self._lines = 0


def _format_bytes(value: int) -> str:
    n = max(0, int(value))
    if n < 1024:
        return f"{n} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    f = float(n)
    for unit in units:
        f /= 1024.0
        if f < 1024.0 or unit == units[-1]:
            return f"{f:.2f} {unit}"
    return f"{n} B"


async def _live_wireguard_counters(registry: CoreRegistry) -> dict[str, tuple[int, int]]:
    """Kernel cumulative totals from wg (not the SQLite pending queue)."""
    if "wireguard" not in set(registry.settings.cores()):
        return {}
    try:
        snapshot = await registry.usage_snapshot("wireguard")
    except Exception:
        return {}
    out: dict[str, tuple[int, int]] = {}
    for inbound in snapshot.inbounds or []:
        for client in inbound.clients or []:
            key = str(client.id or "").strip()
            if not key:
                continue
            out[key] = (int(client.incoming or 0), int(client.outgoing or 0))
    return out


async def collect_volume_billing_snapshot(
    traffic: TrafficService,
    settings: AgentSettings,
    *,
    pending_limit: int = 0,
    registry: CoreRegistry | None = None,
) -> dict[str, Any]:
    rows = await traffic.store.list_traffic_pending_all_scopes()
    panel_id_by_stored: dict[tuple[str, str], str] = {}
    for ident in await traffic.store.list_traffic_identity_all_scopes():
        core_name = str(ident.get("core") or "").strip()
        alias = str(ident.get("alias") or "").strip()
        canonical = str(ident.get("canonical_key") or "").strip()
        if core_name and alias and canonical:
            panel_id_by_stored[(core_name, alias)] = canonical
    chunks_by_client: dict[tuple[str, str, str], int] = {}
    pending_bytes = 0
    pending_chunk_count = 0
    wg_chunk_clients: set[str] = set()
    pending_by_core: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("scope") or ""),
            str(row.get("core") or ""),
            str(row.get("client_key") or ""),
        )
        count = int(row.get("chunk_count") or 0)
        chunk_bytes = int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0)
        if count <= 0 and chunk_bytes <= 0:
            continue
        chunks_by_client[key] = count
        pending_chunk_count += count
        pending_bytes += chunk_bytes
        core_name = key[1] or "—"
        bucket = pending_by_core.setdefault(
            core_name,
            {"clients": set(), "chunks": 0, "bytes": 0},
        )
        bucket["clients"].add((key[0], key[2]))
        bucket["chunks"] += count
        bucket["bytes"] += chunk_bytes
        if key[1] == "wireguard" and key[2] and count > 0:
            wg_chunk_clients.add(key[2])

    row_delta_bytes = sum(
        int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0) for row in rows
    )

    rows_sorted = sorted(
        rows,
        key=lambda row: int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
        reverse=True,
    )

    pending_last_touch = None
    for row in rows:
        touch = row.get("updated_at")
        if not touch:
            continue
        if pending_last_touch is None or str(touch) > str(pending_last_touch):
            pending_last_touch = touch

    snapshot_body: dict[str, Any] = {
        "pending_clients": len(chunks_by_client) or len(rows),
        "pending_chunks": pending_chunk_count,
        "pending_bytes": pending_bytes,
        "pending_bytes_label": _format_bytes(pending_bytes),
        "pending_last_touch": pending_last_touch,
        "worker_lag_ms": await traffic.last_sample_age_ms(),
        "last_sample_at": await traffic.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY),
        "sample_timing": await traffic.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_TIMING_META_KEY),
        "enforce_local_volume_quota": bool(settings.enforce_local_volume_quota),
        "traffic_sample_interval_s": float(settings.traffic_sample_interval),
        "quota_enforce_interval_s": float(settings.quota_enforce_interval),
        "pending_limit": max(0, int(pending_limit)),
        "billing_cores": list(settings.traffic_billing_cores()),
        "enabled_cores": list(settings.cores()),
        "config_bandwidth": [],
        "config_bandwidth_total": 0,
        "config_bandwidth_bytes": 0,
        "pending_by_core": {
            core: {
                "clients": len(item["clients"]),
                "chunks": int(item["chunks"]),
                "bytes": int(item["bytes"]),
                "label": _format_bytes(int(item["bytes"])),
            }
            for core, item in sorted(pending_by_core.items())
        },
    }
    top: list[dict[str, Any]] = []
    top_n = _WATCH_TOP_PENDING if pending_limit <= 0 else max(1, int(pending_limit))
    slice_end = min(len(rows_sorted), top_n)
    live_wg = await _live_wireguard_counters(registry) if registry is not None else {}
    kernel_ahead_bytes = 0
    wg_live_gap_bytes = 0
    if registry is not None and live_wg:
        for client_key, (live_down, live_up) in live_wg.items():
            stored = await traffic.store.get_client_traffic_cursor("wireguard", client_key)
            if stored is None:
                wg_live_gap_bytes += int(live_down) + int(live_up)
                continue
            counter_down, counter_up = stored
            delta_down = max(0, int(live_down) - int(counter_down))
            delta_up = max(0, int(live_up) - int(counter_up))
            wg_live_gap_bytes += delta_down + delta_up
            if client_key not in wg_chunk_clients:
                continue
            kernel_ahead_bytes += delta_down + delta_up

    for row in rows_sorted[:slice_end]:
        scope_name = str(row.get("scope") or "")
        core = str(row.get("core") or "")
        client_key = str(row.get("client_key") or "")
        panel_node_id = panel_id_by_stored.get((core, client_key), client_key)
        item: dict[str, Any] = {
            "scope": scope_name,
            "core": core,
            "client_key": client_key,
            "panel_node_id": panel_node_id,
            "downlink": int(row.get("delta_incoming") or 0),
            "uplink": int(row.get("delta_outgoing") or 0),
            "total": int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
            "chunk_count": int(chunks_by_client.get((scope_name, core, client_key), 0)),
            "updated_at": row.get("updated_at"),
        }
        top.append(item)

    snapshot_body["top_pending"] = top
    snapshot_body["pending_bytes_chunks"] = pending_bytes
    snapshot_body["pending_bytes_aggregate"] = row_delta_bytes
    snapshot_body["kernel_ahead_bytes"] = kernel_ahead_bytes
    snapshot_body["kernel_ahead_label"] = _format_bytes(kernel_ahead_bytes)
    snapshot_body["wg_live_gap_bytes"] = wg_live_gap_bytes
    snapshot_body["wg_live_gap_label"] = _format_bytes(wg_live_gap_bytes)
    snapshot_body["kernel_ahead_unreliable"] = (
        pending_bytes > 0 and kernel_ahead_bytes > max(pending_bytes * 20, 512 * 1024 * 1024)
    )
    usage = await traffic.store.list_client_bandwidth_all_scopes()
    usage_cap = None if int(pending_limit) <= 0 else max(1, int(pending_limit))
    snapshot_body["config_bandwidth_total"] = len(usage)
    snapshot_body["config_bandwidth_bytes"] = sum(int(row.get("total") or 0) for row in usage)
    snapshot_body["config_bandwidth"] = usage if usage_cap is None else usage[:usage_cap]
    return snapshot_body


def _filtered_activity_lines(since_seq: int) -> tuple[list[str], int]:
    payload = activity_log.since(since_seq)
    lines = [
        str(row.get("text") or "")
        for row in payload.get("lines") or []
        if _LOG_FILTER.search(str(row.get("text") or ""))
    ]
    return lines, int(payload.get("next") or since_seq)


class _AgentLogTail:
    """Follow agent.log lines written by the separate ``agent work`` process."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0
        if path.is_file():
            self._offset = path.stat().st_size

    def poll(self, limit: int = 40) -> list[str]:
        if not self._path.is_file():
            return []
        size = self._path.stat().st_size
        if size < self._offset:
            self._offset = 0
        if size <= self._offset:
            return []
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._offset)
            chunk = handle.read(size - self._offset)
            self._offset = size
        lines: list[str] = []
        for raw in chunk.splitlines():
            text = raw.strip()
            if not text or not _LOG_FILTER.search(text):
                continue
            lines.append(text)
        return lines[-max(1, limit) :]


def _snapshot_fingerprint(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    return (
        snapshot.get("pending_clients"),
        snapshot.get("pending_bytes"),
        snapshot.get("last_sample_at"),
        snapshot.get("pending_last_touch"),
    )


def _unchanged_note(snapshot: dict[str, Any]) -> str:
    lag = snapshot.get("worker_lag_ms")
    interval_s = float(snapshot.get("traffic_sample_interval_s") or 5.0)
    stale_ms = max(2000, int(interval_s * 2000))
    if isinstance(lag, int) and lag > stale_ms:
        return (
            f"unchanged — worker has not finished a sample in ~{lag // 1000}s; "
            "new usage is added only after sample_all writes SQLite (ack is not required to grow)"
        )
    clients = int(snapshot.get("pending_clients") or 0)
    if int(snapshot.get("kernel_ahead_bytes") or 0) > 0:
        return (
            f"unchanged pending totals — WireGuard kernel is +{snapshot.get('kernel_ahead_label')} "
            "ahead of last sample (wait for agent work, not a read lock)"
        )
    if clients > 0:
        return (
            "unchanged — no new bytes since last worker sample (GET/watch only read DB; "
            "POST ack shrinks billed bytes, it does not add usage)"
        )
    return "unchanged — queue empty or idle"


def _load_sample_timing(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        timing = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return timing if isinstance(timing, dict) else {}


def _core_timing_entries(timing: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    for key, value in sorted(timing.items()):
        if key in _TIMING_META_KEYS or not isinstance(value, dict):
            continue
        rows.append((str(key), value))
    return rows


def _short_core_name(core: str) -> str:
    return "wg" if core == "wireguard" else core


def _format_timing_summary(raw: Any) -> str | None:
    timing = _load_sample_timing(raw)
    if not timing and raw:
        return str(raw)
    if not timing:
        return None
    parallel = timing.get("parallel_snapshot_ms", timing.get("cycle_ms"))
    sqlite_ms = timing.get("_sqlite_ms", timing.get("sqlite_ms"))
    parts = [f"parallel={parallel}ms", f"sqlite={sqlite_ms}ms"]
    for key, value in _core_timing_entries(timing):
        short = _short_core_name(key)
        if value.get("error"):
            parts.append(f"{short}=FAIL")
            continue
        snap = value.get("snapshot_ms")
        if snap is None:
            continue
        clients = value.get("clients")
        if clients is not None:
            parts.append(f"{short}={snap}ms/{clients}c")
        else:
            parts.append(f"{short}={snap}ms")
    return "  sample  " + "  ".join(str(part) for part in parts if part is not None)


def _tone(text: str, *codes: str) -> str:
    return f"{''.join(codes)}{text}{RESET}"


def _clip(text: str, width: int) -> str:
    flat = " ".join(str(text).split())
    if len(flat) <= width:
        return flat
    if width <= 3:
        return flat[:width]
    return flat[: width - 3] + "..."


def _pad(text: str, width: int, align: str = "<") -> str:
    return f"{_clip(text, width):{align}{width}}"


def _heading(title: str) -> str:
    return f"  {_tone(title, BOLD, CYAN)}"


def _rule() -> str:
    return f"  {_tone('─' * 72, DIM)}"


def _snapshot_errors(raw: Any) -> list[tuple[str, str]]:
    timing = _load_sample_timing(raw)
    if not timing:
        return []
    errors: list[tuple[str, str]] = []
    bundled = timing.get("errors")
    if isinstance(bundled, dict):
        for core, message in sorted(bundled.items()):
            text = str(message or "").strip()
            if text:
                errors.append((str(core), text))
    for core, value in _core_timing_entries(timing):
        text = str(value.get("error") or "").strip()
        if not text:
            continue
        if any(name == core and msg == text for name, msg in errors):
            continue
        errors.append((core, text))
    return errors


def _sample_is_stale(snapshot: dict[str, Any]) -> bool:
    lag = snapshot.get("worker_lag_ms")
    interval_s = float(snapshot.get("traffic_sample_interval_s") or 2.0)
    stale_ms = max(30_000, int(interval_s * 15_000))
    return isinstance(lag, int) and lag > stale_ms


def _status_badge(snapshot: dict[str, Any], note: str | None) -> str:
    if _sample_is_stale(snapshot):
        return _tone("stale", BOLD, RED)
    if note:
        return _tone("idle", DIM)
    return _tone("live", BOLD, GREEN)


def _frame_alerts(snapshot: dict[str, Any]) -> list[str]:
    alerts: list[str] = []
    lag = snapshot.get("worker_lag_ms")
    if _sample_is_stale(snapshot) and isinstance(lag, int):
        alerts.append(f"Sample lag {lag // 1000}s. Pending grows only after a sample finishes.")
    unacked = int(snapshot.get("pending_bytes") or 0)
    clients = int(snapshot.get("pending_clients") or 0)
    if unacked >= 256 * 1024 * 1024 or clients >= 80:
        alerts.append(
            f"Backlog {snapshot.get('pending_bytes_label')} across {clients} clients is still waiting for ack."
        )
    billing = list(snapshot.get("billing_cores") or [])
    enabled = list(snapshot.get("enabled_cores") or [])
    if "wireguard" not in enabled and "amnezia" not in enabled:
        alerts.append("WireGuard and Amnezia are not in ENABLED_CORES, so those peers are not sampled.")
    elif "wireguard" in enabled and "wireguard" not in billing:
        alerts.append("WireGuard is enabled but excluded from volume sampling.")
    by_core = snapshot.get("pending_by_core") or {}
    wg_unacked = int((by_core.get("wireguard") or {}).get("bytes") or 0)
    amz_unacked = int((by_core.get("amnezia") or {}).get("bytes") or 0)
    wg_gap = int(snapshot.get("wg_live_gap_bytes") or 0)
    timing = _load_sample_timing(snapshot.get("sample_timing"))
    wg_sample = next((value for key, value in _core_timing_entries(timing) if key == "wireguard"), {})
    bundled = timing.get("errors") if isinstance(timing.get("errors"), dict) else {}
    wg_error = str(bundled.get("wireguard") or wg_sample.get("error") or "").strip()
    if wg_gap >= 512 * 1024 and wg_unacked == 0 and amz_unacked == 0:
        gap = snapshot.get("wg_live_gap_label")
        if "wireguard" not in billing:
            alerts.append(f"WireGuard live is {gap} ahead and WireGuard is not being sampled.")
        elif wg_error:
            alerts.append(f"WireGuard live is {gap} ahead. Snapshot failed: {wg_error}")
        else:
            alerts.append(f"WireGuard live is {gap} ahead, with nothing queued for WireGuard.")
    for core, message in _snapshot_errors(snapshot.get("sample_timing")):
        alerts.append(f"{core}: {message}")
    ahead = int(snapshot.get("kernel_ahead_bytes") or 0)
    if ahead > 0 and snapshot.get("kernel_ahead_unreliable"):
        alerts.append(f"WireGuard cursor looks desynced ({snapshot.get('kernel_ahead_label')}).")
    return alerts


def _format_top_pending_table(top: list[dict[str, Any]], total_clients: int) -> list[str]:
    if not top:
        return []
    shown = f"showing {len(top)} of {total_clients}" if len(top) != total_clients else f"{total_clients} clients"
    lines = [
        _heading("Pending"),
        f"  {_tone(shown, DIM)}",
        "  "
        + _tone(
            f"{'#':>3}  {'scope':<16}  {'core':<10}  {'node':<28}  {'down':>10}  {'up':>10}  {'total':>10}  {'ck':>4}",
            DIM,
        ),
    ]
    for index, row in enumerate(top, start=1):
        scope_name = _pad(str(row.get("scope") or "—"), 16)
        core = _pad(str(row.get("core") or "—"), 10)
        panel = _pad(str(row.get("panel_node_id") or row.get("client_key") or "—"), 28)
        down = _pad(_format_bytes(int(row.get("downlink") or 0)), 10, ">")
        up = _pad(_format_bytes(int(row.get("uplink") or 0)), 10, ">")
        total = _pad(_format_bytes(int(row.get("total") or 0)), 10, ">")
        chunks = f"{int(row.get('chunk_count') or 0):>4d}"
        lines.append(
            f"  {_tone(f'{index:>3}', DIM)}  {scope_name}  {_tone(core, CYAN)}  {panel}  "
            f"{down}  {up}  {_tone(total, WHITE)}  {chunks}"
        )
        return lines


def _format_config_bandwidth(rows: list[dict[str, Any]], total_count: int, total_bytes: int) -> list[str]:
    if total_count <= 0 or not rows:
        return []
    shown = (
        f"showing {len(rows)} of {total_count}"
        if len(rows) != total_count
        else f"{total_count} configs"
    )
    lines = [
        _heading("Bandwidth"),
        f"  {_tone(shown, DIM)}  {_tone(_format_bytes(total_bytes), YELLOW)}",
        "  "
        + _tone(
            f"{'#':>3}  {'scope':<16}  {'core':<10}  {'config':<28}  {'down':>10}  {'up':>10}  {'used':>10}",
            DIM,
        ),
    ]
    for index, row in enumerate(rows, start=1):
        lines.append(
            f"  {_tone(f'{index:>3}', DIM)}  {_pad(str(row.get('scope') or '—'), 16)}  "
            f"{_tone(_pad(str(row.get('core') or '—'), 10), CYAN)}  "
            f"{_pad(str(row.get('label') or row.get('client_key') or '—'), 28)}  "
            f"{_pad(_format_bytes(int(row.get('downlink') or 0)), 10, '>')}  "
            f"{_pad(_format_bytes(int(row.get('uplink') or 0)), 10, '>')}  "
            f"{_tone(_pad(_format_bytes(int(row.get('total') or 0)), 10, '>'), WHITE)}"
        )
    return lines


def format_volume_billing_frame(
    snapshot: dict[str, Any],
    log_lines: list[str],
    *,
    note: str | None = None,
) -> list[str]:
    del log_lines
    lag = snapshot.get("worker_lag_ms")
    lag_label = f"{lag} ms" if lag is not None else "—"
    clients = int(snapshot.get("pending_clients") or 0)
    chunks = int(snapshot.get("pending_chunks") or 0)
    unacked_label = str(snapshot.get("pending_bytes_label") or "0 B")
    quota = "on" if snapshot.get("enforce_local_volume_quota") else "off"
    last_sample = str(snapshot.get("last_sample_at") or "—")
    timing = _load_sample_timing(snapshot.get("sample_timing"))
    parallel = timing.get("parallel_snapshot_ms", timing.get("cycle_ms"))
    sqlite_ms = timing.get("_sqlite_ms", timing.get("sqlite_ms"))
    billing = list(snapshot.get("billing_cores") or [])
    enabled = list(snapshot.get("enabled_cores") or [])
    skipped = [core for core in enabled if core not in billing]

    out: list[str] = [
        "",
        f"  {_tone('VOLUME', BOLD, CYAN)}  {_tone(time.strftime('%H:%M:%S'), DIM)}  {_status_badge(snapshot, note)}",
        _rule(),
        _heading("Queue"),
        (
            f"    {_tone('clients', DIM)} {_tone(str(clients), WHITE)}"
            f"    {_tone('chunks', DIM)} {_tone(str(chunks), WHITE)}"
            f"    {_tone('unacked', DIM)} {_tone(unacked_label, YELLOW if clients else GREEN)}"
            f"    {_tone('lag', DIM)} {_tone(lag_label, RED if _sample_is_stale(snapshot) else WHITE)}"
        ),
        "",
        _heading("Sample"),
        (
            f"    {_tone('every', DIM)} {_tone(str(snapshot.get('traffic_sample_interval_s')) + 's', WHITE)}"
            f"    {_tone('quota', DIM)} {_tone(str(snapshot.get('quota_enforce_interval_s')) + 's', WHITE)}"
            f"    {_tone('local quota', DIM)} {_tone(quota, GREEN if quota == 'off' else YELLOW)}"
        ),
        (
            f"    {_tone('last', DIM)} {_tone(last_sample, WHITE)}"
            f"    {_tone('parallel', DIM)} {_tone('—' if parallel is None else f'{parallel} ms', WHITE)}"
            f"    {_tone('sqlite', DIM)} {_tone('—' if sqlite_ms is None else f'{sqlite_ms} ms', WHITE)}"
        ),
    ]
    if billing or skipped:
        sampled = ", ".join(billing) if billing else "none"
        skip_note = f"    {_tone('skipped', DIM)} {_tone(', '.join(skipped), DIM)}" if skipped else ""
        out.append(f"    {_tone('sampled', DIM)} {_tone(sampled, CYAN)}{skip_note}")

    core_rows = _core_timing_entries(timing)
    if core_rows:
        out.extend(["", _heading("Cores")])
        for name, value in core_rows:
            if value.get("error"):
                detail = _tone("failed", RED)
            else:
                snap = value.get("snapshot_ms")
                count = value.get("clients")
                parts = []
                if snap is not None:
                    parts.append(f"{snap} ms")
                if count is not None:
                    parts.append(f"{count} clients")
                detail = _tone("  ".join(parts) or "—", WHITE)
            out.append(f"    {_tone(_pad(_short_core_name(name), 12), CYAN)}{detail}")

    by_core = snapshot.get("pending_by_core") or {}
    if by_core:
        out.extend(["", _heading("By core")])
        for name, item in sorted(by_core.items()):
            out.append(
                f"    {_tone(_pad(name, 12), CYAN)}"
                f"{_tone(_pad(str(item.get('clients', 0)) + ' clients', 14), WHITE)}"
                f"{_tone(_pad(str(item.get('chunks', 0)) + ' chunks', 14), DIM)}"
                f"{_tone(str(item.get('label') or '0 B'), YELLOW)}"
            )

    out.append("")
    if clients <= 0:
        out.append(_heading("Pending"))
        out.append(f"  {_tone('Queue is empty.', GREEN)}")
    else:
        out.extend(_format_top_pending_table(snapshot.get("top_pending") or [], clients))

    bandwidth = _format_config_bandwidth(
        list(snapshot.get("config_bandwidth") or []),
        int(snapshot.get("config_bandwidth_total") or 0),
        int(snapshot.get("config_bandwidth_bytes") or 0),
    )
    if bandwidth:
        out.extend(["", *bandwidth])

    alerts = _frame_alerts(snapshot)
    if alerts:
        out.extend(["", _heading("Needs attention")])
        for alert in alerts:
            out.append(f"    {_tone('!', YELLOW)} {_tone(_clip(alert, 96), YELLOW)}")
    out.append("")
    return out


def print_pending_queue_summary(snapshot: dict[str, Any], *, limit: int = 30) -> None:
    """Print the same pending rows as the live watch (for reset preview)."""
    total = int(snapshot.get("pending_clients") or 0)
    top = list(snapshot.get("top_pending") or [])
    if limit > 0:
        top = top[:limit]
    for line in _format_top_pending_table(top, total) or [f"  {_tone('Queue is empty.', GREEN)}"]:
        print(line, flush=True)


def render_volume_billing_frame(
    snapshot: dict[str, Any],
    log_lines: list[str],
    *,
    note: str | None = None,
) -> None:
    for line in format_volume_billing_frame(snapshot, log_lines, note=note):
        print(line, flush=True)


def run_volume_billing_watch(
    runtime: Runtime,
    *,
    interval: float = 2.0,
    once: bool = False,
    as_json: bool = False,
    pending_limit: int = _WATCH_TOP_PENDING,
    log_lines: int = 3,
) -> int:
    from agent.asyncutil import run_sync

    traffic = TrafficService(runtime.store)
    log_cursor = int(activity_log.cursor().get("next") or 0)
    file_tail = _AgentLogTail(resolve_log_path(runtime.settings))
    wait_s = max(0.5, float(interval))

    screen = _LiveScreen()

    prev_fp: tuple[Any, ...] | None = None
    try:
        while True:
            snapshot = run_sync(
                collect_volume_billing_snapshot(
                    traffic,
                    runtime.settings,
                    pending_limit=pending_limit,
                    registry=runtime.registry,
                )
            )
            log_lines_out, log_cursor = _filtered_activity_lines(log_cursor)
            log_lines_out.extend(file_tail.poll(limit=max(1, int(log_lines))))
            fp = _snapshot_fingerprint(snapshot)
            note = None
            if prev_fp is not None and fp == prev_fp:
                note = _unchanged_note(snapshot)
            prev_fp = fp

            if as_json:
                print(
                    json.dumps(
                        {**snapshot, "unchanged": note is not None, "log_lines": log_lines_out},
                        ensure_ascii=False,
                        default=str,
                    ),
                    flush=True,
                )
            else:
                frame = format_volume_billing_frame(snapshot, log_lines_out, note=note)
                if once or not screen._tty:
                    for line in frame:
                        print(line, flush=True)
                else:
                    screen.draw(frame)

            if once:
                return 0
            time.sleep(wait_s)
    except KeyboardInterrupt:
        if not as_json:
            screen.reset()
            print("\nStopped.", flush=True)
        return 0
