"""Foreground volume / pending-queue monitor for CLI and menu debugging."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent.auth_scope import current_scope
from agent.logutil import activity_log, resolve_log_path
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
_PANEL_NODE_ID_WIDTH = 64


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
    rows = await traffic.store.list_traffic_pending()
    chunks = await traffic.store.list_traffic_pending_chunks()
    panel_id_by_stored: dict[tuple[str, str], str] = {}
    for ident in await traffic.store.list_traffic_identity():
        core_name = str(ident.get("core") or "").strip()
        alias = str(ident.get("alias") or "").strip()
        canonical = str(ident.get("canonical_key") or "").strip()
        if core_name and alias and canonical:
            panel_id_by_stored[(core_name, alias)] = canonical
    chunks_by_client: dict[tuple[str, str], int] = {}
    pending_bytes = 0
    wg_chunk_clients: set[str] = set()
    pending_by_core: dict[str, dict[str, Any]] = {}
    for chunk in chunks:
        key = (str(chunk.get("core") or ""), str(chunk.get("client_key") or ""))
        chunks_by_client[key] = chunks_by_client.get(key, 0) + 1
        chunk_bytes = int(chunk.get("incoming") or 0) + int(chunk.get("outgoing") or 0)
        pending_bytes += chunk_bytes
        core_name = key[0] or "—"
        bucket = pending_by_core.setdefault(
            core_name,
            {"clients": set(), "chunks": 0, "bytes": 0},
        )
        bucket["clients"].add(key[1])
        bucket["chunks"] += 1
        bucket["bytes"] += chunk_bytes
        if key[0] == "wireguard" and key[1]:
            wg_chunk_clients.add(key[1])

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
        "pending_chunks": len(chunks),
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
    if registry is not None and live_wg and wg_chunk_clients:
        for client_key in wg_chunk_clients:
            live = live_wg.get(client_key)
            if live is None:
                continue
            stored = await traffic.store.get_client_traffic_cursor("wireguard", client_key)
            if stored is None:
                continue
            live_down, live_up = live
            counter_down, counter_up = stored
            kernel_ahead_bytes += max(0, live_down - counter_down) + max(0, live_up - counter_up)

    for row in rows_sorted[:slice_end]:
        core = str(row.get("core") or "")
        client_key = str(row.get("client_key") or "")
        panel_node_id = panel_id_by_stored.get((core, client_key), client_key)
        item: dict[str, Any] = {
            "core": core,
            "client_key": client_key,
            "panel_node_id": panel_node_id,
            "downlink": int(row.get("delta_incoming") or 0),
            "uplink": int(row.get("delta_outgoing") or 0),
            "total": int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
            "chunk_count": int(chunks_by_client.get((core, client_key), 0)),
            "updated_at": row.get("updated_at"),
        }
        top.append(item)

    snapshot_body["top_pending"] = top
    snapshot_body["pending_bytes_chunks"] = pending_bytes
    snapshot_body["pending_bytes_aggregate"] = row_delta_bytes
    snapshot_body["kernel_ahead_bytes"] = kernel_ahead_bytes
    snapshot_body["kernel_ahead_label"] = _format_bytes(kernel_ahead_bytes)
    snapshot_body["kernel_ahead_unreliable"] = (
        pending_bytes > 0 and kernel_ahead_bytes > max(pending_bytes * 20, 512 * 1024 * 1024)
    )
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


def _format_timing_summary(raw: Any) -> str | None:
    if not raw:
        return None
    try:
        timing = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return str(raw)
    parallel = timing.get("parallel_snapshot_ms", timing.get("cycle_ms"))
    sqlite_ms = timing.get("_sqlite_ms", timing.get("sqlite_ms"))
    parts = [f"parallel={parallel}ms", f"sqlite={sqlite_ms}ms"]
    core_parts: list[str] = []
    for key, value in sorted(timing.items()):
        if key in {"parallel_snapshot_ms", "cycle_ms", "_sqlite_ms", "sqlite_ms"}:
            continue
        if not isinstance(value, dict):
            continue
        snap = value.get("snapshot_ms")
        if snap is None:
            continue
        short = "wg" if key == "wireguard" else key
        core_parts.append(f"{short}={snap}ms")
    parts.extend(core_parts)
    return "  sample  " + "  ".join(str(p) for p in parts if p is not None)


def _format_top_pending_table(top: list[dict[str, Any]], total_clients: int) -> list[str]:
    lines: list[str] = []
    if not top:
        return lines
    lines.append(f"  Top unacked by volume (showing {len(top)} of {total_clients} clients)")
    wid = _PANEL_NODE_ID_WIDTH
    lines.append(
        f"  {'#':>3}  {'core':8}  {'panel node_id':<{wid}}  {'down':>10}  {'up':>10}  {'total':>10}  ck"
    )
    lines.append(f"  {'-' * 3}  {'-' * 8}  {'-' * wid}  {'-' * 10}  {'-' * 10}  {'-' * 10}  ---")
    for index, row in enumerate(top, start=1):
        core = str(row.get("core") or "")[:8]
        panel = str(row.get("panel_node_id") or row.get("client_key") or "")
        down = _format_bytes(int(row.get("downlink") or 0))
        up = _format_bytes(int(row.get("uplink") or 0))
        total = _format_bytes(int(row.get("total") or 0))
        chunks = int(row.get("chunk_count") or 0)
        lines.append(
            f"  {index:3d}  {core:8}  {panel:<{wid}}  {down:>10}  {up:>10}  {total:>10}  {chunks:3d}"
        )
    return lines


def format_volume_billing_frame(
    snapshot: dict[str, Any],
    log_lines: list[str],
    *,
    note: str | None = None,
) -> list[str]:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lag = snapshot.get("worker_lag_ms")
    lag_label = f"{lag} ms" if lag is not None else "—"
    out: list[str] = []
    header = f"--- volume billing · {ts} ---"
    if note:
        header += f"  · {note}"
    out.append(header)
    out.append(
        f"  pending_clients={snapshot.get('pending_clients')}  "
        f"pending_chunks={snapshot.get('pending_chunks', 0)}  "
        f"unacked={snapshot.get('pending_bytes_label')}  "
        f"sample_lag={lag_label}"
    )
    interval_s = float(snapshot.get("traffic_sample_interval_s") or 2.0)
    stale_ms = max(30_000, int(interval_s * 15_000))
    if isinstance(lag, int) and lag > stale_ms:
        out.append(
            f"  hint: sample_lag>{stale_ms // 1000}s — worker may be stuck; "
            "pending grows only when a sample finishes."
        )
    unacked = int(snapshot.get("pending_bytes") or 0)
    clients = int(snapshot.get("pending_clients") or 0)
    if unacked >= 256 * 1024 * 1024 or clients >= 80:
        out.append(
            f"  hint: backlog {snapshot.get('pending_bytes_label')} / {clients} clients — "
            "panel must POST ack after billing."
        )
    billing = snapshot.get("billing_cores") or []
    enabled = snapshot.get("enabled_cores") or []
    skipped = [c for c in enabled if c not in billing]
    out.append(
        f"  sample_interval={snapshot.get('traffic_sample_interval_s')}s  "
        f"quota_interval={snapshot.get('quota_enforce_interval_s')}s  "
        f"local_volume_quota={'on' if snapshot.get('enforce_local_volume_quota') else 'off (panel owns cutoff)'}"
    )
    if billing:
        skip_note = f"  skip: {','.join(skipped)}" if skipped else ""
        out.append(f"  volume sample cores: {','.join(billing)}{skip_note}")
    out.append(f"  last_sample_at={snapshot.get('last_sample_at') or '—'}")
    ahead = int(snapshot.get("kernel_ahead_bytes") or 0)
    if ahead > 0:
        wg_note = (
            "live WG since last stored cursor"
            if not snapshot.get("kernel_ahead_unreliable")
            else "IGNORE if huge — cursor desync"
        )
        out.append(f"  wg_kernel_ahead={snapshot.get('kernel_ahead_label')} ({wg_note})")
    timing_line = _format_timing_summary(snapshot.get("sample_timing"))
    if timing_line:
        out.append(timing_line)
    total_clients = int(snapshot.get("pending_clients") or 0)
    total_chunks = int(snapshot.get("pending_chunks") or 0)
    if total_clients <= 0:
        out.append("  (no unacked pending rows)")
    else:
        out.append(
            f"  queue: {total_clients} clients · {total_chunks} chunks · "
            f"{snapshot.get('pending_bytes_label')} unacked"
        )
        by_core = snapshot.get("pending_by_core") or {}
        if by_core:
            core_bits = [
                f"{name} {item.get('clients', 0)}c/{item.get('chunks', 0)}ch/{item.get('label', '0 B')}"
                for name, item in sorted(by_core.items())
            ]
            out.append(f"  unacked by core: {', '.join(core_bits)}")
        out.extend(_format_top_pending_table(snapshot.get("top_pending") or [], total_clients))
    for line in log_lines[-3:]:
        if "traffic sample timing" in line or "traffic sample cycle" in line:
            out.append(f"  log | {line}")
    return out


def print_pending_queue_summary(snapshot: dict[str, Any], *, limit: int = 30) -> None:
    """Print the same pending rows as the live watch (for reset preview)."""
    total = int(snapshot.get("pending_clients") or 0)
    if total <= 0:
        print("  (no unacked pending rows)", flush=True)
        return
    top = snapshot.get("top_pending") or []
    shown = len(top)
    if limit > 0 and total > shown:
        print(f"  (showing {shown} of {total} clients)", flush=True)
    for row in top[: max(1, limit) if limit > 0 else len(top)]:
        key = str(row.get("panel_node_id") or row.get("client_key") or "")
        core = str(row.get("core") or "")
        down = _format_bytes(int(row.get("downlink") or 0))
        up = _format_bytes(int(row.get("uplink") or 0))
        chunk_count = int(row.get("chunk_count") or 0)
        extra = f"  ({chunk_count} chunks)" if chunk_count > 0 else ""
        ahead = int(row.get("kernel_ahead") or 0)
        if ahead > 0:
            extra += f"  (wg live +{_format_bytes(ahead)} not in pending yet)"
        print(f"    {core:8} {key:<{_PANEL_NODE_ID_WIDTH}}  ↓{down}  ↑{up}{extra}", flush=True)


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
    banner_printed = False

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
                if not banner_printed and sys.stderr.isatty():
                    print(
                        "Volume billing watch (screen refresh in place). Ctrl+C to stop.",
                        file=sys.stderr,
                        flush=True,
                    )
                    banner_printed = True
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
