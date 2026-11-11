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
from agent.traffic.service import AGENT_META_CORE, FETCH_LOCK_META_KEY, LAST_SAMPLE_META_KEY, TrafficService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.runtime import Runtime

_LOG_FILTER = re.compile(r"(traffic|quota|pending|volume|ack|sample)", re.IGNORECASE)


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


async def _panel_pending_read_locked(traffic: TrafficService) -> tuple[bool, str]:
    raw = await traffic.store.get_meta(
        AGENT_META_CORE,
        f"{FETCH_LOCK_META_KEY}:{current_scope()}",
        None,
    )
    if not isinstance(raw, dict):
        return False, ""
    try:
        expires_at = float(raw.get("expires_at") or 0)
    except (TypeError, ValueError):
        return False, ""
    if expires_at <= time.time():
        return False, ""
    owner = str(raw.get("owner") or "").strip()
    return True, owner


async def collect_volume_billing_snapshot(
    traffic: TrafficService,
    settings: AgentSettings,
) -> dict[str, Any]:
    rows = await traffic.store.list_traffic_pending()
    pending_bytes = 0
    for row in rows:
        pending_bytes += int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0)

    locked, lock_owner = await _panel_pending_read_locked(traffic)
    rows_sorted = sorted(
        rows,
        key=lambda row: int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
        reverse=True,
    )

    return {
        "pending_clients": len(rows),
        "pending_bytes": pending_bytes,
        "pending_bytes_label": _format_bytes(pending_bytes),
        "worker_lag_ms": await traffic.last_sample_age_ms(),
        "last_sample_at": await traffic.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY),
        "panel_pending_read_locked": locked,
        "panel_pending_read_owner": lock_owner or None,
        "enforce_local_volume_quota": bool(settings.enforce_local_volume_quota),
        "traffic_sample_interval_s": float(settings.traffic_sample_interval),
        "quota_enforce_interval_s": float(settings.quota_enforce_interval),
        "top_pending": [
            {
                "core": str(row.get("core") or ""),
                "client_key": str(row.get("client_key") or ""),
                "downlink": int(row.get("delta_incoming") or 0),
                "uplink": int(row.get("delta_outgoing") or 0),
                "total": int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
                "updated_at": row.get("updated_at"),
            }
            for row in rows_sorted[:12]
        ],
    }


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
    )


def render_volume_billing_frame(
    snapshot: dict[str, Any],
    log_lines: list[str],
    *,
    note: str | None = None,
) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lag = snapshot.get("worker_lag_ms")
    lag_label = f"{lag} ms" if lag is not None else "—"
    lock = "yes" if snapshot.get("panel_pending_read_locked") else "no"
    owner = snapshot.get("panel_pending_read_owner")
    if owner:
        lock += f" (pid {owner})"

    header = f"--- volume billing · {ts} ---"
    if note:
        header += f"  ({note})"
    print(header, flush=True)
    print(
        f"  pending_clients={snapshot.get('pending_clients')}  "
        f"unacked={snapshot.get('pending_bytes_label')}  "
        f"sample_lag={lag_label}  panel_read_lock={lock}",
        flush=True,
    )
    interval_s = float(snapshot.get("traffic_sample_interval_s") or 2.0)
    stale_ms = max(30_000, int(interval_s * 15_000))
    if isinstance(lag, int) and lag > stale_ms:
        print(
            f"  hint: sample_lag>{stale_ms // 1000}s — worker may be stuck; "
            "pending still grows only when a sample finishes.",
            flush=True,
        )
    unacked = int(snapshot.get("pending_bytes") or 0)
    clients = int(snapshot.get("pending_clients") or 0)
    if unacked >= 256 * 1024 * 1024 or clients >= 80:
        print(
            f"  hint: backlog {snapshot.get('pending_bytes_label')} / {clients} clients — "
            "panel must POST ack after billing; until then this queue does not shrink.",
            flush=True,
        )
    print(
        f"  sample_interval={snapshot.get('traffic_sample_interval_s')}s  "
        f"quota_interval={snapshot.get('quota_enforce_interval_s')}s  "
        f"local_volume_quota={'on' if snapshot.get('enforce_local_volume_quota') else 'off (panel owns cutoff)'}",
        flush=True,
    )
    sampled = snapshot.get("last_sample_at") or "—"
    print(f"  last_sample_at={sampled}", flush=True)

    top = snapshot.get("top_pending") or []
    if not top:
        print("  (no unacked pending rows)", flush=True)
    else:
        for row in top:
            key = str(row.get("client_key") or "")[:48]
            core = str(row.get("core") or "")
            down = _format_bytes(int(row.get("downlink") or 0))
            up = _format_bytes(int(row.get("uplink") or 0))
            print(f"    {core:8} {key:48}  ↓{down}  ↑{up}", flush=True)

    for line in log_lines:
        print(f"  log | {line}", flush=True)


def run_volume_billing_watch(
    runtime: Runtime,
    *,
    interval: float = 2.0,
    once: bool = False,
    as_json: bool = False,
) -> int:
    from agent.asyncutil import run_sync

    traffic = TrafficService(runtime.store)
    log_cursor = int(activity_log.cursor().get("next") or 0)
    file_tail = _AgentLogTail(resolve_log_path(runtime.settings))
    wait_s = max(0.5, float(interval))

    if not as_json and sys.stderr.isatty():
        print(
            "Watching traffic pending + worker activity (Ctrl+C to stop). "
            "Panel bills via GET pending then POST ack; snapshot is stored in agent DB for ack.",
            file=sys.stderr,
            flush=True,
        )

    prev_fp: tuple[Any, ...] | None = None
    try:
        while True:
            snapshot = run_sync(collect_volume_billing_snapshot(traffic, runtime.settings))
            log_lines, log_cursor = _filtered_activity_lines(log_cursor)
            log_lines.extend(file_tail.poll())
            fp = _snapshot_fingerprint(snapshot)
            note = None
            compact = False
            if prev_fp is not None and fp == prev_fp:
                note = (
                    "unchanged — panel has not POST ack; worker/sample values are the same as last tick "
                    "(watch does not bill; only the panel shrinks this queue)"
                )
                compact = not as_json
            prev_fp = fp

            if as_json:
                print(
                    json.dumps(
                        {**snapshot, "unchanged": note is not None, "log_lines": log_lines},
                        ensure_ascii=False,
                        default=str,
                    ),
                    flush=True,
                )
            elif compact:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                lag = snapshot.get("worker_lag_ms")
                lag_label = f"{lag} ms" if lag is not None else "—"
                print(
                    f"--- volume billing · {ts} ---  ({note})",
                    flush=True,
                )
                print(
                    f"  pending_clients={snapshot.get('pending_clients')}  "
                    f"unacked={snapshot.get('pending_bytes_label')}  "
                    f"sample_lag={lag_label}",
                    flush=True,
                )
                for line in log_lines:
                    print(f"  log | {line}", flush=True)
            else:
                render_volume_billing_frame(snapshot, log_lines, note=note)

            if once:
                return 0
            time.sleep(wait_s)
    except KeyboardInterrupt:
        if not as_json:
            print("\nStopped.", flush=True)
        return 0
