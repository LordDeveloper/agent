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
from agent.traffic.service import AGENT_META_CORE, LAST_SAMPLE_META_KEY, TrafficService

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry
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
    chunks_by_client: dict[tuple[str, str], int] = {}
    for chunk in chunks:
        key = (str(chunk.get("core") or ""), str(chunk.get("client_key") or ""))
        chunks_by_client[key] = chunks_by_client.get(key, 0) + 1

    pending_bytes = 0
    for row in rows:
        pending_bytes += int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0)

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
        "pending_clients": len(rows),
        "pending_chunks": len(chunks),
        "pending_bytes": pending_bytes,
        "pending_bytes_label": _format_bytes(pending_bytes),
        "pending_last_touch": pending_last_touch,
        "worker_lag_ms": await traffic.last_sample_age_ms(),
        "last_sample_at": await traffic.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY),
        "enforce_local_volume_quota": bool(settings.enforce_local_volume_quota),
        "traffic_sample_interval_s": float(settings.traffic_sample_interval),
        "quota_enforce_interval_s": float(settings.quota_enforce_interval),
        "pending_limit": max(0, int(pending_limit)),
    }
    top: list[dict[str, Any]] = []
    slice_end = len(rows_sorted) if pending_limit <= 0 else max(1, int(pending_limit))
    live_wg = await _live_wireguard_counters(registry) if registry is not None else {}
    kernel_ahead_bytes = 0
    for row in rows_sorted[:slice_end]:
        core = str(row.get("core") or "")
        client_key = str(row.get("client_key") or "")
        counter_down = int(row.get("current_incoming") or 0)
        counter_up = int(row.get("current_outgoing") or 0)
        item: dict[str, Any] = {
            "core": core,
            "client_key": client_key,
            "downlink": int(row.get("delta_incoming") or 0),
            "uplink": int(row.get("delta_outgoing") or 0),
            "total": int(row.get("delta_incoming") or 0) + int(row.get("delta_outgoing") or 0),
            "chunk_count": int(chunks_by_client.get((core, client_key), 0)),
            "counter_downlink": counter_down,
            "counter_uplink": counter_up,
            "updated_at": row.get("updated_at"),
        }
        if core == "wireguard" and client_key in live_wg:
            live_down, live_up = live_wg[client_key]
            item["live_downlink"] = live_down
            item["live_uplink"] = live_up
            ahead = max(0, live_down - counter_down) + max(0, live_up - counter_up)
            item["kernel_ahead"] = ahead
            kernel_ahead_bytes += ahead
        top.append(item)

    snapshot_body["top_pending"] = top
    snapshot_body["kernel_ahead_bytes"] = kernel_ahead_bytes
    snapshot_body["kernel_ahead_label"] = _format_bytes(kernel_ahead_bytes)
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
        key = str(row.get("client_key") or "")[:48]
        core = str(row.get("core") or "")
        down = _format_bytes(int(row.get("downlink") or 0))
        up = _format_bytes(int(row.get("uplink") or 0))
        chunk_count = int(row.get("chunk_count") or 0)
        extra = f"  ({chunk_count} chunks)" if chunk_count > 0 else ""
        ahead = int(row.get("kernel_ahead") or 0)
        if ahead > 0:
            extra += f"  (wg live +{_format_bytes(ahead)} not in pending yet)"
        print(f"    {core:8} {key:48}  ↓{down}  ↑{up}{extra}", flush=True)


def render_volume_billing_frame(
    snapshot: dict[str, Any],
    log_lines: list[str],
    *,
    note: str | None = None,
) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lag = snapshot.get("worker_lag_ms")
    lag_label = f"{lag} ms" if lag is not None else "—"
    header = f"--- volume billing · {ts} ---"
    if note:
        header += f"  ({note})"
    print(header, flush=True)
    print(
        f"  pending_clients={snapshot.get('pending_clients')}  "
        f"pending_chunks={snapshot.get('pending_chunks', 0)}  "
        f"unacked={snapshot.get('pending_bytes_label')}  "
        f"sample_lag={lag_label}",
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
    ahead = int(snapshot.get("kernel_ahead_bytes") or 0)
    if ahead > 0:
        print(
            f"  wg_kernel_ahead={snapshot.get('kernel_ahead_label')} "
            "(live interface moved; pending updates on next agent work sample, not panel GET)",
            flush=True,
        )

    top = snapshot.get("top_pending") or []
    total_clients = int(snapshot.get("pending_clients") or 0)
    limit = int(snapshot.get("pending_limit") or 12)
    if not top:
        print("  (no unacked pending rows)", flush=True)
    else:
        if limit > 0 and total_clients > len(top):
            print(
                f"  (showing top {len(top)} of {total_clients} pending rows; "
                "use --pending-limit 0 for full list)",
                flush=True,
            )
        for row in top:
            key = str(row.get("client_key") or "")[:48]
            core = str(row.get("core") or "")
            down = _format_bytes(int(row.get("downlink") or 0))
            up = _format_bytes(int(row.get("uplink") or 0))
            extra = ""
            chunk_count = int(row.get("chunk_count") or 0)
            if chunk_count > 0:
                extra = f"  ({chunk_count} chunks)"
            ahead = int(row.get("kernel_ahead") or 0)
            if ahead > 0:
                extra += f"  (wg live +{_format_bytes(ahead)} not in pending yet)"
            print(f"    {core:8} {key:48}  ↓{down}  ↑{up}{extra}", flush=True)

    for line in log_lines:
        print(f"  log | {line}", flush=True)


def run_volume_billing_watch(
    runtime: Runtime,
    *,
    interval: float = 2.0,
    once: bool = False,
    as_json: bool = False,
    pending_limit: int = 0,
    log_lines: int = 40,
) -> int:
    from agent.asyncutil import run_sync

    traffic = TrafficService(runtime.store)
    log_cursor = int(activity_log.cursor().get("next") or 0)
    file_tail = _AgentLogTail(resolve_log_path(runtime.settings))
    wait_s = max(0.5, float(interval))

    if not as_json and sys.stderr.isatty():
        print(
            "Watching SQLite pending (written by agent work sample_all). "
            "No panel_read lock. GET/watch do not block WG counters; "
            "unchanged rows mean the worker has not committed a sample yet.",
            file=sys.stderr,
            flush=True,
        )

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
            compact = False
            if prev_fp is not None and fp == prev_fp:
                note = _unchanged_note(snapshot)
                compact = not as_json
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
                    f"pending_chunks={snapshot.get('pending_chunks', 0)}  "
                    f"unacked={snapshot.get('pending_bytes_label')}  "
                    f"sample_lag={lag_label}",
                    flush=True,
                )
                for line in log_lines_out:
                    print(f"  log | {line}", flush=True)
            else:
                render_volume_billing_frame(snapshot, log_lines_out, note=note)

            if once:
                return 0
            time.sleep(wait_s)
    except KeyboardInterrupt:
        if not as_json:
            print("\nStopped.", flush=True)
        return 0
