from __future__ import annotations

import time
from typing import Any

from agent.support import record_is_enabled


def clear_disabled_metadata(row: dict[str, Any]) -> None:
    row.pop("disabled_reason", None)
    row.pop("disabled_at", None)
    row.pop("disabled_detail", None)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mark_quota_disabled(row: dict[str, Any], live_incoming: int, live_outgoing: int) -> None:
    remaining = int(row.get("volume") or 0)
    base_in = int(row.get("_incoming") or 0)
    base_out = int(row.get("_outgoing") or 0)
    store_in = int(row.get("incoming") or 0)
    store_out = int(row.get("outgoing") or 0)

    delta_in = live_incoming - base_in if live_incoming >= base_in else live_incoming
    delta_out = live_outgoing - base_out if live_outgoing >= base_out else live_outgoing
    delta = max(0, delta_in) + max(0, delta_out)

    row["is_enabled"] = False
    row["disabled_reason"] = "quota_exceeded"
    row["disabled_at"] = _now_iso()
    row["disabled_detail"] = {
        "remaining_bytes": remaining,
        "delta_bytes": delta,
        "baseline_incoming": base_in,
        "baseline_outgoing": base_out,
        "live_incoming": live_incoming,
        "live_outgoing": live_outgoing,
        "store_incoming": store_in,
        "store_outgoing": store_out,
    }


def mark_panel_disabled(row: dict[str, Any]) -> None:
    row["is_enabled"] = False
    row["disabled_reason"] = "panel_sync"
    row["disabled_at"] = _now_iso()
    row["disabled_detail"] = {
        "source": "panel",
        "message": "Panel pushed is_enabled=false",
    }


def explain_disabled(row: dict[str, Any]) -> str:
    if record_is_enabled(row):
        return "Peer is enabled"

    reason = str(row.get("disabled_reason") or "").strip()
    detail = row.get("disabled_detail")
    detail = detail if isinstance(detail, dict) else {}

    if reason == "quota_exceeded":
        remaining = int(detail.get("remaining_bytes", row.get("volume") or 0))
        delta = int(detail.get("delta_bytes") or 0)
        base_in = int(detail.get("baseline_incoming") or 0)
        base_out = int(detail.get("baseline_outgoing") or 0)
        if base_in <= 0 and base_out <= 0 and delta > 0:
            return (
                "Peer disabled by quota enforcer: baseline (_incoming/_outgoing) is still zero "
                f"while cumulative traffic exists (delta={delta} bytes). "
                "Sync from panel or upgrade Agent to v0.3.83+ to auto-seed baseline."
            )
        if remaining <= 0:
            return (
                "Peer disabled by quota enforcer: remaining volume is zero "
                f"(delta={delta} bytes since baseline)."
            )
        return (
            "Peer disabled by quota enforcer: usage since baseline reached the synced quota "
            f"(delta={delta} bytes, remaining={remaining} bytes)."
        )

    if reason == "panel_sync":
        return "Peer disabled because the panel pushed is_enabled=false."

    if reason:
        message = str(detail.get("message") or "").strip()
        if message:
            return f"Peer disabled ({reason}): {message}"
        return f"Peer disabled ({reason})."

    remaining = int(row.get("volume") or 0)
    if "volume" in row and remaining <= 0:
        return "Peer disabled in agent store (remaining volume is zero)."

    return "Peer disabled in agent store (reason not recorded — update Agent to v0.3.83+)."
