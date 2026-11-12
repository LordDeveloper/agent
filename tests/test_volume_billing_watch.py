from agent.config import AgentSettings
from agent.support.volume_billing_watch import (
    _LOG_FILTER,
    _format_bytes,
    _filtered_activity_lines,
    _format_timing_summary,
    format_volume_billing_frame,
)
from agent.logutil import activity_log


def test_format_bytes():
    assert _format_bytes(512) == "512 B"
    assert _format_bytes(2048) == "2.00 KiB"
    assert _format_bytes(5 * 1024 * 1024) == "5.00 MiB"


def test_log_filter_matches_traffic_family():
    assert _LOG_FILTER.search("traffic sample clients=3 pending=1")
    assert _LOG_FILTER.search("quota exceeded — disabled clients=1")
    assert not _LOG_FILTER.search("http listening on 8443")


def test_filtered_activity_lines():
    start = int(activity_log.cursor().get("next") or 0)
    activity_log.add("traffic sample clients=2 pending=1 initialized=0 regressed=0")
    activity_log.add("unrelated noise line")
    lines, nxt = _filtered_activity_lines(start)
    assert any("traffic sample" in line for line in lines)
    assert all("unrelated" not in line for line in lines)
    assert nxt > start


def test_timing_summary_marks_failed_cores_and_client_counts():
    line = _format_timing_summary(
        {
            "parallel_snapshot_ms": 23,
            "sqlite_ms": 10,
            "xray": {"snapshot_ms": 22, "clients": 71},
            "wireguard": {
                "snapshot_ms": 1,
                "error": "TypeError: unexpected keyword argument 'reset_stats'",
            },
            "openvpn": {"snapshot_ms": 4, "clients": 0},
        }
    )
    assert "parallel=23ms" in line
    assert "xray=22ms/71c" in line
    assert "wg=FAIL" in line
    assert "openvpn=4ms/0c" in line


def test_watch_frame_shows_snapshot_errors_instead_of_log_hint():
    snapshot = {
        "pending_clients": 0,
        "pending_chunks": 0,
        "pending_bytes": 0,
        "pending_bytes_label": "0 B",
        "worker_lag_ms": 100,
        "last_sample_at": "2026-11-12T00:00:00+00:00",
        "sample_timing": {
            "parallel_snapshot_ms": 5,
            "sqlite_ms": 1,
            "wireguard": {
                "snapshot_ms": 1,
                "error": "TypeError: usage_snapshot() got an unexpected keyword argument 'reset_stats'",
            },
            "errors": {
                "wireguard": "TypeError: usage_snapshot() got an unexpected keyword argument 'reset_stats'"
            },
        },
        "enforce_local_volume_quota": False,
        "traffic_sample_interval_s": 5,
        "quota_enforce_interval_s": 10,
        "billing_cores": ["xray", "wireguard"],
        "enabled_cores": ["xray", "wireguard"],
        "pending_by_core": {},
        "top_pending": [],
        "wg_live_gap_bytes": 1024 * 1024,
        "wg_live_gap_label": "1.00 MiB",
    }
    text = "\n".join(format_volume_billing_frame(snapshot, []))
    assert "snapshot errors:" in text
    assert "TypeError: usage_snapshot() got an unexpected keyword argument 'reset_stats'" in text
    assert "snapshot failed:" in text
    assert "see agent.log" not in text


def test_default_volume_sample_includes_standalone_l2tp():
    settings = AgentSettings(
        enabled_cores="xray,wireguard,openvpn,amnezia,l2tp",
    )
    assert settings.traffic_billing_cores() == [
        "xray",
        "wireguard",
        "openvpn",
        "amnezia",
        "l2tp",
    ]


def test_watch_frame_names_l2tp_only_when_the_core_is_skipped():
    included = {
        "pending_clients": 0,
        "pending_chunks": 0,
        "pending_bytes": 0,
        "pending_bytes_label": "0 B",
        "worker_lag_ms": 0,
        "enforce_local_volume_quota": False,
        "traffic_sample_interval_s": 5,
        "quota_enforce_interval_s": 10,
        "billing_cores": ["xray", "wireguard", "openvpn", "amnezia", "l2tp"],
        "enabled_cores": ["xray", "wireguard", "openvpn", "amnezia", "l2tp"],
        "pending_by_core": {},
        "top_pending": [],
    }
    included_text = "\n".join(format_volume_billing_frame(included, []))
    assert "volume sample cores: xray,wireguard,openvpn,amnezia,l2tp" in included_text
    assert "skip: l2tp" not in included_text

    skipped = {**included, "billing_cores": ["xray", "wireguard", "openvpn", "amnezia"]}
    skipped_text = "\n".join(format_volume_billing_frame(skipped, []))
    assert "skip: l2tp" in skipped_text
    assert "standalone L2TP volume is not sampled" in skipped_text
