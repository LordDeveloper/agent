import re

from agent.support.volume_billing_watch import _LOG_FILTER, _format_bytes, _filtered_activity_lines
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
