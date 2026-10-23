from agent.logutil import ActivityHandler, ActivityLog, activity_log
import logging


def test_activity_follow_starts_at_the_current_cursor():
    log = ActivityLog()
    log.add("older line")
    cursor = log.cursor()
    assert cursor["lines"] == []
    assert cursor["next"] == 1
    log.add("live line")
    fresh = log.since(cursor["next"])
    assert [row["text"] for row in fresh["lines"]] == ["live line"]


def test_activity_handler_skips_http_access_lines():
    before = activity_log.cursor()["next"]
    handler = ActivityHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    http_record = logging.LogRecord("agent.http", logging.INFO, __file__, 1, "GET /activity", (), None)
    app_record = logging.LogRecord("agent.progress", logging.INFO, __file__, 1, "WireGuard wg0: up (1/1)", (), None)
    handler.emit(http_record)
    handler.emit(app_record)
    lines = [row["text"] for row in activity_log.since(before)["lines"]]
    assert lines == ["WireGuard wg0: up (1/1)"]
    assert "GET /activity" not in lines
