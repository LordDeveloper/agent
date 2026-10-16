from agent.drivers.xray_http import (
    is_fresh_ip_last_seen,
    retain_fresh_online_ips,
)


NOW = 1_700_000_000.0


def test_stale_iplist_entries_are_dropped():
    ips = {
        "5.116.96.198": NOW - 3600,
        "5.115.104.52": NOW - 120,
        "89.196.9.230": int((NOW - 30) * 1000),
        "83.121.27.148": NOW - 10,
    }

    fresh = retain_fresh_online_ips(ips, now=NOW)

    assert fresh == {
        "89.196.9.230": int((NOW - 30) * 1000),
        "83.121.27.148": NOW - 10,
    }


def test_bare_ip_list_is_left_unchanged():
    ips = ["1.2.3.4", "5.6.7.8"]

    assert retain_fresh_online_ips(ips, now=NOW) == ips


def test_future_skew_within_thirty_seconds_stays_fresh():
    assert is_fresh_ip_last_seen(NOW + 20, now=NOW) is True
    assert is_fresh_ip_last_seen(NOW + 90, now=NOW) is False
    assert is_fresh_ip_last_seen(0, now=NOW) is False
    assert is_fresh_ip_last_seen(None, now=NOW) is False
