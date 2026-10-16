import time

import httpx

from agent.config import XraySettings
from agent.drivers.xray_http import XrayHttpClient
from agent.errors import AgentError


class _OfflineIplistTransport(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/stats/online/iplist":
            return httpx.Response(
                404,
                json={"message": "user>>>uuid>>>online not found"},
            )
        return httpx.Response(404, json={"message": "404 page not found"})


class _StaleIplistTransport(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/stats/online/iplist":
            now = time.time()
            return httpx.Response(
                200,
                json={
                    "ips": {
                        "5.116.96.198": int(now - 3600),
                        "83.121.27.148": int(now - 5),
                    }
                },
            )
        return httpx.Response(404, json={"message": "404 page not found"})


def test_online_ips_drops_stale_last_seen():
    settings = XraySettings(
        api_base="http://127.0.0.1:8080",
        username="",
        password="",
        binary="xray",
        config="/tmp/xray.json",
        timeout=5.0,
        connect_timeout=1.0,
    )
    client = XrayHttpClient(settings, transport=_StaleIplistTransport())

    assert client.online_ips("uuid") == ["83.121.27.148"]
    seen = client.online_ip_last_seen("uuid")
    assert list(seen) == ["83.121.27.148"]
    assert seen["83.121.27.148"] > 1_000_000_000


def test_online_ips_offline_user_returns_empty_list():
    settings = XraySettings(
        api_base="http://127.0.0.1:8080",
        username="",
        password="",
        binary="xray",
        config="/tmp/xray.json",
        timeout=5.0,
        connect_timeout=1.0,
    )
    client = XrayHttpClient(settings, transport=_OfflineIplistTransport())

    assert client.online_ips("uuid") == []


class _OnlineAllTransport(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/stats/sys":
            return httpx.Response(200, json={"uptime": 1})
        if request.url.path == "/api/stats/online/all":
            return httpx.Response(
                200,
                json={
                    "users": [
                        {"email": "CmLB85", "ips": {"1.2.3.4": 1700000000}},
                    ]
                },
            )
        return httpx.Response(404, json={"message": "404 page not found"})


def test_xray_http_online_all_returns_users():
    settings = XraySettings(
        api_base="http://127.0.0.1:8080",
        username="",
        password="",
        binary="xray",
        config="/tmp/xray.json",
        timeout=5.0,
        connect_timeout=1.0,
    )
    client = XrayHttpClient(settings, transport=_OnlineAllTransport())

    body = client.online_all()
    assert body["users"][0]["email"] == "CmLB85"
    assert "1.2.3.4" in body["users"][0]["ips"]


def test_online_ips_offline_raises_user_offline_not_config_not_found():
    settings = XraySettings(
        api_base="http://127.0.0.1:8080",
        username="",
        password="",
        binary="xray",
        config="/tmp/xray.json",
        timeout=5.0,
        connect_timeout=1.0,
    )
    client = XrayHttpClient(settings, transport=_OfflineIplistTransport())

    try:
        client.get("/api/stats/online/iplist", params={"email": "uuid"})
        assert False, "expected AgentError"
    except AgentError as exc:
        assert exc.code == "USER_OFFLINE"
        assert exc.status == 404
