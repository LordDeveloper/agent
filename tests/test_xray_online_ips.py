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
