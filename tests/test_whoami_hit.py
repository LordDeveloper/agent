from agent.whoami_hit import HOST, PORT, decide, destination_is_check_host, http_response
from agent.xray_service import describe_httpapi_guard

SECRET = "test-secret-value-with-32-bytes-min"


def _headers(length: int) -> dict[str, str]:
    return {
        "content-length": str(length),
        "authorization": f"Bearer {SECRET}",
    }


def test_listener_address_is_loopback_only():
    assert HOST == "127.0.0.1"
    assert PORT == 39217
    message = http_response(204)
    assert b"Location" not in message
    assert b"302" not in message


def test_wrong_route_and_oversized_body_are_not_read():
    wrong = decide("GET", "/hit", {"content-length": "20"}, None, False, SECRET, 1000, {})
    huge = decide("POST", "/hit", {"content-length": "4097"}, b"{}", False, SECRET, 1000, {})

    assert wrong["status"] == 404 and wrong["read_body"] is False and wrong["store"] is False
    assert huge["status"] == 401 and huge["read_body"] is False and huge["store"] is False


def test_bad_authorization_does_not_store():
    decision = decide(
        "POST",
        "/hit",
        {"content-length": "2", "authorization": "Bearer wrong"},
        b"{}",
        False,
        SECRET,
        1000,
        {},
    )

    assert decision["status"] == 401
    assert decision["read_body"] is False
    assert decision["store"] is False


def test_only_the_check_host_is_stored_and_rate_limited():
    assert destination_is_check_host("tcp:whoami.nerobot.click:443")
    assert not destination_is_check_host("example.com")
    assert not destination_is_check_host("app.nerobot.click")
    assert not destination_is_check_host("evil.whoami.nerobot.click")

    body = b'{"email":"user1","destination":"whoami.nerobot.click:443","inboundTag":"inbound-1","source":"203.0.113.8:1"}'
    stored = decide("POST", "/hit", _headers(len(body)), body, True, SECRET, 1000, {})
    empty = decide("POST", "/hit", _headers(20), b'{"email":"","destination":"whoami.nerobot.click"}', True, SECRET, 1000, {})
    limited = decide("POST", "/hit", _headers(len(body)), body, True, SECRET, 1010, {"user1": 1000})

    assert stored["store"] is True
    assert stored["email"] == "user1"
    assert stored["inbound_tag"] == "inbound-1"
    assert empty["store"] is False
    assert limited["store"] is False


def test_agent_credentials_count_as_httpapi_auth_without_revealing_them():
    guard = describe_httpapi_guard(
        {"listen": "127.0.0.1:8080", "username": "", "password": ""},
        "agent-user",
        "agent-password",
    )

    assert guard["auth_configured"] is True
    assert guard["has_agent_credentials"] is True
    assert guard["has_config_credentials"] is False
    assert guard["listen"] == "127.0.0.1:8080"
    assert "agent-password" not in guard.values()
    assert describe_httpapi_guard({"listen": "127.0.0.1:8080"}, "", "")["auth_configured"] is False
