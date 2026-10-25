from agent.xray_service import describe_httpapi_guard


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
