from agent.drivers.xray_http import format_xray_api_error


def test_format_xray_api_error_includes_code_and_details():
    body = {
        "error": "app/httpapi/apiserver: add inbound inbound-1642",
        "code": "validation_failed",
        "details": ["port 2053 already in use", "listen failed"],
        "runtime_applied": False,
    }
    message = format_xray_api_error(500, "POST http://127.0.0.1:8080/api/inbounds/edit", body)
    assert "add inbound inbound-1642" in message
    assert "code=validation_failed" in message
    assert "port 2053 already in use" in message
    assert "runtime_applied=true" not in message


def test_format_xray_api_error_marks_runtime_applied():
    body = {
        "error": "config save failed",
        "code": "config_save_failed",
        "runtime_applied": True,
    }
    message = format_xray_api_error(500, "POST http://127.0.0.1:8080/api/inbounds/edit", body)
    assert "runtime_applied=true" in message
    assert "config_save_failed" in message
