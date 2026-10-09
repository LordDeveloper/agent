from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent.main import RequestLogMiddleware
from agent.runtime import RuntimeTrace, command_span_name


def test_header_includes_action_total_and_spans():
    RuntimeTrace.start("peer_config")
    RuntimeTrace.add("wg.show", 12.34)
    RuntimeTrace.add("wg.show", 7.66)
    RuntimeTrace.add("wg.syncconf", 4.0)
    header = RuntimeTrace.header()
    RuntimeTrace.reset()

    assert header.startswith("action=peer_config;total=")
    assert "wg.show=20.0ms*2" in header
    assert "wg.syncconf=4.0ms" in header


def test_span_is_noop_outside_request():
    RuntimeTrace.reset()
    with RuntimeTrace.span("wg.show"):
        pass
    assert RuntimeTrace.header() == ""


def test_command_span_name():
    assert command_span_name(["/usr/bin/wg", "show", "wg0", "dump"]) == "wg.show"
    assert command_span_name(["wg-quick", "up", "wg0"]) == "wg-quick.up"
    assert command_span_name(["ip", "-4", "addr"]) == "ip"


def test_middleware_sets_x_runtime_header():
    app = FastAPI()
    app.add_middleware(RequestLogMiddleware)

    @app.get("/ping")
    def ping():
        RuntimeTrace.add("wg.show", 3.0)
        return {"ok": True}

    with TestClient(app) as client:
        response = client.get("/ping")

    assert response.status_code == 200
    runtime = response.headers.get("x-runtime") or ""
    assert "action=ping" in runtime
    assert "total=" in runtime
    assert "wg.show=3.0ms" in runtime
