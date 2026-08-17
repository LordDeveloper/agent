import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.db import Store
from agent.errorlog import list_log_errors, parse_error_payload, parse_log_line
from agent.logutil import reset_logging
from agent.main import create_app

_CLEAR_PREFIXES = (
    "LISTEN",
    "AUTH_",
    "DATA_DIR",
    "DB_PATH",
    "ENABLED_CORES",
    "XRAY_",
    "WIREGUARD_",
    "AMNEZIA_",
    "ENV_FILE",
)


def _clear_env() -> None:
    for key in list(os.environ):
        if key.startswith(_CLEAR_PREFIXES) or key in {"LISTEN", "DATA_DIR", "DB_PATH", "ENABLED_CORES", "ENV_FILE"}:
            os.environ.pop(key, None)


@pytest.fixture()
def wg_client(tmp_path):
    _clear_env()
    reset_logging()
    env = tmp_path / ".env"
    data = tmp_path / "data"
    conf = tmp_path / "wg"
    conf.mkdir()
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data.as_posix()}",
                "ENABLED_CORES=wireguard",
                f"WIREGUARD_CONFIG_DIR={conf.as_posix()}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with TestClient(create_app(str(env))) as client:
        yield client, data / "agent.log"
    reset_logging()
    _clear_env()


def test_parse_error_payload_agent_detail():
    code, message, _detail = parse_error_payload(
        b'{"detail":{"success":false,"error":{"code":"CLIENT_NOT_FOUND","message":"missing"}}}'
    )
    assert code == "CLIENT_NOT_FOUND"
    assert message == "missing"


def test_parse_error_payload_validation_list():
    code, message, _detail = parse_error_payload(
        b'{"detail":[{"loc":["body","email"],"msg":"Field required","type":"missing"}]}'
    )
    assert code == "VALIDATION_ERROR"
    assert "Field required" in message


def test_parse_log_line_splits_core_and_level():
    line = (
        "2026-08-17 14:30:01 [WARNING] agent.xray: core_error "
        "code=HTTP_ERROR status=422 method=POST path=/api/v1/cores/xray/clients message=email required"
    )
    parsed = parse_log_line(line)
    assert parsed is not None
    assert parsed["core"] == "xray"
    assert parsed["level"] == "warning"
    assert parsed["code"] == "HTTP_ERROR"
    assert parsed["status"] == 422
    assert parsed["method"] == "POST"
    assert parsed["path"] == "/api/v1/cores/xray/clients"
    assert parsed["message"] == "email required"


def test_list_log_errors_filters_by_core_and_level(tmp_path: Path):
    log_path = tmp_path / "agent.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-08-17 14:00:00 [INFO] agent.app: agent started",
                "2026-08-17 14:00:01 [WARNING] agent.xray: core_error code=A status=400 method=GET path=/x message=xray warn",
                "2026-08-17 14:00:02 [ERROR] agent.xray: core_error code=B status=500 method=GET path=/x message=xray err",
                "2026-08-17 14:00:03 [ERROR] agent.wireguard: core_error code=C status=500 method=GET path=/w message=wg err",
                "",
            ]
        ),
        encoding="utf-8",
    )

    xray_all = list_log_errors(log_path, core="xray", limit=10)
    assert [row["message"] for row in xray_all] == ["xray err", "xray warn"]

    xray_errors = list_log_errors(log_path, core="xray", level="error")
    assert [row["message"] for row in xray_errors] == ["xray err"]

    wg = list_log_errors(log_path, core="wireguard")
    assert [row["message"] for row in wg] == ["wg err"]


def test_store_does_not_keep_core_errors_table(tmp_path: Path):
    store = Store(tmp_path / "agent.db")
    try:
        row = store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='core_errors'"
        ).fetchone()
        assert row is None
        assert not hasattr(store, "record_error")
    finally:
        store.close()


def test_core_errors_are_written_to_agent_log(wg_client):
    client, log_path = wg_client
    headers = {"Authorization": "Bearer dev-token"}

    empty = client.get("/api/v1/cores/wireguard/errors", headers=headers)
    assert empty.status_code == 200, empty.text
    assert empty.json()["errors"] == []

    missing = client.get("/api/v1/cores/wireguard/inbounds", headers=headers)
    assert missing.status_code == 404

    text = log_path.read_text(encoding="utf-8")
    assert "[WARNING] agent.wireguard: core_error" in text
    assert "path=/api/v1/cores/wireguard/inbounds" in text

    listed = client.get("/api/v1/cores/wireguard/errors?limit=10", headers=headers)
    assert listed.status_code == 200, listed.text
    errors = listed.json()["errors"]
    assert len(errors) == 1
    assert errors[0]["core"] == "wireguard"
    assert errors[0]["level"] == "warning"
    assert errors[0]["status"] == 404
    assert errors[0]["path"].endswith("/cores/wireguard/inbounds")
    assert errors[0]["method"] == "GET"

    filtered = client.get("/api/v1/cores/wireguard/errors?level=error", headers=headers)
    assert filtered.json()["errors"] == []
