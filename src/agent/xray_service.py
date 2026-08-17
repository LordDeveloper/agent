from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.support.process import service_is_active, systemctl


XRAY_UNIT = "xray"
DEFAULT_CONFIG_PATH = "/usr/local/etc/xray/config.json"
DEFAULT_UNIT_PATH = "/etc/systemd/system/xray.service"


def httpapi_listen(api_base: str) -> str:
    parsed = urlparse(api_base or "http://127.0.0.1:8080")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8080
    return f"{host}:{port}"


def default_xray_config(
    *,
    api_base: str = "http://127.0.0.1:8080",
    username: str = "",
    password: str = "",
    config_path: str = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    httpapi: dict[str, Any] = {
        "listen": httpapi_listen(api_base),
        "config_path": config_path,
    }
    if username:
        httpapi["username"] = username
    if password:
        httpapi["password"] = password

    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"],
        },
        "httpapi": httpapi,
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "statsUserOnline": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 10000,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            ],
        },
    }


def xray_unit_text(binary: str, config_path: str) -> str:
    return f"""[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart={binary} run -config {config_path}
Restart=on-failure
RestartPreventExitStatus=23
RestartSec=2
LimitNPROC=10000
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""


def write_xray_config_if_missing(
    config_path: Path,
    *,
    api_base: str,
    username: str = "",
    password: str = "",
) -> bool:
    if config_path.is_file():
        return False
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = default_xray_config(
        api_base=api_base,
        username=username,
        password=password,
        config_path=str(config_path),
    )
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return True


def write_xray_unit(unit_path: Path, binary: str, config_path: str) -> None:
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(xray_unit_text(binary, config_path), encoding="utf-8")


def _journal(unit: str, limit: int = 20) -> str:
    if not which("journalctl"):
        return ""
    proc = run_cmd(
        ["journalctl", "-u", unit, "-n", str(limit), "--no-pager", "-o", "cat"],
        check=False,
    )
    return (proc.stdout or proc.stderr or "").strip()


def ensure_xray_runtime(
    *,
    binary: str,
    config_path: str = DEFAULT_CONFIG_PATH,
    api_base: str = "http://127.0.0.1:8080",
    username: str = "",
    password: str = "",
    unit_path: str = DEFAULT_UNIT_PATH,
    start: bool = False,
) -> dict[str, Any]:
    binary_path = Path(binary)
    if not binary_path.is_file() and which("xray") is None:
        raise AgentError("CONFIG_NOT_FOUND", f"Xray binary not found at [{binary}]. Install the core first.")

    resolved_binary = str(binary_path if binary_path.is_file() else Path(which("xray") or binary))
    cfg = Path(config_path)
    unit = Path(unit_path)

    wrote_config = write_xray_config_if_missing(
        cfg,
        api_base=api_base,
        username=username,
        password=password,
    )
    write_xray_unit(unit, resolved_binary, str(cfg))

    result: dict[str, Any] = {
        "binary": resolved_binary,
        "config": str(cfg),
        "unit": str(unit),
        "wrote_config": wrote_config,
        "started": False,
    }

    if not start:
        return result

    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not found; cannot start xray.service")

    run_cmd(["systemctl", "daemon-reload"], check=False)
    enabled = systemctl("enable", XRAY_UNIT)
    started = systemctl("start", XRAY_UNIT)

    for _ in range(8):
        if service_is_active(XRAY_UNIT):
            result["started"] = True
            result["enable"] = enabled
            result["start"] = started
            return result
        time.sleep(0.25)

    logs = _journal(XRAY_UNIT)
    detail = started.get("stderr") or started.get("stdout") or logs or "xray.service did not become active"
    raise AgentError(
        "VALIDATION_ERROR",
        f"Failed to start xray.service: {detail}",
    )


def stop_xray_service() -> dict[str, Any]:
    stopped = systemctl("stop", XRAY_UNIT)
    disabled = systemctl("disable", XRAY_UNIT)
    return {"stop": stopped, "disable": disabled, "ok": bool(stopped.get("ok"))}


def restart_xray_service(
    *,
    binary: str,
    config_path: str,
    api_base: str,
    username: str = "",
    password: str = "",
) -> dict[str, Any]:
    prepared = ensure_xray_runtime(
        binary=binary,
        config_path=config_path,
        api_base=api_base,
        username=username,
        password=password,
        start=False,
    )
    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not found; cannot restart xray.service")
    run_cmd(["systemctl", "daemon-reload"], check=False)
    restarted = systemctl("restart", XRAY_UNIT)
    if not restarted.get("ok") and not service_is_active(XRAY_UNIT):
        logs = _journal(XRAY_UNIT)
        raise AgentError(
            "VALIDATION_ERROR",
            f"Failed to restart xray.service: {restarted.get('stderr') or logs or 'unknown error'}",
        )
    prepared["restart"] = restarted
    prepared["started"] = service_is_active(XRAY_UNIT)
    return prepared
