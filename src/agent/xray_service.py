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
_HTTPAPI_NEEDLES = (b"httpapi", b"/api/stats/sys", b"/api/inbounds/list")
STOCK_XRAY_HINT = (
    "Xray binary has no HTTP API (usually official/XTLS Xray). "
    "Reinstall the customized core from LordDeveloper/xray via the admin panel "
    "(node needs GITHUB_TOKEN)."
)


def binary_has_httpapi(binary: str | Path | None) -> bool:
    """True when the binary looks like customized Xray with HTTP API."""
    if not binary:
        return False
    path = Path(binary)
    if not path.is_file():
        resolved = which("xray")
        if not resolved:
            return False
        path = Path(resolved)
    try:
        leftover = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(256 * 1024)
                if not chunk:
                    return False
                blob = leftover + chunk
                if any(needle in blob for needle in _HTTPAPI_NEEDLES):
                    return True
                leftover = blob[-32:]
    except OSError:
        return False


def client_api_base(listen: str, fallback: str = "http://127.0.0.1:8080") -> str:
    text = (listen or "").strip() or fallback
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080
    else:
        host, sep, port = text.partition(":")
        if not sep:
            host, port = "127.0.0.1", text
        host = host or "127.0.0.1"
        port = port or 8080
    hostname = str(host).strip("[]")
    if hostname in {"0.0.0.0", "::", ""}:
        hostname = "127.0.0.1"
    return f"http://{hostname}:{port}".rstrip("/")


def httpapi_listen(api_base: str) -> str:
    parsed = urlparse(api_base or "http://127.0.0.1:8080")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8080
    return f"{host}:{port}"


def api_base_from_config(config_path: Path, fallback: str) -> str:
    if not config_path.is_file():
        return client_api_base(fallback)

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return client_api_base(fallback)

    httpapi = data.get("httpapi")
    if not isinstance(httpapi, dict):
        return client_api_base(fallback)

    listen = str(httpapi.get("listen") or "").strip()
    if not listen:
        return client_api_base(fallback)
    return client_api_base(listen, fallback)


def xray_auth_from_config(config_path: Path, username: str, password: str) -> tuple[str, str]:
    if not config_path.is_file():
        return username, password

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return username, password

    httpapi = data.get("httpapi")
    if not isinstance(httpapi, dict):
        return username, password

    return (
        str(httpapi.get("username") or username),
        str(httpapi.get("password") or password),
    )


def _httpapi_matches(desired: dict[str, Any], current: dict[str, Any]) -> bool:
    for key in ("listen", "config_path", "username", "password"):
        if str(desired.get(key) or "") != str(current.get(key) or ""):
            return False
    return True


def ensure_xray_httpapi_config(
    config_path: Path,
    *,
    api_base: str,
    username: str = "",
    password: str = "",
) -> bool:
    desired_httpapi: dict[str, Any] = {
        "listen": httpapi_listen(api_base),
        "config_path": str(config_path),
    }
    if username:
        desired_httpapi["username"] = username
    if password:
        desired_httpapi["password"] = password

    if not config_path.is_file():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = default_xray_config(
            api_base=api_base,
            username=username,
            password=password,
            config_path=str(config_path),
        )
        config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return True

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = default_xray_config(
            api_base=api_base,
            username=username,
            password=password,
            config_path=str(config_path),
        )
        config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return True

    current = data.get("httpapi") if isinstance(data.get("httpapi"), dict) else {}
    if _httpapi_matches(desired_httpapi, current):
        return False

    data["httpapi"] = {**current, **desired_httpapi}
    config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return True


def wait_xray_http_api(
    *,
    api_base: str,
    username: str = "",
    password: str = "",
    attempts: int = 20,
    delay: float = 0.25,
) -> None:
    import httpx

    auth = (username, password) if username and password else None
    url = f"{api_base.rstrip('/')}/api/stats/sys"
    last_error = "unknown"

    for _ in range(max(1, attempts)):
        try:
            response = httpx.get(url, auth=auth, timeout=3.0)
            # Only 2xx means the customized HTTP API is actually serving routes.
            # Stock Xray / wrong port often answers bare "404 page not found".
            if 200 <= response.status_code < 300:
                return
            last_error = f"HTTP {response.status_code}: {(response.text or '').strip()[:120] or 'empty'}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(delay)

    raise AgentError(
        "CONFIG_NOT_FOUND",
        f"Xray HTTP API unreachable at [{api_base}]: {last_error}",
    )


def _unreachable_detail(api_error: str, logs: str = "") -> str:
    parts = [api_error]
    snippet = " ".join((logs or "").split())
    if snippet:
        parts.append(snippet[-700:])
    parts.append(STOCK_XRAY_HINT)
    return " | ".join(parts)


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

    httpapi_changed = ensure_xray_httpapi_config(
        cfg,
        api_base=api_base,
        username=username,
        password=password,
    )
    wrote_config = httpapi_changed
    write_xray_unit(unit, resolved_binary, str(cfg))
    reachable_api = api_base_from_config(cfg, api_base)
    auth_user, auth_pass = xray_auth_from_config(cfg, username, password)

    result: dict[str, Any] = {
        "binary": resolved_binary,
        "config": str(cfg),
        "unit": str(unit),
        "wrote_config": wrote_config,
        "httpapi_synced": httpapi_changed,
        "started": False,
        "httpapi": reachable_api,
        "httpapi_capable": binary_has_httpapi(resolved_binary),
    }

    if not start:
        return result

    if not binary_has_httpapi(resolved_binary):
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"Xray at [{resolved_binary}] has no HTTP API. {STOCK_XRAY_HINT}",
        )

    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not found; cannot start xray.service")

    run_cmd(["systemctl", "reset-failed", XRAY_UNIT], check=False)
    run_cmd(["systemctl", "daemon-reload"], check=False)
    enabled = systemctl("enable", XRAY_UNIT)
    if httpapi_changed and service_is_active(XRAY_UNIT):
        systemctl("restart", XRAY_UNIT)
        started = {"ok": True}
    else:
        started = systemctl("start", XRAY_UNIT)

    for _ in range(20):
        if service_is_active(XRAY_UNIT):
            try:
                wait_xray_http_api(
                    api_base=reachable_api,
                    username=auth_user,
                    password=auth_pass,
                    attempts=40,
                    delay=0.3,
                )
            except AgentError as exc:
                raise AgentError(
                    "VALIDATION_ERROR",
                    _unreachable_detail(exc.message, _journal(XRAY_UNIT)),
                ) from exc
            result["started"] = True
            result["enable"] = enabled
            result["start"] = started
            return result
        time.sleep(0.25)

    logs = _journal(XRAY_UNIT)
    detail = started.get("stderr") or started.get("stdout") or logs or "xray.service did not become active"
    raise AgentError(
        "VALIDATION_ERROR",
        _unreachable_detail(f"Failed to start xray.service: {detail}", logs),
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
    if not binary_has_httpapi(prepared.get("binary") or binary):
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"Xray at [{prepared.get('binary') or binary}] has no HTTP API. {STOCK_XRAY_HINT}",
        )
    run_cmd(["systemctl", "reset-failed", XRAY_UNIT], check=False)
    run_cmd(["systemctl", "daemon-reload"], check=False)
    restarted = systemctl("restart", XRAY_UNIT)
    if not restarted.get("ok") and not service_is_active(XRAY_UNIT):
        logs = _journal(XRAY_UNIT)
        raise AgentError(
            "VALIDATION_ERROR",
            _unreachable_detail(
                f"Failed to restart xray.service: {restarted.get('stderr') or logs or 'unknown error'}",
                logs,
            ),
        )
    reachable_api = str(prepared.get("httpapi") or api_base_from_config(Path(config_path), api_base))
    auth_user, auth_pass = xray_auth_from_config(Path(config_path), username, password)
    try:
        wait_xray_http_api(
            api_base=reachable_api,
            username=auth_user,
            password=auth_pass,
            attempts=40,
            delay=0.3,
        )
    except AgentError as exc:
        raise AgentError(
            "VALIDATION_ERROR",
            _unreachable_detail(exc.message, _journal(XRAY_UNIT)),
        ) from exc
    prepared["restart"] = restarted
    prepared["started"] = service_is_active(XRAY_UNIT)
    return prepared
