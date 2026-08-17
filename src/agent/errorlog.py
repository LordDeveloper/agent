from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from agent.logutil import flush_logging, get_logger
from agent.routing import SLUG_TO_CORE

_CORE_PATH = re.compile(r"^/(?:api/v1/)?cores/(xray|wireguard|amnezia)(?:/|$)", re.IGNORECASE)
_SKIP_SUFFIXES = ("/health", "/errors")
_CORES = ("xray", "wireguard", "amnezia", "agent")
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\] "
    r"agent\.(?P<core>xray|wireguard|amnezia|agent): "
    r"core_error (?P<body>.*)$"
)

log = get_logger("errors")


class CoreErrorLog:
    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)

    def record(self, **kwargs: Any) -> dict[str, Any]:
        core = str(kwargs.get("core") or "agent").strip().lower() or "agent"
        if core not in _CORES:
            core = "agent"

        level = str(kwargs.get("level") or "error").strip().lower()
        code = str(kwargs.get("code") or "")[:64]
        message = " ".join(str(kwargs.get("message") or "").split())[:1000]
        method = str(kwargs.get("method") or "")[:16]
        path = str(kwargs.get("path") or "")[:256]
        status = int(kwargs.get("status") or 0)

        logger = get_logger(core)
        emit = logger.error if level == "error" else logger.warning
        emit(
            "core_error code=%s status=%s method=%s path=%s message=%s",
            code,
            status,
            method,
            path,
            message,
        )
        flush_logging()

        return {
            "core": core,
            "level": "error" if level == "error" else "warning",
            "code": code,
            "message": message,
            "method": method,
            "path": path,
            "status": status,
        }

    def list(self, core: str | None = None, limit: int = 40, level: str | None = None) -> list[dict[str, Any]]:
        return list_log_errors(self.log_path, core=core, limit=limit, level=level)


def core_from_path(path: str) -> str:
    match = _CORE_PATH.search(path or "")
    if match:
        slug = match.group(1).lower()
        return SLUG_TO_CORE.get(slug, slug)
    return "agent"


def should_skip_path(path: str) -> bool:
    normalized = (path or "").rstrip("/")
    return any(normalized.endswith(suffix) for suffix in _SKIP_SUFFIXES)


def parse_error_payload(body: bytes | str | None) -> tuple[str, str, str]:
    """Return (code, message, detail)."""
    if not body:
        return "", "", ""

    text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else str(body)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "", text[:400], text[:2000]

    if not isinstance(payload, dict):
        return "", text[:400], text[:2000]

    error = payload.get("error")
    detail = payload.get("detail")

    if isinstance(error, dict):
        code = str(error.get("code") or "")
        message = str(error.get("message") or "")
        return code, message, text[:2000]

    if isinstance(detail, dict):
        nested = detail.get("error") if isinstance(detail.get("error"), dict) else detail
        code = str(nested.get("code") or "")
        message = str(nested.get("message") or nested.get("msg") or "")
        return code, message, text[:2000]

    if isinstance(detail, list) and detail:
        first = detail[0] if isinstance(detail[0], dict) else {"msg": str(detail[0])}
        message = str(first.get("msg") or first.get("message") or first)
        return "VALIDATION_ERROR", message[:400], text[:2000]

    if isinstance(detail, str) and detail:
        return "", detail[:400], text[:2000]

    return "", str(payload.get("message") or text)[:400], text[:2000]


def parse_fields(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "code": "",
        "status": 0,
        "method": "",
        "path": "",
        "message": "",
    }
    marker = " message="
    msg_at = body.find(marker)
    prefix = body if msg_at < 0 else body[:msg_at]
    if msg_at >= 0:
        result["message"] = body[msg_at + len(marker) :]

    for part in prefix.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key in ("code", "method", "path"):
            result[key] = value
        elif key == "status":
            result["status"] = int(value) if value.lstrip("-").isdigit() else 0

    return result


def parse_log_line(line: str) -> dict[str, Any] | None:
    match = _LINE_RE.match((line or "").rstrip("\n"))
    if not match:
        return None

    level = match.group("level").lower()
    if level == "critical":
        level = "error"
    elif level not in ("warning", "error"):
        return None

    fields = parse_fields(match.group("body"))
    ts = match.group("ts").replace(" ", "T")
    return {
        "id": 0,
        "ts": ts,
        "core": match.group("core"),
        "level": level,
        "code": fields["code"],
        "message": fields["message"],
        "method": fields["method"],
        "path": fields["path"],
        "status": fields["status"],
        "detail": "",
    }


def _tail_lines(path: Path, max_bytes: int = 512_000) -> list[str]:
    if not path.is_file():
        return []

    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes))
        data = handle.read()

    return data.decode("utf-8", errors="replace").splitlines()


def list_log_errors(
    log_path: str | Path,
    core: str | None = None,
    limit: int = 40,
    level: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    core_key = (core or "").strip().lower() or None
    level_key = (level or "").strip().lower() or None
    if level_key == "warn":
        level_key = "warning"

    path = Path(log_path)
    files = [path]
    for index in range(1, 6):
        rotated = path.with_name(f"{path.name}.{index}")
        if rotated.is_file():
            files.append(rotated)

    rows: list[dict[str, Any]] = []
    for file_path in files:
        for line in reversed(_tail_lines(file_path)):
            parsed = parse_log_line(line)
            if parsed is None:
                continue
            if core_key and parsed["core"] != core_key:
                continue
            if level_key and parsed["level"] != level_key:
                continue
            rows.append(parsed)
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break

    for index, row in enumerate(rows, start=1):
        row["id"] = index

    return rows


async def read_response_body(response: Response) -> tuple[bytes, Response]:
    body = getattr(response, "body", b"") or b""
    if body:
        return (body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "replace")), response

    iterator = getattr(response, "body_iterator", None)
    if iterator is None:
        return b"", response

    chunks: list[bytes] = []
    async for chunk in iterator:
        if isinstance(chunk, memoryview):
            chunk = chunk.tobytes()
        elif isinstance(chunk, str):
            chunk = chunk.encode("utf-8", "replace")
        elif not isinstance(chunk, (bytes, bytearray)):
            chunk = bytes(chunk)
        chunks.append(chunk)
    data = b"".join(chunks)

    async def replay():
        yield data

    response.body_iterator = replay()
    return data, response


class CoreErrorCaptureMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        if response.status_code < 400:
            return response

        path = request.url.path
        if should_skip_path(path):
            return response

        errors: CoreErrorLog | None = getattr(request.app.state, "errors", None)
        if errors is None:
            return response

        body, response = await read_response_body(response)
        code, message, _detail = parse_error_payload(body)
        if not message:
            message = f"HTTP {response.status_code}"

        errors.record(
            core=core_from_path(path),
            message=message,
            code=code or ("HTTP_ERROR" if response.status_code < 500 else "INTERNAL_ERROR"),
            level="error" if response.status_code >= 500 else "warning",
            method=request.method,
            path=path,
            status=response.status_code,
        )

        return response
