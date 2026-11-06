"""ASGI server wrapper.

One request must not hold the socket open with zero bytes. Panel polls get a
JSON body within a few seconds (the last good payload, marked stale). Other
routes get a JSON error when their own longer deadline expires. The body is
not read twice, and a client disconnect cancels the handler.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import OrderedDict
from typing import Any

from agent.asyncutil import panel_read_path, read_deadline, short_read_path
from agent.errorlog import core_from_path, parse_error_payload, should_skip_path
from agent.logutil import get_logger
from agent.runtime import RuntimeTrace

log = get_logger("http")

_CACHE_LIMIT = 128


def warn_if_slow_sync_seconds() -> float:
    return 3.0


async def warn_if_slow(request: Any, client: str) -> None:
    try:
        await asyncio.sleep(warn_if_slow_sync_seconds())
    except asyncio.CancelledError:
        return
    path = getattr(getattr(request, "url", None), "path", None) or getattr(request, "path", "-")
    log.warning(
        "request still running method=%s path=%s client=%s request_id=%s runtime=%s",
        getattr(request, "method", "-"),
        path,
        client,
        RuntimeTrace.request_id() or "-",
        RuntimeTrace.header() or "-",
    )


def _set_endpoint_action(scope: dict[str, Any], method: str, path: str) -> None:
    endpoint = scope.get("endpoint")
    name = getattr(endpoint, "__name__", "") if callable(endpoint) else ""
    if name:
        RuntimeTrace.set_action(name)
        return
    if not RuntimeTrace.header():
        RuntimeTrace.set_action(f"{method}.{path}")


def _header_map(scope: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        found[key.decode("latin1").lower()] = value.decode("latin1")
    return found


def _client_host(scope: dict[str, Any]) -> str:
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return "-"


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _parse_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def empty_stale_body(path: str) -> dict[str, Any]:
    """A successful body the panel can store and replace on the next poll."""
    normalized = path.split("?", 1)[0].rstrip("/") or "/"
    body: dict[str, Any] = {"success": True, "stale": True}
    if normalized == "/health" or normalized.endswith("/health"):
        body["service"] = "agent"
    if "/stats" in normalized:
        body["users"] = {}
    if normalized.endswith("/mullvad/locations"):
        body["settings"] = {}
        body["locations"] = []
    return body


def stale_from_cache(cached: dict[str, Any] | None, path: str) -> dict[str, Any]:
    if not isinstance(cached, dict):
        return empty_stale_body(path)
    body = dict(cached)
    body["success"] = True
    body["stale"] = True
    return body


class _ResponseState:
    def __init__(self) -> None:
        self.start: dict[str, Any] | None = None
        self.chunks: list[bytes] = []
        self.status = 0
        self.buffer = False
        self.sent = False


class AgentHttpMiddleware:
    """Pure ASGI middleware. Does not use BaseHTTPMiddleware."""

    def __init__(
        self,
        app: Any,
        *,
        read_response_seconds: float | None = None,
        write_response_seconds: float | None = None,
    ) -> None:
        self.app = app
        self._read_override = read_response_seconds
        self._write_override = write_response_seconds
        self._cache: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "/")
        query = (scope.get("query_string") or b"").decode("latin1")
        headers = _header_map(scope)
        client = _client_host(scope)
        request_id = (headers.get("x-request-id") or "").strip() or uuid.uuid4().hex
        node_id = (headers.get("x-node-id") or headers.get("x-node-host") or "").strip()
        protocol_switch_trace = (headers.get("x-protocol-switch-trace") or "").strip()

        RuntimeTrace.start()
        RuntimeTrace.set_request_id(request_id)
        RuntimeTrace.set_action(f"{method}.{path}")
        if node_id:
            RuntimeTrace.set_node_id(node_id)

        panel = panel_read_path(method, path)
        short = short_read_path(method, path)
        read_budget, write_budget, core_budget = self._budgets(scope)
        deadline = write_budget
        deadline_token = None
        if panel:
            deadline = read_budget
            deadline_token = read_deadline.set(max(0.2, read_budget))
        elif short:
            deadline = max(1.0, core_budget)
            deadline_token = read_deadline.set(deadline)

        state = _ResponseState()
        state.buffer = panel
        cache_key = (method, path, query)
        disconnected = asyncio.Event()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def pump() -> None:
            while True:
                message = await receive()
                await queue.put(message)
                if message.get("type") == "http.disconnect":
                    disconnected.set()
                    return

        async def app_receive() -> dict[str, Any]:
            return await queue.get()

        def decorate(message: dict[str, Any]) -> None:
            _set_endpoint_action(scope, method, path)
            pairs = list(message.get("headers") or [])

            def has(header_name: bytes) -> bool:
                return any(key.lower() == header_name for key, _value in pairs)

            if not has(b"x-request-id"):
                pairs.append((b"x-request-id", request_id.encode("latin1")))
            runtime = RuntimeTrace.header()
            if runtime and not has(b"x-runtime"):
                pairs.append((b"x-runtime", runtime.encode("latin1")))
            message["headers"] = pairs

        async def app_send(message: dict[str, Any]) -> None:
            kind = message.get("type")
            if kind == "http.response.start":
                state.status = int(message.get("status") or 0)
                state.start = message
                state.buffer = panel or state.status >= 400
                if not state.buffer:
                    decorate(message)
                    state.sent = True
                    await send(message)
                return
            if kind != "http.response.body":
                if not state.buffer and state.sent:
                    await send(message)
                return
            body = message.get("body") or b""
            if state.buffer:
                if body:
                    state.chunks.append(body if isinstance(body, (bytes, bytearray)) else bytes(body))
                return
            await send(message)

        started = time.perf_counter()
        watch = asyncio.create_task(self._warn(method, path, client))
        pump_task = asyncio.create_task(pump())
        app_task = asyncio.create_task(self.app(scope, app_receive, app_send))
        status_for_log = 0
        try:
            with RuntimeTrace.span("handler"):
                await self._run_until(app_task, disconnected, deadline)
            timed_out = not app_task.done()
            if timed_out or (disconnected.is_set() and not app_task.done()):
                app_task.cancel()
                await _silence(app_task)
            if disconnected.is_set() and not state.sent:
                status_for_log = 499
                return
            failure = _task_exception(app_task)
            if failure is not None and not state.sent:
                log.exception(
                    "request failed method=%s path=%s client=%s request_id=%s",
                    method,
                    path,
                    client,
                    request_id,
                    exc_info=failure,
                )
                status_for_log = 500
                await self._send_json(
                    send,
                    500,
                    {
                        "success": False,
                        "error": {"code": "INTERNAL_ERROR", "message": type(failure).__name__},
                    },
                    request_id,
                )
                state.sent = True
                return
            if timed_out and not state.sent:
                status_for_log = await self._send_deadline(
                    send,
                    path,
                    cache_key,
                    panel,
                    request_id,
                )
                state.sent = True
                return
            if not state.sent:
                status_for_log = await self._flush(scope, send, state, cache_key, panel, path, request_id)
            else:
                status_for_log = state.status
        finally:
            if not app_task.done():
                app_task.cancel()
                await _silence(app_task)
            pump_task.cancel()
            watch.cancel()
            await _silence(pump_task)
            await _silence(watch)
            if deadline_token is not None:
                read_deadline.reset(deadline_token)
            elapsed_ms = (time.perf_counter() - started) * 1000
            self._log_access(
                scope,
                method,
                path,
                client,
                status_for_log or state.status,
                elapsed_ms,
                protocol_switch_trace,
            )
            RuntimeTrace.reset()

    async def _run_until(self, app_task: asyncio.Task[Any], disconnected: asyncio.Event, deadline: float) -> None:
        disconnect_wait = asyncio.create_task(disconnected.wait())
        try:
            await asyncio.wait(
                {app_task, disconnect_wait},
                timeout=max(0.05, deadline),
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            if not disconnect_wait.done():
                disconnect_wait.cancel()
            await _silence(disconnect_wait)

    async def _flush(
        self,
        scope: dict[str, Any],
        send: Any,
        state: _ResponseState,
        cache_key: tuple[str, str, str],
        panel: bool,
        path: str,
        request_id: str,
    ) -> int:
        if state.start is None:
            await self._send_json(
                send,
                500,
                {"success": False, "error": {"code": "INTERNAL_ERROR", "message": "empty response"}},
                request_id,
            )
            return 500
        body = b"".join(state.chunks)
        _set_endpoint_action(scope, str(scope.get("method") or "GET"), path)
        if panel and state.status == 200:
            parsed = _parse_json(body)
            if isinstance(parsed, dict):
                self._remember(cache_key, parsed)
        if state.status >= 400:
            self._record_error(scope, path, state.status, body)
        self._decorate_start(state.start, request_id)
        await send(state.start)
        await send({"type": "http.response.body", "body": body})
        state.sent = True
        return state.status

    async def _send_deadline(
        self,
        send: Any,
        path: str,
        cache_key: tuple[str, str, str],
        panel: bool,
        request_id: str,
    ) -> int:
        if panel:
            payload = stale_from_cache(self._cache.get(cache_key), path)
            await self._send_json(send, 200, payload, request_id)
            log.warning(
                "read deadline path=%s request_id=%s stale=%s",
                path,
                request_id,
                "cache" if cache_key in self._cache else "empty",
            )
            return 200
        await self._send_json(
            send,
            504,
            {
                "success": False,
                "error": {
                    "code": "READ_DEADLINE",
                    "message": "request exceeded the server deadline",
                },
            },
            request_id,
        )
        log.warning("write deadline path=%s request_id=%s", path, request_id)
        return 504

    async def _send_json(
        self,
        send: Any,
        status: int,
        payload: dict[str, Any],
        request_id: str,
    ) -> None:
        body = _json_bytes(payload)
        message = {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
        self._decorate_start(message, request_id)
        await send(message)
        await send({"type": "http.response.body", "body": body})

    def _decorate_start(self, message: dict[str, Any], request_id: str) -> None:
        pairs = list(message.get("headers") or [])

        def has(header_name: bytes) -> bool:
            return any(key.lower() == header_name for key, _value in pairs)

        if not has(b"x-request-id"):
            pairs.append((b"x-request-id", request_id.encode("latin1")))
        runtime = RuntimeTrace.header()
        if runtime and not has(b"x-runtime"):
            pairs.append((b"x-runtime", runtime.encode("latin1")))
        message["headers"] = pairs

    def _record_error(self, scope: dict[str, Any], path: str, status: int, body: bytes) -> None:
        if should_skip_path(path):
            return
        app = scope.get("app")
        errors = getattr(getattr(app, "state", None), "errors", None)
        if errors is None:
            return
        code, message, detail = parse_error_payload(body)
        if not message:
            message = f"HTTP {status}"
        errors.record(
            core=core_from_path(path),
            message=message,
            code=code or ("HTTP_ERROR" if status < 500 else "INTERNAL_ERROR"),
            level="error" if status >= 500 else "warning",
            method=str(scope.get("method") or ""),
            path=path,
            status=status,
            detail=detail,
        )

    def _remember(self, key: tuple[str, str, str], payload: dict[str, Any]) -> None:
        stored = dict(payload)
        stored.pop("stale", None)
        self._cache[key] = stored
        self._cache.move_to_end(key)
        while len(self._cache) > _CACHE_LIMIT:
            self._cache.popitem(last=False)

    def _budgets(self, scope: dict[str, Any]) -> tuple[float, float, float]:
        settings = getattr(getattr(scope.get("app"), "state", None), "settings", None)
        read_budget = self._read_override
        if read_budget is None:
            read_budget = float(getattr(settings, "read_response_seconds", 3.0) or 3.0)
        write_budget = self._write_override
        if write_budget is None:
            write_budget = float(getattr(settings, "write_response_seconds", 180.0) or 180.0)
        core_budget = float(getattr(settings, "read_budget_seconds", 12.0) or 12.0)
        return max(0.2, read_budget), max(1.0, write_budget), max(1.0, core_budget)

    def _log_access(
        self,
        scope: dict[str, Any],
        method: str,
        path: str,
        client: str,
        status: int,
        elapsed_ms: float,
        protocol_switch_trace: str,
    ) -> None:
        settings = getattr(getattr(scope.get("app"), "state", None), "settings", None)
        slow_ms = float(getattr(settings, "slow_request_log_ms", 0) or 0) if settings is not None else 0.0
        runtime_h = RuntimeTrace.header() or "-"
        level = log.warning if status >= 400 else log.info
        extra: dict[str, str] = {}
        if protocol_switch_trace:
            extra["protocol_switch_trace"] = protocol_switch_trace
        msg = "method=%s path=%s status=%s client=%s duration_ms=%.1f runtime=%s"
        args = (method, path, status, client, elapsed_ms, runtime_h)
        if extra:
            level(msg, *args, extra=extra)
        else:
            level(msg, *args)
        if slow_ms > 0 and elapsed_ms >= slow_ms:
            slow_msg = (
                "slow_request_detail method=%s path=%s status=%s client=%s "
                "request_id=%s duration_ms=%.1f runtime=%s"
            )
            slow_args = (
                method,
                path,
                status,
                client,
                RuntimeTrace.request_id() or "-",
                elapsed_ms,
                runtime_h,
            )
            if extra:
                log.warning(slow_msg, *slow_args, extra=extra)
            else:
                log.warning(slow_msg, *slow_args)

    @staticmethod
    async def _warn(method: str, path: str, client: str) -> None:
        request = _WarnRequest(method, path)
        await warn_if_slow(request, client)


class _WarnRequest:
    def __init__(self, method: str, path: str) -> None:
        self.method = method
        self.path = path
        self.url = self

    def __repr__(self) -> str:
        return f"{self.method} {self.path}"


def _task_exception(task: asyncio.Task[Any]) -> BaseException | None:
    if not task.done() or task.cancelled():
        return None
    try:
        return task.exception()
    except asyncio.CancelledError:
        return None


async def _silence(task: asyncio.Task[Any]) -> None:
    try:
        await task
    except (asyncio.CancelledError, Exception):
        return

