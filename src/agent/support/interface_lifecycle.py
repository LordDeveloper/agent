"""Parallel, fault-isolated interface lifecycle operations.

Each interface runs under its own lock and timeout. A failure or timeout on
one interface does not cancel the others. Restart is stop then start for that
interface, while other interfaces proceed at the same time.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from agent.asyncutil import bounded_gather
from agent.logutil import get_logger

log = get_logger("interface_lifecycle")

Worker = Callable[[str, str, str], Awaitable[Any]]

DEFAULT_CONCURRENCY = 4
DEFAULT_TIMEOUT = 180.0
_OPERATIONS = frozenset({"start", "stop", "restart"})


class InterfaceLockRegistry:
    """One lock per interface so different interfaces stay concurrent."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def lock(self, key: str) -> asyncio.Lock:
        name = str(key or "")
        existing = self._locks.get(name)
        if existing is None:
            existing = asyncio.Lock()
            self._locks[name] = existing
        return existing


def lifecycle_limits(settings: Any, *, default_timeout: float = DEFAULT_TIMEOUT) -> tuple[int, float]:
    """Read the shared concurrency and per-interface timeout knobs."""
    raw_limit = getattr(settings, "interface_lifecycle_concurrency", DEFAULT_CONCURRENCY)
    raw_timeout = getattr(settings, "interface_lifecycle_timeout", default_timeout)
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        limit = DEFAULT_CONCURRENCY
    try:
        timeout = float(raw_timeout)
    except (TypeError, ValueError):
        timeout = default_timeout
    return max(1, limit), max(1.0, timeout)


def summarize(results: Sequence[dict[str, Any]]) -> dict[str, int]:
    successful = sum(1 for row in results if row.get("ok"))
    timed_out = sum(1 for row in results if row.get("timed_out"))
    failed = sum(1 for row in results if not row.get("ok") and not row.get("timed_out"))
    return {
        "total": len(results),
        "successful": successful,
        "failed": failed,
        "timed_out": timed_out,
    }


def _is_timeout(outcome: Any) -> bool:
    return isinstance(outcome, dict) and bool(outcome.get("timed_out"))


def _interpret(outcome: Any) -> tuple[bool, bool, str | None]:
    if not isinstance(outcome, dict):
        return True, False, None
    timed_out = bool(outcome.get("timed_out"))
    ok = bool(outcome.get("ok", True)) and not timed_out
    if ok:
        return True, False, None
    error = outcome.get("error") or outcome.get("message") or outcome.get("stderr") or "operation failed"
    text = str(error).strip() or "operation failed"
    return False, timed_out, text


def _timeout_message(verb: str, exc: BaseException, timeout_s: float) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        limit = exc.timeout if exc.timeout is not None else timeout_s
        try:
            shown = f"{float(limit):g}"
        except (TypeError, ValueError):
            shown = str(limit)
        return f"{verb} timed out after {shown}s"
    try:
        shown = f"{float(timeout_s):g}"
    except (TypeError, ValueError):
        shown = str(timeout_s)
    return f"{verb} timed out after {shown}s"


async def run_interface_operations(
    interfaces: Sequence[tuple[str, str]],
    operation: str,
    worker: Worker,
    *,
    locks: InterfaceLockRegistry,
    limit: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Run ``operation`` on each interface and wait until every one finishes.

    ``interfaces`` is ``(interface_id, interface_name)``. ``worker`` performs
    one step (``start`` or ``stop``) and either returns a mapping or raises.
    A mapping with ``ok`` false or ``timed_out`` true is that interface's
    result; it does not affect the other interfaces.
    """
    verb = str(operation or "").strip().lower()
    if verb not in _OPERATIONS:
        raise ValueError("action must be start, stop, or restart")

    active_log = logger or log
    timeout_s = max(1.0, float(timeout))
    concurrency = max(1, int(limit))
    scheduled = [(str(interface_id), str(interface_name)) for interface_id, interface_name in interfaces]

    async def one(interface_id: str, interface_name: str) -> dict[str, Any]:
        lock_key = interface_name or interface_id
        async with locks.lock(lock_key):
            return await _run_locked(
                interface_id,
                interface_name,
                verb,
                worker,
                timeout_s,
                active_log,
            )

    factories = [
        (lambda interface_id=interface_id, interface_name=interface_name: one(interface_id, interface_name))
        for interface_id, interface_name in scheduled
    ]
    raw = await bounded_gather(factories, limit=concurrency, return_exceptions=True)
    results: list[dict[str, Any]] = []
    for (interface_id, interface_name), item in zip(scheduled, raw):
        if isinstance(item, dict):
            results.append(item)
            continue
        error = item if isinstance(item, BaseException) else RuntimeError(str(item))
        results.append(
            _row_from_exception(
                interface_id,
                interface_name,
                verb,
                error,
                timeout_s,
                duration_ms=0,
                active_log=active_log,
            )
        )

    summary = summarize(results)
    errors = [
        {
            "iface": str(row.get("interface_name") or row.get("name") or ""),
            "interface_id": str(row.get("interface_id") or ""),
            "error": str(row.get("error") or ""),
        }
        for row in results
        if not row.get("ok")
    ]
    active_log.info(
        "interface lifecycle batch op=%s total=%s successful=%s failed=%s timed_out=%s",
        verb,
        summary["total"],
        summary["successful"],
        summary["failed"],
        summary["timed_out"],
    )
    return {
        "ok": summary["failed"] == 0 and summary["timed_out"] == 0,
        "action": verb,
        "operation": verb,
        "results": results,
        "interfaces": results,
        "summary": summary,
        "count": summary["successful"],
        "failed_count": summary["failed"] + summary["timed_out"],
        "errors": errors,
    }


async def _run_locked(
    interface_id: str,
    interface_name: str,
    verb: str,
    worker: Worker,
    timeout_s: float,
    active_log: logging.Logger,
) -> dict[str, Any]:
    started = time.perf_counter()
    active_log.info(
        "interface lifecycle start id=%s name=%s op=%s timeout_s=%s",
        interface_id,
        interface_name,
        verb,
        timeout_s,
    )
    try:
        outcome = await asyncio.wait_for(
            _execute(worker, interface_id, interface_name, verb),
            timeout=timeout_s,
        )
    except asyncio.CancelledError:
        duration_ms = _elapsed_ms(started)
        active_log.warning(
            "interface lifecycle cancelled id=%s name=%s op=%s duration_ms=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
        )
        raise
    except (asyncio.TimeoutError, TimeoutError, subprocess.TimeoutExpired) as exc:
        return _row_from_exception(
            interface_id,
            interface_name,
            verb,
            exc,
            timeout_s,
            duration_ms=_elapsed_ms(started),
            active_log=active_log,
        )
    except Exception as exc:
        duration_ms = _elapsed_ms(started)
        active_log.error(
            "interface lifecycle failed id=%s name=%s op=%s duration_ms=%s error=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
            exc,
        )
        row = _base_row(interface_id, interface_name, verb)
        row.update(
            {
                "ok": False,
                "timed_out": False,
                "error": str(exc) or exc.__class__.__name__,
                "message": str(exc) or exc.__class__.__name__,
                "duration_ms": duration_ms,
                "code": getattr(exc, "code", None) or "EXEC_ERROR",
                "status": int(getattr(exc, "status", None) or 500),
            }
        )
        return row

    duration_ms = _elapsed_ms(started)
    ok, timed_out, error = _interpret(outcome)
    row = _base_row(interface_id, interface_name, verb)
    if isinstance(outcome, dict):
        row.update(outcome)
    row["interface_id"] = interface_id
    row["interface_name"] = interface_name
    row["id"] = interface_id
    row["name"] = interface_name or str(row.get("name") or "")
    row["operation"] = verb
    row["action"] = verb
    row["ok"] = ok
    row["timed_out"] = timed_out
    row["error"] = error
    row["duration_ms"] = duration_ms
    if error and not row.get("message"):
        row["message"] = error
    if ok:
        active_log.info(
            "interface lifecycle done id=%s name=%s op=%s duration_ms=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
        )
    elif timed_out:
        active_log.warning(
            "interface lifecycle timeout id=%s name=%s op=%s duration_ms=%s error=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
            error,
        )
    else:
        active_log.error(
            "interface lifecycle failed id=%s name=%s op=%s duration_ms=%s error=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
            error,
        )
    return row


async def _execute(worker: Worker, interface_id: str, interface_name: str, verb: str) -> Any:
    if verb != "restart":
        return await worker(interface_id, interface_name, verb)
    # Stop must finish (or time out) before start. A timed-out stop owns the
    # interface until its process is reaped, so start must not race it.
    stopped = await worker(interface_id, interface_name, "stop")
    if _is_timeout(stopped):
        return stopped
    started = await worker(interface_id, interface_name, "start")
    if isinstance(started, dict) and started.get("ok", True) and not started.get("timed_out"):
        started = {**started, "message": f"restarted {interface_name}", "action": "restart"}
    return started


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _base_row(interface_id: str, interface_name: str, verb: str) -> dict[str, Any]:
    return {
        "interface_id": interface_id,
        "interface_name": interface_name,
        "id": interface_id,
        "name": interface_name,
        "iface": interface_name,
        "operation": verb,
        "action": verb,
    }


def _row_from_exception(
    interface_id: str,
    interface_name: str,
    verb: str,
    exc: BaseException,
    timeout_s: float,
    *,
    duration_ms: int,
    active_log: logging.Logger,
) -> dict[str, Any]:
    timed_out = isinstance(exc, (asyncio.TimeoutError, TimeoutError, subprocess.TimeoutExpired))
    if timed_out:
        error = _timeout_message(verb, exc, timeout_s)
        active_log.warning(
            "interface lifecycle timeout id=%s name=%s op=%s duration_ms=%s error=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
            error,
        )
    else:
        error = str(exc) or exc.__class__.__name__
        active_log.error(
            "interface lifecycle failed id=%s name=%s op=%s duration_ms=%s error=%s",
            interface_id,
            interface_name,
            verb,
            duration_ms,
            error,
        )
    row = _base_row(interface_id, interface_name, verb)
    row.update(
        {
            "ok": False,
            "timed_out": timed_out,
            "error": error,
            "message": error,
            "duration_ms": duration_ms,
            "code": "EXEC_ERROR",
            "status": 504 if timed_out else 500,
        }
    )
    return row
