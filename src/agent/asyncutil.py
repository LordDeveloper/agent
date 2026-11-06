from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from contextvars import ContextVar
from typing import Any, TypeVar

T = TypeVar("T")

# Fallback when read_deadline ContextVar is unset (CLI/tests). The server sets
# the budget per request from AgentSettings.read_budget_seconds (default 12s) so
# core I/O stays within typical Laravel Guzzle timeouts while still failing before
# bare 45s core budgets.
READ_BUDGET_SECONDS = 12.0
read_deadline: ContextVar[float | None] = ContextVar("agent_read_deadline", default=None)


async def maybe_await(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


def run_sync(value: T | Awaitable[T]) -> T:
    """Run an awaitable from sync CLI/menu code.

    Sync entry points (argparse, the text menu) must use this instead of
    touching a coroutine. It must not be called from the server loop: waiting
    here freezes every connection, which shows up as HTTP timeouts with
    0 bytes received.
    """
    if not inspect.isawaitable(value):
        return value
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(value)

    # Close the coroutine so it does not leak a "never awaited" warning.
    close = getattr(value, "close", None)
    if callable(close):
        close()
    raise RuntimeError(
        "run_sync() was called on the running event loop. Await the coroutine instead; "
        "blocking here stalls every in-flight request."
    )


async def gather_independent(
    *coros: Coroutine[Any, Any, T] | Awaitable[T],
    return_exceptions: bool = False,
) -> list[T | BaseException]:
    if not coros:
        return []
    return await asyncio.gather(*coros, return_exceptions=return_exceptions)


def is_upstream_failure(exc: BaseException) -> bool:
    """A core that did not answer. This is not an empty stats or user list."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return True
    status = getattr(exc, "status", None)
    code = getattr(exc, "code", None)
    if code == "UPSTREAM_TIMEOUT":
        return True
    if isinstance(status, int) and status >= 500:
        return True
    return type(exc).__name__ in {"TimeoutExpired", "ConnectTimeout", "ReadTimeout"}


def _request_path(path: str) -> str:
    return path.split("?", 1)[0].rstrip("/") or "/"


def short_read_path(method: str, path: str) -> bool:
    """Routes whose result the panel can replace on the next poll."""
    if method.upper() not in {"GET", "HEAD"}:
        return False
    normalized = _request_path(path)
    if normalized == "/health" or normalized.endswith("/health"):
        return True
    if normalized.startswith("/api/v1/stats") or normalized.startswith("/cores/"):
        return True
    if normalized == "/api/v1/mullvad/locations":
        return True
    return "/diagnose" in normalized


def panel_read_path(method: str, path: str) -> bool:
    """Polls that must answer in a few seconds, from cache when the handler is slow."""
    if method.upper() not in {"GET", "HEAD"}:
        return False
    normalized = _request_path(path)
    if normalized == "/health" or normalized.endswith("/health"):
        return True
    if normalized.startswith("/api/v1/stats"):
        return True
    return normalized == "/api/v1/mullvad/locations"


async def wait_signal(wake: asyncio.Event, stop: asyncio.Event, timeout: float) -> str:
    """Wait until ``wake``, ``stop``, or ``timeout``. Stop wins when both are set."""
    if stop.is_set():
        return "stop"
    if wake.is_set():
        return "wake"
    wake_task = asyncio.create_task(wake.wait())
    stop_task = asyncio.create_task(stop.wait())
    try:
        done, _pending = await asyncio.wait(
            {wake_task, stop_task},
            timeout=max(0.0, float(timeout)),
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for task in (wake_task, stop_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(wake_task, stop_task, return_exceptions=True)
    if stop.is_set():
        return "stop"
    if not done:
        return "timeout"
    return "wake"


async def bounded_gather(
    factories: Sequence[Callable[[], Awaitable[T]]],
    *,
    limit: int = 16,
    return_exceptions: bool = False,
) -> list[T | BaseException]:
    if not factories:
        return []
    sem = asyncio.Semaphore(max(1, int(limit)))

    async def run(factory: Callable[[], Awaitable[T]]) -> T:
        async with sem:
            return await factory()

    return await asyncio.gather(
        *(run(factory) for factory in factories),
        return_exceptions=return_exceptions,
    )
