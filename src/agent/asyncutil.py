from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from typing import Any, TypeVar

T = TypeVar("T")


async def maybe_await(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


def run_sync(value: T | Awaitable[T]) -> T:
    """Run an awaitable from sync CLI/menu code."""
    if inspect.isawaitable(value):
        return asyncio.run(value)
    return value


async def invoke(fn: Callable[..., T | Awaitable[T]], /, *args: Any, **kwargs: Any) -> T:
    """Run an async function natively, or a sync function in a worker thread."""
    if asyncio.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    return await asyncio.to_thread(fn, *args, **kwargs)


async def gather_independent(
    *coros: Coroutine[Any, Any, T] | Awaitable[T],
    return_exceptions: bool = False,
) -> list[T | BaseException]:
    if not coros:
        return []
    return await asyncio.gather(*coros, return_exceptions=return_exceptions)


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
