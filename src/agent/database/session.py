from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, TypeVar

from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agent.database.engine import configure_sqlite_pragmas, create_read_engine, create_write_engine
from agent.logutil import get_logger
from agent.runtime import RuntimeTrace

_sql_log = get_logger("sql")

LOCK_ATTEMPTS = 4
STATEMENTS_PER_COMMIT = 100

T = TypeVar("T")


def _is_db_locked(exc: BaseException) -> bool:
    if isinstance(exc, OperationalError):
        orig = getattr(exc, "orig", None)
        if isinstance(orig, sqlite3.OperationalError) and "locked" in str(orig).lower():
            return True
    if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
        return True
    return False


class DatabaseRuntime:
    """Async SQLAlchemy session management with write lock and read engine."""

    def __init__(self, path: str | Path, *, slow_query_log_ms: float = 0.0):
        self.path = Path(path)
        self._slow_query_log_ms = max(0.0, float(slow_query_log_ms))
        self._lock = asyncio.Lock()
        self._write_engine = None
        self._read_engine = None
        self._write_factory: async_sessionmaker[AsyncSession] | None = None
        self._read_factory: async_sessionmaker[AsyncSession] | None = None

    def _maybe_log_slow(self, phase: str, elapsed_ms: float, extra: str = "") -> None:
        if self._slow_query_log_ms <= 0 or elapsed_ms < self._slow_query_log_ms:
            return
        suffix = f" {extra}" if extra else ""
        _sql_log.warning("slow_sql phase=%s duration_ms=%.1f%s", phase, elapsed_ms, suffix)

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_engine = create_write_engine(self.path)
        self._read_engine = create_read_engine(self.path)

        @event.listens_for(self._write_engine.sync_engine, "connect")
        def _on_write_connect(dbapi_conn, _record):
            dbapi_conn.execute(f"PRAGMA busy_timeout=15000")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(self._read_engine.sync_engine, "connect")
        def _on_read_connect(dbapi_conn, _record):
            dbapi_conn.execute(f"PRAGMA busy_timeout=15000")
            dbapi_conn.execute("PRAGMA query_only=ON")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        async with self._write_engine.connect() as conn:
            await configure_sqlite_pragmas(conn, query_only=False)

        self._write_factory = async_sessionmaker(
            self._write_engine,
            expire_on_commit=False,
            autoflush=False,
        )
        self._read_factory = async_sessionmaker(
            self._read_engine,
            expire_on_commit=False,
            autoflush=False,
        )

    async def close(self) -> None:
        if self._write_engine is not None:
            await self._write_engine.dispose()
            self._write_engine = None
        if self._read_engine is not None:
            await self._read_engine.dispose()
            self._read_engine = None
        self._write_factory = None
        self._read_factory = None

    def write_session(self) -> AsyncSession:
        if self._write_factory is None:
            raise RuntimeError("DatabaseRuntime is not open")
        return self._write_factory()

    def read_session(self) -> AsyncSession:
        if self._read_factory is None:
            raise RuntimeError("DatabaseRuntime is not open")
        return self._read_factory()

    @asynccontextmanager
    async def writing(self) -> AsyncIterator[AsyncSession]:
        wait_started = time.perf_counter()
        with RuntimeTrace.span("db.wait"):
            await self._lock.acquire()
        self._maybe_log_slow("db.wait_lock", (time.perf_counter() - wait_started) * 1000)
        session = self.write_session()
        q_started = time.perf_counter()
        try:
            with RuntimeTrace.span("db.query"):
                yield session
            self._maybe_log_slow("db.write", (time.perf_counter() - q_started) * 1000)
        finally:
            try:
                await session.rollback()
            except Exception:
                _sql_log.debug("rollback after write failed", exc_info=True)
            await session.close()
            self._lock.release()

    @asynccontextmanager
    async def hold_write_lock(self) -> AsyncIterator[None]:
        """Hold the write lock without opening a session (serialization tests)."""
        await self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()

    @asynccontextmanager
    async def reading(self) -> AsyncIterator[AsyncSession]:
        session = self.read_session()
        q_started = time.perf_counter()
        try:
            with RuntimeTrace.span("db.query"):
                yield session
        finally:
            self._maybe_log_slow(
                "db.read",
                (time.perf_counter() - q_started) * 1000,
            )
            await session.close()

    async def retry_locked(self, operation: Callable[[], Awaitable[T]]) -> T:
        delay = 0.05
        for attempt in range(LOCK_ATTEMPTS):
            try:
                return await operation()
            except (OperationalError, sqlite3.OperationalError) as exc:
                if not _is_db_locked(exc) or attempt + 1 >= LOCK_ATTEMPTS:
                    raise
                _sql_log.warning(
                    "sqlite locked; retrying attempt=%s/%s error=%s",
                    attempt + 1,
                    LOCK_ATTEMPTS,
                    exc,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.5)
        raise RuntimeError("sqlite lock retry exhausted")

    async def commit_chunk(self, session: AsyncSession, pending: int) -> int:
        if pending < STATEMENTS_PER_COMMIT:
            return pending
        await session.commit()
        return 0
