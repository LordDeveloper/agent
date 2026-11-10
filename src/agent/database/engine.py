from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

BUSY_TIMEOUT_MS = 15_000


def _sqlite_url(path: Path) -> str:
    """Absolute SQLite file URL for the aiosqlite driver."""
    resolved = path.resolve().as_posix()
    return f"sqlite+aiosqlite:///{resolved}"


def _engine(path: Path) -> AsyncEngine:
    return create_async_engine(
        _sqlite_url(path),
        connect_args={"timeout": 15.0},
        pool_pre_ping=True,
    )


def create_write_engine(path: Path) -> AsyncEngine:
    return _engine(path)


def create_read_engine(path: Path) -> AsyncEngine:
    # Read isolation uses PRAGMA query_only on connect (see session.DatabaseRuntime.open).
    return _engine(path)


async def configure_sqlite_pragmas(conn, *, query_only: bool = False) -> None:
    await conn.exec_driver_sql(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    if query_only:
        await conn.exec_driver_sql("PRAGMA query_only=ON")
    else:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
