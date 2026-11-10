from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

BUSY_TIMEOUT_MS = 15_000


def _sqlite_url(path: Path, *, read_only: bool = False) -> str:
    resolved = path.resolve().as_posix()
    mode = "&mode=ro" if read_only else ""
    return f"sqlite+aiosqlite:///{resolved}?timeout=15.0{mode}"


def create_write_engine(path: Path) -> AsyncEngine:
    return create_async_engine(
        _sqlite_url(path),
        connect_args={"timeout": 15.0},
        pool_pre_ping=True,
    )


def create_read_engine(path: Path) -> AsyncEngine:
    return create_async_engine(
        _sqlite_url(path, read_only=True),
        connect_args={"timeout": 15.0},
        pool_pre_ping=True,
    )


async def configure_sqlite_pragmas(conn, *, query_only: bool = False) -> None:
    await conn.exec_driver_sql(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    if query_only:
        await conn.exec_driver_sql("PRAGMA query_only=ON")
    else:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
