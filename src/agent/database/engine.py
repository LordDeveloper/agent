from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent.database.config import DatabaseConfig

BUSY_TIMEOUT_MS = 15_000


def create_write_engine(config: DatabaseConfig) -> AsyncEngine:
    url = config.sqlalchemy_async_url()
    connect_args: dict = {}
    if config.is_sqlite:
        connect_args["timeout"] = 15.0
    elif config.is_mysql:
        connect_args["charset"] = "utf8mb4"
    return create_async_engine(
        url,
        connect_args=connect_args or {},
        pool_pre_ping=True,
    )


def create_read_engine(config: DatabaseConfig) -> AsyncEngine:
    return create_write_engine(config)


async def configure_sqlite_pragmas(conn, *, query_only: bool = False) -> None:
    await conn.exec_driver_sql(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    if query_only:
        await conn.exec_driver_sql("PRAGMA query_only=ON")
    else:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
