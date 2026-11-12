from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent.database.config import DatabaseConfig

BUSY_TIMEOUT_MS = 15_000
# Negative cache_size is KiB. 32 MiB stays hot across pooled connections.
CACHE_SIZE_KIB = 32_768
MMAP_SIZE = 128 * 1024 * 1024


def create_write_engine(config: DatabaseConfig) -> AsyncEngine:
    url = config.sqlalchemy_async_url()
    connect_args: dict = {}
    pool: dict = {"pool_pre_ping": True}
    if config.is_sqlite:
        connect_args["timeout"] = 15.0
        # The asyncio write lock allows one writer. A second connection covers
        # pool_pre_ping without opening a fresh database each statement.
        pool["pool_size"] = 2
        pool["max_overflow"] = 0
    elif config.is_mysql:
        connect_args["charset"] = "utf8mb4"
    return create_async_engine(
        url,
        connect_args=connect_args or {},
        **pool,
    )


def create_read_engine(config: DatabaseConfig) -> AsyncEngine:
    if not config.is_sqlite:
        return create_write_engine(config)
    return create_async_engine(
        config.sqlalchemy_async_url(),
        connect_args={"timeout": 15.0},
        pool_pre_ping=True,
        pool_size=4,
        max_overflow=2,
    )


async def configure_sqlite_pragmas(conn, *, query_only: bool = False) -> None:
    await conn.exec_driver_sql(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    await conn.exec_driver_sql(f"PRAGMA cache_size=-{CACHE_SIZE_KIB}")
    await conn.exec_driver_sql("PRAGMA temp_store=MEMORY")
    await conn.exec_driver_sql(f"PRAGMA mmap_size={MMAP_SIZE}")
    if query_only:
        await conn.exec_driver_sql("PRAGMA query_only=ON")
    else:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
