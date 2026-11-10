from __future__ import annotations

import asyncio
import errno
import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config

from agent.database.config import DatabaseConfig
from agent.logutil import get_logger

_log = get_logger("migrate")


def _agent_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[3]


def _alembic_config(config: DatabaseConfig) -> Config:
    root = _agent_root()
    ini = root / "alembic.ini"
    scripts = root / "alembic"
    if not scripts.is_dir():
        raise RuntimeError(f"alembic scripts missing at {scripts}")
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(scripts.resolve()))
    if getattr(sys, "frozen", False):
        cfg.set_main_option("prepend_sys_path", ".")
    else:
        cfg.set_main_option("prepend_sys_path", str((root / "src").resolve()))
    cfg.set_main_option("sqlalchemy.url", config.alembic_sync_url())
    return cfg


_LOCK_WAIT_SECONDS = 600
_LOCK_LOG_INTERVAL = 5.0


def _acquire_migration_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+b")
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    last_log = 0.0
    try:
        while True:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0)
                handle.write(b"0")
                handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    return handle, lock_path
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return handle, lock_path
                except OSError as exc:
                    if exc.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
            now = time.monotonic()
            if now - last_log >= _LOCK_LOG_INTERVAL:
                _log.info("waiting for database migration lock path=%s", lock_path)
                last_log = now
            if now >= deadline:
                handle.close()
                raise RuntimeError(
                    f"timed out waiting for migration lock ({_LOCK_WAIT_SECONDS}s): {lock_path}"
                )
            time.sleep(0.25)
    except Exception as exc:
        handle.close()
        raise RuntimeError(f"could not acquire migration lock: {exc}") from exc


def _release_migration_lock(handle, lock_path: Path) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _upgrade_mysql_schema(config: DatabaseConfig) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from agent.database.base import Base
    import agent.database.models  # noqa: F401

    async def run() -> None:
        engine = create_async_engine(config.sqlalchemy_async_url())
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            for core in ("xray", "wireguard", "amnezia", "l2tp", "openvpn", "mullvad"):
                await conn.execute(
                    text("INSERT IGNORE INTO cores (id) VALUES (:id)"),
                    {"id": core},
                )
        await engine.dispose()

    asyncio.run(run())
    _log.info("mysql schema ensured database=%s", config.database)


def upgrade_head(config: DatabaseConfig) -> None:
    """Run migrations under a cross-process file lock."""
    lock_path = config.migration_lock_path()
    if config.is_sqlite and config.sqlite_path is not None:
        config.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    handle, _ = _acquire_migration_lock(lock_path)
    try:
        if config.is_mysql:
            _log.info("database migration starting connection=mysql database=%s", config.database)
            _upgrade_mysql_schema(config)
            _log.info("database migration complete connection=mysql")
            return
        if config.sqlite_path is None:
            raise RuntimeError("sqlite_path missing for sqlite migration")
        cfg = _alembic_config(config)
        _log.info("database migration starting path=%s", config.sqlite_path)
        command.upgrade(cfg, "head")
        _log.info("database migration complete path=%s", config.sqlite_path)
    finally:
        _release_migration_lock(handle, lock_path)


def stamp_head(config: DatabaseConfig) -> None:
    if not config.is_sqlite:
        return
    cfg = _alembic_config(config)
    command.stamp(cfg, "head")
