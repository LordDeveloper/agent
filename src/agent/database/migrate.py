from __future__ import annotations

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from agent.logutil import get_logger

_log = get_logger("migrate")

def _agent_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[3]


def _alembic_config(db_path: Path) -> Config:
    root = _agent_root()
    ini = root / "alembic.ini"
    scripts = root / "alembic"
    if not scripts.is_dir():
        raise RuntimeError(f"alembic scripts missing at {scripts}")
    cfg = Config(str(ini))
    # ini uses a relative script_location; PyInstaller cwd is not the bundle root.
    cfg.set_main_option("script_location", str(scripts.resolve()))
    if getattr(sys, "frozen", False):
        cfg.set_main_option("prepend_sys_path", ".")
    else:
        cfg.set_main_option("prepend_sys_path", str((root / "src").resolve()))
    resolved = db_path.resolve().as_posix()
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{resolved}")
    return cfg


def _acquire_migration_lock(db_path: Path):
    lock_path = db_path.with_name(db_path.name + ".migrate.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+b")
    try:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            handle.write(b"0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception as exc:
        handle.close()
        raise RuntimeError(f"could not acquire migration lock: {exc}") from exc
    return handle, lock_path


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


def upgrade_head(db_path: Path) -> None:
    """Run Alembic migrations to head under a cross-process file lock."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    handle, lock_path = _acquire_migration_lock(db_path)
    try:
        cfg = _alembic_config(db_path)
        cfg.cmd_opts = type("opts", (), {"x": [f"dburl=sqlite+aiosqlite:///{db_path.resolve().as_posix()}"]})()
        _log.info("database migration starting path=%s", db_path)
        command.upgrade(cfg, "head")
        _log.info("database migration complete path=%s", db_path)
    finally:
        _release_migration_lock(handle, lock_path)


def stamp_head(db_path: Path) -> None:
    cfg = _alembic_config(db_path)
    command.stamp(cfg, "head")
