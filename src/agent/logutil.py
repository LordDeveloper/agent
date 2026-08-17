from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from agent.config import AgentSettings

_LOGGER_NAME = "agent"
_configured = False


def get_logger(name: str | None = None) -> logging.Logger:
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)


def resolve_log_path(settings: AgentSettings) -> Path:
    if settings.log_file:
        return Path(settings.log_file)
    return Path(settings.data_dir) / "agent.log"


def setup_logging(settings: AgentSettings) -> logging.Logger:
    """Configure root agent logger to write rotating agent.log (+ stderr)."""
    global _configured

    logger = get_logger()
    level_name = (settings.log_level or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    if _configured:
        return logger

    log_path = resolve_log_path(settings)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=max(1, int(settings.log_max_bytes or 5_000_000)),
        backupCount=max(1, int(settings.log_backup_count or 5)),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)

    logger.propagate = False
    _configured = True

    logger.info("logging started path=%s level=%s", log_path, level_name)
    return logger


def reset_logging() -> None:
    """Drop handlers so tests can bind a fresh agent.log."""
    global _configured

    logger = get_logger()
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    _configured = False


def flush_logging() -> None:
    for handler in get_logger().handlers:
        handler.flush()
