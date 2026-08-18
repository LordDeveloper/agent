"""Bring enabled VPN cores online when the agent process starts."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry


def bootstrap_enabled_cores(
    settings: AgentSettings,
    registry: CoreRegistry,
    log: logging.Logger | None = None,
) -> None:
    """Start xray and bring up wireguard/amnezia interfaces for enabled cores."""
    logger = log or logging.getLogger("app")
    enabled = set(settings.cores())

    for key in ("xray", "wireguard", "amnezia"):
        if key not in enabled:
            continue
        driver = registry._drivers.get(key)
        if driver is None:
            continue
        try:
            if not driver.installed():
                logger.info("supervisor skip core=%s: not installed", key)
                continue
            if key == "xray":
                if driver.running():
                    logger.info("supervisor core=%s already running", key)
                    continue
                logger.info("supervisor starting core=%s", key)
                driver.enable()
            else:
                logger.info("supervisor enabling interfaces core=%s", key)
                driver.enable()
        except Exception as exc:
            logger.warning("supervisor core=%s bootstrap failed: %s", key, exc)
