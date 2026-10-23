"""Bring enabled VPN cores online when the agent process starts."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agent.asyncutil import maybe_await, run_sync

if TYPE_CHECKING:
    from agent.config import AgentSettings
    from agent.registry import CoreRegistry


async def bootstrap_enabled_cores(
    settings: AgentSettings,
    registry: CoreRegistry,
    log: logging.Logger | None = None,
) -> None:
    """Start xray and bring up wireguard/amnezia interfaces for enabled cores."""
    logger = log or logging.getLogger("app")
    _refresh_boot_egress(settings, registry, logger)
    enabled = set(settings.cores())

    for key in ("xray", "wireguard", "amnezia", "l2tp", "openvpn"):
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
                if await maybe_await(driver.running()):
                    logger.info("supervisor core=%s already running", key)
                    try:
                        await maybe_await(driver.sync_proxy_protocol_forwarders())
                    except Exception as exc:
                        logger.warning("supervisor pp-forward sync failed core=%s: %s", key, exc)
                    continue
                logger.info("supervisor starting core=%s", key)
                await maybe_await(driver.enable())
                try:
                    await maybe_await(driver.sync_proxy_protocol_forwarders())
                except Exception as exc:
                    logger.warning("supervisor pp-forward sync failed core=%s: %s", key, exc)
            elif key == "l2tp":
                if await maybe_await(driver.running()):
                    logger.info("supervisor core=%s already running; reconcile companions", key)
                    try:
                        await maybe_await(driver.reconcile_runtime())
                    except Exception as exc:
                        logger.warning("supervisor l2tp companion reconcile failed: %s", exc)
                    continue
                logger.info("supervisor starting core=%s", key)
                await maybe_await(driver.enable())
            elif key == "openvpn":
                if await maybe_await(driver.running()):
                    logger.info("supervisor core=%s already running", key)
                    continue
                logger.info("supervisor starting core=%s", key)
                await maybe_await(driver.enable())
            else:
                logger.info("supervisor enabling interfaces core=%s", key)
                await maybe_await(driver.enable())
        except Exception as exc:
            logger.warning("supervisor core=%s bootstrap failed: %s", key, exc)


def _refresh_boot_egress(settings, registry, logger: logging.Logger) -> None:
    """Rewrite egress before wg-quick so PostUp cannot sleep on a stale script.

    Also retarget an installed agent unit whose ExecStartPost runs that script
    inline. The running start is unaffected; the next start will not wait.
    """
    try:
        from agent.ops import relax_agent_start_post

        if relax_agent_start_post():
            logger.info("supervisor retargeted agent ExecStartPost off peer-egress-apply.sh")
    except Exception as exc:
        logger.warning("supervisor agent unit refresh failed: %s", exc)

    store = getattr(registry, "store", None)
    data_dir = getattr(settings, "data_dir", None)
    if store is None or not data_dir:
        return
    try:
        from agent.support.peer_egress import persist_peer_egress

        persist_peer_egress(store, data_dir=data_dir, force_start=False, start_unit=False)
    except Exception as exc:
        logger.warning("supervisor egress script refresh failed: %s", exc)


def bootstrap_enabled_cores_sync(
    settings: AgentSettings,
    registry: CoreRegistry,
    log: logging.Logger | None = None,
) -> None:
    run_sync(bootstrap_enabled_cores(settings, registry, log))
