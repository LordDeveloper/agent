"""Background work for one node.

Traffic sampling, quota, egress, bandwidth, and Mullvad fallback run here,
not in the HTTP process. A slow core walk can no longer stop the listener
from writing a response.
"""

from __future__ import annotations

import asyncio
import signal
from pathlib import Path

from agent import __version__
from agent.config import AgentSettings, load_settings
from agent.logutil import get_logger, resolve_log_path, setup_logging
from agent.support.quota import configure_quota_settings

log = get_logger("worker")


async def watch_task_files(settings: AgentSettings, stop: asyncio.Event) -> None:
    """Wake the worker when the API process queues routing or bandwidth work."""
    from agent.support.bandwidth import get_manager
    from agent.support.egress_tasks import get_scheduler

    egress_path = Path(settings.data_dir) / "egress" / "tasks.json"
    bandwidth_path = Path(settings.data_dir) / "bandwidth" / "tasks.json"
    seen = {
        egress_path: _mtime(egress_path),
        bandwidth_path: _mtime(bandwidth_path),
    }
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=1.0)
            return
        except asyncio.TimeoutError:
            pass
        egress_mtime = _mtime(egress_path)
        if seen.get(egress_path) != egress_mtime:
            seen[egress_path] = egress_mtime
            scheduler = get_scheduler()
            if scheduler is not None:
                for core in ("wireguard", "amnezia"):
                    scheduler.enqueue(core)
        bandwidth_mtime = _mtime(bandwidth_path)
        if seen.get(bandwidth_path) != bandwidth_mtime:
            seen[bandwidth_path] = bandwidth_mtime
            manager = get_manager()
            if manager is not None:
                manager.reconcile()


def _mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns if path.is_file() else 0
    except OSError:
        return 0


async def serve_background(settings: AgentSettings, stop: asyncio.Event) -> None:
    from agent.audit import AuditLog
    from agent.core_supervisor import bootstrap_enabled_cores
    from agent.db import Store
    from agent.mullvad_worker import mullvad_worker_loop
    from agent.quota_enforcer import quota_enforcer_loop
    from agent.registry import CoreRegistry
    from agent.support.bandwidth import bandwidth_reconcile_loop, configure_runtime
    from agent.support.egress_tasks import configure_egress, egress_reconcile_loop
    from agent.support.proxy_protocol_forwarder import stop_forwarders
    from agent.support.quota_identity_migration import migrate_client_quota_identity
    from agent.traffic.service import TrafficService
    from agent.traffic_worker import traffic_worker_loop

    configure_quota_settings(settings)
    if not settings.enforce_local_volume_quota:
        log.info(
            "volume quota cutoff is owned by the panel (UpdateSubscribeStats); "
            "agent will not disable clients for quota",
        )
    setup_logging(settings)
    from agent.database.config import database_config_from_settings

    store = Store(
        database_config_from_settings(settings),
        slow_query_log_ms=float(settings.slow_query_log_ms or 0.0),
    )
    await store.open(migrate=True)
    from agent.systemd_notify import systemd_notify

    systemd_notify("READY=1")
    try:
        migrated = await migrate_client_quota_identity(store)
        if migrated:
            log.info("client quota identity migrated docs=%s", migrated)
        from agent.support.node_id_pk_migration import migrate_node_id_primary_key

        moved = await migrate_node_id_primary_key(store)
        if moved:
            log.info("client node_id primary key migrated docs=%s", moved)
        audit = AuditLog(store)
        registry = CoreRegistry(settings, audit, store)
        traffic = TrafficService(store)
        configure_runtime(registry, settings.data_dir)
        configure_egress(registry, settings.data_dir)
        log.info(
            "worker started version=%s cores=%s log=%s",
            __version__,
            ",".join(settings.cores()) or "-",
            resolve_log_path(settings),
        )
        try:
            await bootstrap_enabled_cores(settings, registry, log)
        except Exception:
            log.exception("bootstrap failed")
        try:
            from agent.support.xray_exit_bind import reapply_saved_binds

            rebound = await reapply_saved_binds()
            if rebound.get("applied") or rebound.get("failed"):
                log.info(
                    "xray exit binds applied=%s failed=%s",
                    rebound.get("applied"),
                    rebound.get("failed"),
                )
        except Exception:
            log.exception("xray exit bind reapply failed")

        tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(bandwidth_reconcile_loop(registry, settings, stop)),
            asyncio.create_task(egress_reconcile_loop(registry, settings, stop)),
            asyncio.create_task(watch_task_files(settings, stop)),
        ]
        if float(settings.quota_enforce_interval) > 0:
            tasks.append(asyncio.create_task(quota_enforcer_loop(registry, settings, stop)))
        if float(settings.traffic_sample_interval) > 0:
            tasks.append(asyncio.create_task(traffic_worker_loop(registry, traffic, settings, stop)))
        if float(getattr(settings, "mullvad_fallback_interval", 60.0) or 0) > 0:
            tasks.append(asyncio.create_task(mullvad_worker_loop(store, settings, stop)))

        await stop.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        stop_forwarders(settings)
        log.info("worker stopping")
        await store.close()


def run_worker(env_file: str | None = None) -> int:
    settings = load_settings(env_file)
    stop = asyncio.Event()

    async def main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        await serve_background(settings, stop)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        return 130
    return 0
