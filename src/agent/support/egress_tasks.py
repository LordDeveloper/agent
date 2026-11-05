"""Background policy routing for WireGuard and AmneziaWG.

Peer creation stays on the request. This worker applies ip rules and exit
routes afterward. It re-reads the store when it runs, so a delayed job cannot
rebuild routes for a peer that was deleted or disabled, and an older plan
cannot overwrite a newer one.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from agent.logutil import get_logger

log = get_logger("egress")

_scheduler: EgressScheduler | None = None


class EgressScheduler:
    def __init__(self, registry: Any, data_dir: str | Path, *, retry_delay: float | None = None) -> None:
        self.registry = registry
        self.data_dir = Path(data_dir)
        self.retry_delay = retry_delay
        self.generation = 0
        self._wake = asyncio.Event()
        self._tasks: dict[str, dict[str, Any]] = {}
        self._plans: dict[str, dict[str, Any]] = {}
        self._drops: dict[str, set[str]] = {}
        self._core_locks: dict[str, asyncio.Lock] = {}
        self._load()

    def _path(self) -> Path:
        return self.data_dir / "egress" / "tasks.json"

    def _load(self) -> None:
        path = self._path()
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        rows = payload.get("tasks")
        if isinstance(rows, dict):
            self._tasks = {str(key): value for key, value in rows.items() if isinstance(value, dict)}
        self.generation = int(payload.get("generation") or 0)

    def _save(self) -> None:
        path = self._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"generation": self.generation, "tasks": self._tasks}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(path)

    def _lock(self, core: str) -> asyncio.Lock:
        lock = self._core_locks.get(core)
        if lock is None:
            lock = asyncio.Lock()
            self._core_locks[core] = lock
        return lock

    def enqueue(
        self,
        core: str,
        *client_ids: Any,
        only_ids: set[str] | None = None,
        drop_keys: list[str] | None = None,
    ) -> dict[str, Any]:
        self.generation += 1
        now = time.time()
        core_name = str(core or "").strip() or "wireguard"
        self._plans[core_name] = {"only_ids": None if only_ids is None else {str(item) for item in only_ids}}
        if drop_keys:
            self._drops.setdefault(core_name, set()).update(str(item) for item in drop_keys if item)
        ids = [str(item) for item in client_ids if item] or ["*"]
        record: dict[str, Any] | None = None
        for cid in ids:
            current = self._tasks.get(cid)
            if current and current.get("status") == "queued":
                current["generation"] = self.generation
                current["updated_at"] = now
                current["core"] = core_name
                record = current
                continue
            record = {
                "task_type": "routing",
                "client_id": cid,
                "core": core_name,
                "status": "queued",
                "retries": 0,
                "duration_ms": None,
                "last_error": None,
                "generation": self.generation,
                "created_at": (current or {}).get("created_at") or now,
                "updated_at": now,
            }
            self._tasks[cid] = record
        self._save()
        self._wake.set()
        log.info("routing task queued core=%s clients=%s generation=%s", core_name, ",".join(ids), self.generation)
        return {"status": "queued", "generation": self.generation, "task": record}

    def status_for(self, client_ids: list[str] | None = None) -> str:
        ids = [item for item in (client_ids or []) if item]
        rows: list[Any] = [self._tasks.get(cid) for cid in ids] if ids else []
        bulk = self._tasks.get("*")
        if isinstance(bulk, dict) and (not ids or bulk.get("status") in {"queued", "running", "failed"} or not any(rows)):
            rows.append(bulk)
        statuses = [str(row.get("status")) for row in rows if isinstance(row, dict)]
        if "running" in statuses:
            return "running"
        if "queued" in statuses or "pending" in statuses:
            return "pending"
        if "failed" in statuses:
            return "failed"
        if "completed" in statuses:
            return "completed"
        return "not_required"

    def requeue_unfinished(self) -> int:
        restored = 0
        now = time.time()
        for row in self._tasks.values():
            if row.get("status") in {"queued", "running"}:
                row["status"] = "queued"
                row["updated_at"] = now
                restored += 1
        if restored:
            self._save()
            self._wake.set()
        return restored

    async def _apply(self, core: str, only_ids: set[str] | None, drop_keys: list[str]) -> None:
        driver = self.registry.get(core)
        apply = getattr(driver, "_apply_peer_egress", None)
        if apply is None:
            return
        rows = None
        if only_ids is not None:
            listed = await driver.list_interfaces()
            rows = [row for row in listed if str((row or {}).get("id")) in only_ids]
        async with self._lock(core):
            await apply(rows, drop_keys=drop_keys or None)

    async def _run(self) -> None:
        started = self.generation
        plans = {core: dict(plan) for core, plan in self._plans.items()}
        drops = {core: set(keys) for core, keys in self._drops.items()}
        if self.generation != started:
            return
        for core, plan in plans.items():
            if self.generation != started:
                return
            only_ids = plan.get("only_ids")
            await self._apply(core, only_ids if isinstance(only_ids, set) else None, list(drops.get(core) or []))
        if self.generation != started:
            return
        for core, keys in drops.items():
            pending = self._drops.get(core)
            if pending is not None:
                pending.difference_update(keys)

    async def serve(self, stop: asyncio.Event) -> None:
        restored = self.requeue_unfinished()
        if restored:
            log.info("routing recovered unfinished tasks=%s", restored)
        enabled = []
        try:
            enabled = [key for key, _driver in self.registry.enabled_drivers() if key in {"wireguard", "amnezia"}]
        except Exception:
            enabled = []
        for core in enabled:
            self.enqueue(core)
        while not stop.is_set():
            if not self._wake.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=60)
                except asyncio.TimeoutError:
                    for core in enabled:
                        self.enqueue(core)
                    continue
                if stop.is_set():
                    break
            await self._drain(stop)

    async def _drain(self, stop: asyncio.Event) -> None:
        while self._wake.is_set() and not stop.is_set():
            self._wake.clear()
            generation = self.generation
            started = time.perf_counter()
            self._mark(generation, "running")
            try:
                await asyncio.wait_for(self._run(), timeout=90)
            except Exception as exc:
                duration = int((time.perf_counter() - started) * 1000)
                self._mark(generation, "failed", duration, str(exc))
                log.exception("routing task failed duration_ms=%s", duration)
                if self.generation == generation and not stop.is_set():
                    await self._retry(generation, stop)
                continue
            duration = int((time.perf_counter() - started) * 1000)
            if self.generation != generation or self._wake.is_set():
                log.info("routing task superseded duration_ms=%s generation=%s", duration, generation)
                self._wake.set()
                continue
            self._mark(generation, "completed", duration, None)
            log.info("routing task completed duration_ms=%s generation=%s", duration, generation)

    async def _retry(self, generation: int, stop: asyncio.Event) -> None:
        retries = 0
        for item in self._tasks.values():
            if item.get("generation") == generation:
                retries = max(retries, int(item.get("retries") or 0))
        if retries >= 3:
            return
        delay = self.retry_delay if self.retry_delay is not None else float(2 ** retries)
        now = time.time()
        for item in self._tasks.values():
            if item.get("generation") == generation and item.get("status") == "failed":
                item["retries"] = retries + 1
                item["status"] = "queued"
                item["updated_at"] = now
        self._save()
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
            return
        except asyncio.TimeoutError:
            pass
        if self.generation == generation:
            self._wake.set()

    def _mark(self, generation: int, status: str, duration: int | None = None, error: str | None = None) -> None:
        now = time.time()
        for item in self._tasks.values():
            current = str(item.get("status") or "")
            if status == "running" and current != "queued":
                continue
            if status in {"completed", "failed"} and current != "running":
                continue
            if int(item.get("generation") or 0) > generation:
                continue
            item["status"] = status
            item["updated_at"] = now
            if duration is not None:
                item["duration_ms"] = duration
            if status in {"completed", "failed"}:
                item["last_error"] = error
        self._save()


def get_scheduler() -> EgressScheduler | None:
    return _scheduler


def configure_egress(registry: Any, data_dir: str | Path) -> EgressScheduler:
    global _scheduler
    _scheduler = EgressScheduler(registry, data_dir)
    return _scheduler


def reset_egress_for_tests() -> None:
    global _scheduler
    _scheduler = None


def schedule_egress(
    core: str,
    *client_ids: Any,
    only_ids: set[str] | None = None,
    drop_keys: list[str] | None = None,
) -> dict[str, Any] | None:
    scheduler = _scheduler
    if scheduler is None:
        return None
    return scheduler.enqueue(core, *client_ids, only_ids=only_ids, drop_keys=drop_keys)


def routing_status(client_ids: list[Any] | None = None) -> str:
    scheduler = _scheduler
    if scheduler is None:
        return "not_required"
    return scheduler.status_for([str(item) for item in (client_ids or []) if item])


def describe_routing(client_id: Any, *, verified: bool | None) -> dict[str, Any]:
    """Task state and kernel verification stay separate. Pending is not active."""
    task = routing_status([client_id] if client_id else [])
    if task == "running":
        status = "installing"
    elif task in {"queued", "pending"}:
        status = "pending"
    elif task == "failed" and verified is not True:
        status = "error"
    elif verified is True and task not in {"queued", "running", "pending"}:
        status = "active"
    elif verified is False:
        status = "error"
    else:
        status = "not_required" if task == "not_required" else task
    return {"status": status, "verified": verified, "task_status": task}


def tunnel_provisioning(payload: dict[str, Any], *client_ids: Any, peer_field: str = "wireguard_peer") -> dict[str, Any]:
    """Essential peer provisioning is already finished. Routing and bandwidth are not."""
    from agent.support.bandwidth import get_manager

    bandwidth = "not_required"
    manager = get_manager()
    if manager is not None:
        bandwidth = manager.bandwidth_status([str(item) for item in client_ids if item])
    return {
        **payload,
        "provisioning": {peer_field: "completed"},
        "routing": {"status": routing_status(list(client_ids))},
        "bandwidth": {"status": bandwidth},
    }


async def egress_reconcile_loop(registry: Any, settings: Any, stop: asyncio.Event) -> None:
    if get_scheduler() is None:
        configure_egress(registry, settings.data_dir)
    scheduler = get_scheduler()
    if scheduler is None:
        return
    await scheduler.serve(stop)
