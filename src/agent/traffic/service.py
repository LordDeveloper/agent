from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from agent.db import Store
from agent.logutil import get_logger
from agent.traffic.keys import client_key

if TYPE_CHECKING:
    from agent.registry import CoreRegistry

log = get_logger("traffic")

AGENT_META_CORE = "__agent__"
LAST_SAMPLE_META_KEY = "traffic_last_sample_at"
LAST_SAMPLE_TIMING_META_KEY = "traffic_last_sample_timing"
# From a stored (0,0) cursor, deltas above this are lifetime skew (reset/stale), not one interval.
_ZERO_CURSOR_SKEW_BYTES = 512 * 1024 * 1024
FETCH_SNAPSHOT_META_KEY = "traffic_fetch_snapshot"
FETCH_LOCK_META_KEY = "traffic_fetch_lock"
# Legacy panel read-lock meta (removed). Ack still deletes stale keys after upgrade.
# A volume sample may hold the worker exclusively for this long. After that
# the next sample tick cancels it and starts a new cycle.
DEFAULT_SAMPLE_LOCK_SECONDS = 120.0


class PendingReadLocked(Exception):
    """Another process already read pending and has not acked those node ids."""


class TrafficService:
    """Samples cumulative client counters and tracks unreported deltas for the panel.

    Pending is a queue: worker keeps adding live growth until the panel GET+ack
    cycle. Online / handshake state must not stop the queue. GET is a snapshot;
    POST ack advances the watermark to that snapshot so bytes after GET stay
    in the next pending cycle.
    """

    def __init__(self, store: Store):
        self.store = store
        self._aliases: dict[str, str] = {}
        self._emails: dict[str, str] = {}
        self._fetch_snapshot: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self._sample_lock = asyncio.Lock()
        self._sample_flight: asyncio.Task | None = None
        self._sample_started_at = 0.0
        # One in-flight sample per core. A slow core must not hold the others.
        self._core_flights: dict[str, tuple[asyncio.Task, float]] = {}

    def cancel_inflight_sample(self) -> None:
        """Stop every volume sample that is still running."""
        flight = self._sample_flight
        if flight is not None and not flight.done():
            flight.cancel()
        for core_flight, _started in list(self._core_flights.values()):
            if not core_flight.done():
                core_flight.cancel()

    def _listed_cores(self, registry: CoreRegistry) -> list[str] | None:
        settings = getattr(registry, "settings", None)
        cores = getattr(settings, "cores", None)
        if not callable(cores):
            return None
        try:
            names = [str(key) for key in cores() if str(key or "").strip()]
        except Exception:
            return None
        return names

    async def sample_unless_overlapping(
        self,
        registry: CoreRegistry,
        *,
        lock_seconds: float = DEFAULT_SAMPLE_LOCK_SECONDS,
    ) -> dict[str, int] | None:
        """Start volume sampling and return without waiting for it.

        Each core runs on its own task. A core that is still inside
        ``lock_seconds`` is left alone; the other cores still sample. Once a
        core's lock window has passed, that task is cancelled and a new one
        starts. Returns None when every core was already inside its window.
        """
        cores = self._listed_cores(registry)
        if not cores:
            return await self._start_combined_sample(registry, lock_seconds=lock_seconds)

        doomed: list[asyncio.Task] = []
        async with self._sample_lock:
            now = time.monotonic()
            for core_key in cores:
                flight, started_at = self._core_flights.get(core_key, (None, 0.0))
                if flight is None or flight.done():
                    continue
                age = now - started_at
                if age < lock_seconds:
                    log.debug(
                        "traffic sample skipped core=%s; in flight for %.1fs (lock %ss)",
                        core_key,
                        age,
                        lock_seconds,
                    )
                    continue
                log.warning(
                    "traffic sample lock expired core=%s after %.1fs; cancelling",
                    core_key,
                    age,
                )
                flight.cancel()
                self._core_flights.pop(core_key, None)
                doomed.append(flight)

        if doomed:
            # Wait until the stuck core has actually stopped, then start the
            # next one. Awaiting while holding the lock would deadlock: the
            # cancelled task needs that same lock to clear itself.
            await asyncio.gather(*doomed, return_exceptions=True)

        started: list[str] = []
        async with self._sample_lock:
            now = time.monotonic()
            for core_key in cores:
                flight, _started_at = self._core_flights.get(core_key, (None, 0.0))
                if flight is not None and not flight.done():
                    continue
                self._core_flights[core_key] = (
                    asyncio.create_task(self._run_core_sample(registry, core_key)),
                    now,
                )
                started.append(core_key)
        if not started:
            return None
        log.debug("traffic sample scheduled cores=%s", ",".join(started))
        return {"started": len(started)}

    async def _start_combined_sample(
        self,
        registry: CoreRegistry,
        *,
        lock_seconds: float,
    ) -> dict[str, int] | None:
        """One flight for callers that do not name their cores (tests)."""
        doomed: asyncio.Task | None = None
        async with self._sample_lock:
            flight = self._sample_flight
            if flight is not None and not flight.done():
                age = time.monotonic() - self._sample_started_at
                if age < lock_seconds:
                    log.debug(
                        "traffic sample skipped; in flight for %.1fs (lock %ss)",
                        age,
                        lock_seconds,
                    )
                    return None
                log.warning(
                    "traffic sample lock expired after %.1fs; cancelling",
                    age,
                )
                flight.cancel()
                self._sample_flight = None
                doomed = flight

        if doomed is not None:
            await asyncio.gather(doomed, return_exceptions=True)

        async with self._sample_lock:
            flight = self._sample_flight
            if flight is not None and not flight.done():
                return None
            self._sample_started_at = time.monotonic()
            self._sample_flight = asyncio.create_task(self._run_sample(registry))
        return {"started": 1}

    async def _run_sample(self, registry: CoreRegistry) -> dict[str, int] | None:
        try:
            stats = await self.sample_all(registry)
            if stats.get("pending", 0) or stats.get("regressed", 0):
                log.info(
                    "traffic sample clients=%s pending=%s initialized=%s regressed=%s",
                    stats.get("clients_seen", 0),
                    stats.get("pending", 0),
                    stats.get("initialized", 0),
                    stats.get("regressed", 0),
                )
            return stats
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("traffic sample cycle failed")
            return None
        finally:
            async with self._sample_lock:
                current = asyncio.current_task()
                if self._sample_flight is current:
                    self._sample_flight = None

    async def _run_core_sample(self, registry: CoreRegistry, core_key: str) -> dict[str, int] | None:
        try:
            stats = await self._sample_core(registry, core_key)
            if stats.get("pending", 0) or stats.get("regressed", 0):
                log.info(
                    "traffic sample core=%s clients=%s pending=%s initialized=%s regressed=%s",
                    core_key,
                    stats.get("clients_seen", 0),
                    stats.get("pending", 0),
                    stats.get("initialized", 0),
                    stats.get("regressed", 0),
                )
            return stats
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("traffic sample failed core=%s", core_key)
            return None
        finally:
            async with self._sample_lock:
                current = asyncio.current_task()
                flight, _started = self._core_flights.get(core_key, (None, 0.0))
                if flight is current:
                    self._core_flights.pop(core_key, None)

    def _schedule_sample_all(self, registry: CoreRegistry) -> None:
        """Start a background sample if none is inside the overlap window."""
        loop = asyncio.get_running_loop()
        loop.create_task(self.sample_unless_overlapping(registry))

    def _schedule_persist_fetch_snapshot(self, snapshot: dict[str, list[dict[str, Any]]]) -> None:
        """Persist ack snapshot off the hot GET path (large nodes hold the write lock)."""
        loop = asyncio.get_running_loop()

        async def _persist() -> None:
            try:
                await self._persist_fetch_snapshot(snapshot)
            except Exception:
                log.exception("traffic pending snapshot persist failed")

        loop.create_task(_persist())

    async def sample_cores_blocking(self, registry: CoreRegistry) -> dict[str, int]:
        """Run one volume sample cycle and await every enabled core (worker cadence)."""
        stats, core_timings, cycle_ms = await self._sample_cores_merged(registry)
        import json

        timing_payload = {**core_timings, "sqlite_ms": core_timings.get("_sqlite_ms", 0), "cycle_ms": cycle_ms}
        timing_payload.pop("_sqlite_ms", None)
        await self.store.set_meta(AGENT_META_CORE, LAST_SAMPLE_TIMING_META_KEY, json.dumps(timing_payload))
        log.info("traffic sample cycle cycle_ms=%s cores=%s", cycle_ms, json.dumps(core_timings, sort_keys=True))
        return stats

    async def sample_all(self, registry: CoreRegistry) -> dict[str, int]:
        """Refresh pending deltas from every core at once (online not required)."""
        stats, _, _ = await self._sample_cores_merged(registry)
        return stats

    async def _sample_cores_merged(
        self,
        registry: CoreRegistry,
    ) -> tuple[dict[str, int], dict[str, dict[str, int]], int]:
        """Parallel core snapshots on the worker registry, then one SQLite commit."""
        from agent.asyncutil import gather_independent

        cycle_started = time.monotonic()
        all_cores = self._listed_cores(registry) or []
        settings = registry.settings
        if hasattr(settings, "traffic_billing_cores") and callable(settings.traffic_billing_cores):
            billing = set(settings.traffic_billing_cores())
        else:
            billing = set(all_cores)
        cores = [key for key in all_cores if key in billing]
        if "l2tp" in all_cores and "l2tp" not in cores:
            await self._drop_linked_l2tp_billing(registry.get("l2tp"))

        owners_task = asyncio.create_task(self.store.client_scopes())
        snapshot_started = time.monotonic()
        captured = await gather_independent(
            *(self._read_core_usage_snapshot(registry, core_key) for core_key in cores),
            return_exceptions=True,
        )
        parallel_snapshot_ms = int((time.monotonic() - snapshot_started) * 1000)
        owners = await owners_task
        capture_order = list(cores)
        core_snapshots: list[tuple[str, Any, int]] = []
        core_timings: dict[str, dict[str, int]] = {}
        for core_key, item in zip(capture_order, captured):
            if isinstance(item, Exception):
                log.exception("traffic snapshot failed core=%s: %s", core_key, item)
                continue
            key, snapshot, snapshot_ms = item
            core_snapshots.append((key, snapshot, snapshot_ms))
            core_timings[str(key)] = {
                "snapshot_ms": int(snapshot_ms),
                "sqlite_ms": 0,
                "total_ms": int(snapshot_ms),
            }
            log.info(
                "traffic sample timing core=%s snapshot_ms=%s (sqlite merged)",
                key,
                snapshot_ms,
            )

        core_timings["parallel_snapshot_ms"] = parallel_snapshot_ms
        sqlite_started = time.monotonic()
        stats, sqlite_detail = await self._commit_merged_core_samples(
            core_snapshots,
            owners,
            registry,
        )
        sqlite_ms = int((time.monotonic() - sqlite_started) * 1000)
        core_timings["_sqlite_ms"] = sqlite_ms
        if sqlite_detail:
            core_timings.update(sqlite_detail)
        cycle_ms = int((time.monotonic() - cycle_started) * 1000)
        if sqlite_detail:
            log.info(
                "traffic sample timing sqlite_ms=%s cursor_load_ms=%s plan_ms=%s write_ms=%s "
                "chunk_count=%s cycle_ms=%s clients=%s pending=%s",
                sqlite_ms,
                sqlite_detail.get("cursor_load_ms", 0),
                sqlite_detail.get("plan_ms", 0),
                sqlite_detail.get("write_ms", 0),
                sqlite_detail.get("chunk_count", 0),
                cycle_ms,
                stats.get("clients_seen", 0),
                stats.get("pending", 0),
            )
        else:
            log.info(
                "traffic sample timing sqlite_ms=%s cycle_ms=%s clients=%s pending=%s",
                sqlite_ms,
                cycle_ms,
                stats.get("clients_seen", 0),
                stats.get("pending", 0),
            )
        return stats, core_timings, cycle_ms

    async def _read_core_usage_snapshot(
        self,
        registry: CoreRegistry,
        core_key: str,
    ) -> tuple[str, Any, int]:
        from agent.asyncutil import maybe_await

        started = time.monotonic()
        driver = registry.get(core_key)
        if core_key == "l2tp":
            await self._drop_linked_l2tp_billing(driver)
        reset_xray = core_key == "xray" and bool(
            getattr(registry.settings, "traffic_xray_reset_stats", False)
        )
        cache_hit: bool | None = None
        if core_key == "xray" and not reset_xray:
            max_age = getattr(driver, "_usage_cache_max_age", lambda: 5.0)()
            cache_hit = getattr(driver, "cached_usage_snapshot", lambda _a: None)(max_age) is not None
        snapshot = await maybe_await(driver.usage_snapshot(reset_stats=reset_xray))
        if core_key == "xray" and cache_hit is not None:
            log.info("traffic sample xray cache=%s", "hit" if cache_hit else "miss")
        if core_key == "xray" and reset_xray:
            log.info("traffic sample xray reset_stats=on")
        snapshot_ms = int((time.monotonic() - started) * 1000)
        return core_key, snapshot, snapshot_ms

    async def _commit_merged_core_samples(
        self,
        core_snapshots: list[tuple[str, Any, int]],
        owners: dict[tuple[str, str], str],
        registry: CoreRegistry,
    ) -> tuple[dict[str, int], dict[str, int]]:
        from agent.auth_scope import DEFAULT_SCOPE, current_scope

        sampled_at = datetime.now(timezone.utc).isoformat()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for core_key, snapshot, _snapshot_ms in core_snapshots:
            for sample in self._usage_rows(core_key, snapshot):
                scope = owners.get((str(sample["core"]), str(sample["label"])), DEFAULT_SCOPE)
                grouped.setdefault(scope, []).append(sample)

        if not grouped:
            grouped[DEFAULT_SCOPE] = []

        cursor_keys: set[tuple[str, str]] = set()
        for group in grouped.values():
            for sample in group:
                core = str(sample["core"])
                label = str(sample["label"])
                cursor_keys.add((core, label))
                for alias in (sample.get("email"), sample.get("client_id"), sample.get("protocol_id")):
                    alias_text = str(alias or "").strip()
                    if alias_text:
                        cursor_keys.add((core, alias_text))

        xray_reset = bool(getattr(registry.settings, "traffic_xray_reset_stats", False))

        def plan(cursors: dict[tuple[str, str], tuple[int, int]]) -> dict[str, Any]:
            merged_stats = {
                "clients_seen": 0,
                "pending": 0,
                "initialized": 0,
                "regressed": 0,
                "unchanged": 0,
            }
            chunk_inserts: list[dict[str, Any]] = []
            client_cursor_upserts: list[tuple[str, str, int, int]] = []
            identity_upserts: list[tuple[str, str, str]] = []
            for _scope, group in grouped.items():
                if not group:
                    continue
                part = self._plan_sample(group, cursors, sampled_at, xray_reset_stats=xray_reset)
                for key in merged_stats:
                    if key == "pending":
                        merged_stats[key] += int(part.get("stats", {}).get(key, 0))
                    else:
                        merged_stats[key] += int(part.get("stats", {}).get(key, 0))
                chunk_inserts.extend(part.get("chunk_inserts") or [])
                client_cursor_upserts.extend(part.get("client_cursor_upserts") or [])
                identity_upserts.extend(part.get("identity_upserts") or [])
            return {
                "stats": merged_stats,
                "chunk_inserts": chunk_inserts,
                "client_cursor_upserts": client_cursor_upserts,
                "identity_upserts": identity_upserts,
                "meta": (AGENT_META_CORE, LAST_SAMPLE_META_KEY, sampled_at),
            }

        try:
            stats, sqlite_detail = await self.store.apply_traffic_sample(
                plan,
                current_scope(),
                fast_stats=True,
                cursor_keys=cursor_keys,
                return_sqlite_timing=True,
            )
            return stats, sqlite_detail
        except Exception:
            log.exception("traffic merged sqlite commit failed")
            return (
                {
                    "clients_seen": 0,
                    "pending": 0,
                    "initialized": 0,
                    "regressed": 0,
                },
                {},
            )

    async def _sample_core(
        self,
        registry: CoreRegistry,
        core_key: str,
        *,
        owners_task: asyncio.Task | None = None,
    ) -> dict[str, int]:
        from agent.asyncutil import gather_independent, maybe_await

        started = time.monotonic()
        driver = registry.get(core_key)
        if core_key == "l2tp":
            await self._drop_linked_l2tp_billing(driver)
        reset_xray = core_key == "xray" and bool(
            getattr(registry.settings, "traffic_xray_reset_stats", False)
        )
        if owners_task is not None:
            snapshot = await maybe_await(driver.usage_snapshot(reset_stats=reset_xray))
            owners = await owners_task
        else:
            snapshot, owners = await gather_independent(
                maybe_await(driver.usage_snapshot(reset_stats=reset_xray)),
                self.store.client_scopes(),
            )
        snapshot_ms = int((time.monotonic() - started) * 1000)
        store_started = time.monotonic()
        stats = await self._store_core_samples(
            core_key,
            snapshot,
            owners=owners,
            registry=registry,
        )
        store_ms = int((time.monotonic() - store_started) * 1000)
        total_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "traffic sample timing core=%s clients=%s pending=%s "
            "snapshot_ms=%s sqlite_ms=%s total_ms=%s",
            core_key,
            stats.get("clients_seen", 0),
            stats.get("pending", 0),
            snapshot_ms,
            store_ms,
            total_ms,
        )
        stats["_timing"] = {
            "snapshot_ms": snapshot_ms,
            "sqlite_ms": store_ms,
            "total_ms": total_ms,
        }
        return stats

    async def _store_core_samples(
        self,
        core_key: str,
        snapshot: Any,
        *,
        owners: dict[tuple[str, str], str],
        registry: CoreRegistry | None = None,
    ) -> dict[str, int]:
        from agent.auth_scope import DEFAULT_SCOPE

        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
        }
        samples = self._usage_rows(core_key, snapshot)
        sampled_at = datetime.now(timezone.utc).isoformat()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for sample in samples:
            scope = owners.get((str(sample["core"]), str(sample["label"])), DEFAULT_SCOPE)
            grouped.setdefault(scope, []).append(sample)
        if not grouped:
            grouped[DEFAULT_SCOPE] = []

        xray_reset = (
            core_key == "xray"
            and registry is not None
            and bool(getattr(registry.settings, "traffic_xray_reset_stats", False))
        )
        for scope, group in grouped.items():
            stored = await self._commit_samples(
                group,
                sampled_at,
                scope,
                core_key,
                xray_reset_stats=xray_reset,
            )
            for key in stats:
                if key == "pending":
                    stats[key] = max(stats[key], int(stored.get(key, 0)))
                else:
                    stats[key] += int(stored.get(key, 0))
        return stats

    def _usage_rows(self, core_key: str, snapshot: Any) -> list[dict[str, Any]]:
        samples: list[dict[str, Any]] = []
        try:
            inbounds = snapshot.inbounds
        except Exception:
            log.exception("traffic sample failed core=%s", core_key)
            return samples

        for inbound in inbounds:
            for client in inbound.clients:
                label = client_key(client)
                if not label:
                    continue

                email = str(getattr(client, "email", "") or "").strip()
                client_id = str(getattr(client, "id", "") or "").strip()
                protocol_id = str(getattr(client, "protocol_id", "") or "").strip()
                self._remember_identity(label, email, client_id)
                samples.append(
                    {
                        "core": core_key,
                        "label": label,
                        "email": email,
                        "client_id": client_id,
                        "protocol_id": protocol_id,
                        "incoming": int(client.incoming or 0),
                        "outgoing": int(client.outgoing or 0),
                    }
                )
        return samples

    async def ensure_sample_fresh(
        self,
        registry: CoreRegistry,
        *,
        max_sample_age_ms: int,
    ) -> bool:
        """Report whether the last snapshot is stale; optionally schedule a refresh.

        With split ``agent serve`` + ``agent work``, sampling must stay in the worker only.
        **Never awaits** the sample on GET.
        """
        age = await self.last_sample_age_ms()
        settings = getattr(registry, "settings", None)
        schedule_on_get = bool(getattr(settings, "traffic_schedule_sample_on_get", False))
        stale = max_sample_age_ms <= 0 or age is None or age > max_sample_age_ms
        if not schedule_on_get:
            return False
        if not stale:
            return False
        self._schedule_sample_all(registry)
        return True

    async def _commit_samples(
        self,
        samples: list[dict[str, Any]],
        sampled_at: str,
        scope: str | None = None,
        core: str | None = None,
        *,
        xray_reset_stats: bool = False,
    ) -> dict[str, int]:
        from agent.auth_scope import current_scope

        def plan(cursors: dict[tuple[str, str], tuple[int, int]]) -> dict[str, Any]:
            return self._plan_sample(
                samples,
                cursors,
                sampled_at,
                xray_reset_stats=xray_reset_stats and str(core or "") == "xray",
            )

        return await self.store.apply_traffic_sample(plan, scope or current_scope(), core)

    def _plan_sample(
        self,
        samples: list[dict[str, Any]],
        sample_cursors: dict[tuple[str, str], tuple[int, int]],
        sampled_at: str,
        *,
        xray_reset_stats: bool = False,
    ) -> dict[str, Any]:
        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
            "unchanged": 0,
        }
        identity_upserts: list[tuple[str, str, str]] = []
        chunk_inserts: list[dict[str, Any]] = []
        client_cursor_upserts: list[tuple[str, str, int, int]] = []

        protected = {str(sample["label"]) for sample in samples if str(sample["label"])}
        for sample in samples:
            core = str(sample["core"])
            label = str(sample["label"])
            email = str(sample["email"] or "")
            client_id = str(sample["client_id"] or "")
            protocol_id = str(sample.get("protocol_id") or "")
            current_incoming = int(sample["incoming"])
            current_outgoing = int(sample["outgoing"])
            stats["clients_seen"] += 1
            self._migrate_legacy_sample_cursors(
                core,
                label,
                email,
                protocol_id=protocol_id,
                protected=protected,
                sample_cursors=sample_cursors,
            )
            if core == "xray" and xray_reset_stats:
                outcome = self._classify_xray_reset_interval_sample(
                    core,
                    label,
                    current_incoming,
                    current_outgoing,
                    sample_cursors=sample_cursors,
                    chunk_inserts=chunk_inserts,
                    client_cursor_upserts=client_cursor_upserts,
                    sampled_at=sampled_at,
                )
            else:
                outcome = self._classify_interval_sample(
                    core,
                    label,
                    current_incoming,
                    current_outgoing,
                    sample_cursors=sample_cursors,
                    chunk_inserts=chunk_inserts,
                    client_cursor_upserts=client_cursor_upserts,
                    sampled_at=sampled_at,
                )
            stats[outcome] = stats.get(outcome, 0) + 1
            for alias in (email, protocol_id):
                alias_text = str(alias or "").strip()
                if not alias_text or alias_text == label or alias_text in protected:
                    continue
                identity_upserts.append((core, alias_text, label))

        stats["pending"] = len(chunk_inserts)
        return {
            "stats": stats,
            "chunk_inserts": chunk_inserts,
            "client_cursor_upserts": client_cursor_upserts,
            "identity_upserts": identity_upserts,
            "meta": (AGENT_META_CORE, LAST_SAMPLE_META_KEY, sampled_at),
        }

    @staticmethod
    def _migrate_legacy_sample_cursors(
        core: str,
        canonical_key: str,
        email: str,
        *,
        protocol_id: str = "",
        protected: set[str] | None = None,
        sample_cursors: dict[tuple[str, str], tuple[int, int]],
    ) -> None:
        if not canonical_key:
            return
        protected = protected or set()
        aliases: list[str] = []
        for name in (email, protocol_id):
            text = str(name or "").strip()
            if not text or text == canonical_key or text in aliases or text in protected:
                continue
            aliases.append(text)
        best = sample_cursors.get((core, canonical_key))
        for name in aliases:
            alias_cursor = sample_cursors.pop((core, name), None)
            if alias_cursor is None:
                continue
            if best is None:
                best = alias_cursor
                continue
            best = (
                max(best[0], alias_cursor[0]),
                max(best[1], alias_cursor[1]),
            )
        if best is not None:
            sample_cursors[(core, canonical_key)] = best

    @staticmethod
    def _classify_xray_reset_interval_sample(
        core: str,
        client_key: str,
        interval_incoming: int,
        interval_outgoing: int,
        *,
        sample_cursors: dict[tuple[str, str], tuple[int, int]],
        chunk_inserts: list[dict[str, Any]],
        client_cursor_upserts: list[tuple[str, str, int, int]],
        sampled_at: str,
    ) -> str:
        """Xray stats query reset=true: snapshot values are interval bytes, not kernel totals."""
        tick_in = max(0, int(interval_incoming))
        tick_out = max(0, int(interval_outgoing))
        pair = (core, client_key)
        last = sample_cursors.get(pair)
        base_in, base_out = last if last is not None else (0, 0)
        new_in = int(base_in) + tick_in
        new_out = int(base_out) + tick_out
        client_cursor_upserts.append((core, client_key, new_in, new_out))
        sample_cursors[pair] = (new_in, new_out)
        if tick_in <= 0 and tick_out <= 0:
            return "unchanged"
        chunk_inserts.append(
            {
                "chunk_id": str(uuid.uuid4()),
                "core": core,
                "client_key": client_key,
                "incoming": tick_in,
                "outgoing": tick_out,
                "sampled_at": sampled_at,
            }
        )
        return "pending"

    @staticmethod
    def _classify_interval_sample(
        core: str,
        client_key: str,
        current_incoming: int,
        current_outgoing: int,
        *,
        sample_cursors: dict[tuple[str, str], tuple[int, int]],
        chunk_inserts: list[dict[str, Any]],
        client_cursor_upserts: list[tuple[str, str, int, int]],
        sampled_at: str,
    ) -> str:
        pair = (core, client_key)
        last = sample_cursors.get(pair)
        client_cursor_upserts.append((core, client_key, current_incoming, current_outgoing))
        sample_cursors[pair] = (current_incoming, current_outgoing)
        if last is None:
            return "initialized"
        last_in, last_out = last
        reset = current_incoming < last_in or current_outgoing < last_out
        if reset:
            tick_in, tick_out = current_incoming, current_outgoing
            log.warning(
                "traffic counter regression core=%s client=%s last=(%s,%s) current=(%s,%s)",
                core,
                client_key,
                last_in,
                last_out,
                current_incoming,
                current_outgoing,
            )
        else:
            tick_in = max(0, current_incoming - last_in)
            tick_out = max(0, current_outgoing - last_out)
        if last_in == 0 and last_out == 0 and (tick_in + tick_out) > _ZERO_CURSOR_SKEW_BYTES:
            log.warning(
                "traffic zero-cursor skew core=%s client=%s tick=(%s,%s) "
                "re-anchor without chunk (reset/stale cursor)",
                core,
                client_key,
                tick_in,
                tick_out,
            )
            return "initialized"
        if tick_in <= 0 and tick_out <= 0:
            return "unchanged"
        chunk_inserts.append(
            {
                "chunk_id": str(uuid.uuid4()),
                "core": core,
                "client_key": client_key,
                "incoming": int(tick_in),
                "outgoing": int(tick_out),
                "sampled_at": sampled_at,
            }
        )
        return "regressed" if reset else "pending"

    def _remember_identity(self, canonical: str, email: str, client_id: str) -> None:
        self._aliases[canonical] = canonical
        if client_id:
            self._aliases[client_id] = canonical
        if email:
            self._aliases[email] = canonical
            self._emails[canonical] = email

    def _canonical_key(self, label: str) -> str:
        return self._aliases.get(label, label)

    def _public_client_key(self, stored: str) -> str:
        """Ack and pending responses publish the panel node_id.

        Email and the Xray protocol UUID are lookup aliases. They are not the
        client key returned to the panel.
        """
        label = str(stored or "").strip()
        if not label:
            return ""
        canonical = str(self._canonical_key(label) or "").strip()
        return canonical or label

    async def _load_persisted_aliases(self) -> None:
        """HTTP and worker are separate processes; aliases cannot live only in memory."""
        for row in await self.store.list_traffic_identity():
            alias = str(row.get("alias") or "").strip()
            canonical = str(row.get("canonical_key") or "").strip()
            if not alias or not canonical:
                continue
            self._aliases[alias] = canonical
            self._aliases.setdefault(canonical, canonical)

    def _snapshot_meta_key(self) -> str:
        from agent.auth_scope import current_scope

        return f"{FETCH_SNAPSHOT_META_KEY}:{current_scope()}"

    def _pending_lock_meta_key(self) -> str:
        from agent.auth_scope import current_scope

        return f"{FETCH_LOCK_META_KEY}:{current_scope()}"

    async def _release_pending_read(self) -> None:
        await self.store.delete_meta(AGENT_META_CORE, self._pending_lock_meta_key())

    def _read_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        from agent.auth_scope import current_scope

        return self._fetch_snapshot.get(current_scope(), {})

    def _write_snapshot(self, snapshot: dict[str, list[dict[str, Any]]]) -> None:
        from agent.auth_scope import current_scope

        self._fetch_snapshot[current_scope()] = snapshot

    async def pending_payload(self, *, persist_snapshot: bool = True) -> dict[str, Any]:
        """Return unacked pending deltas and optionally persist a fetch snapshot for POST ack.

        The panel runs a single billing writer per node (UpdateSubscribeStats
        withoutOverlapping). ``persist_snapshot=False`` keeps GET off the write lock;
        the in-memory snapshot is enough until a background meta write finishes.
        """
        await self._load_persisted_aliases()
        chunks = await self.store.list_traffic_pending_chunks()
        rows = await self.store.list_traffic_pending()
        users: dict[str, dict[str, Any]] = {}
        snapshot: dict[str, list[dict[str, Any]]] = {}
        linked_l2tp = await self._linked_l2tp_client_keys()

        chunks_by_label: dict[str, list[dict[str, Any]]] = {}
        for chunk in chunks:
            stored = str(chunk["client_key"])
            if str(chunk.get("core") or "") == "l2tp" and stored in linked_l2tp:
                continue
            label = self._public_client_key(stored)
            if not label:
                continue
            incoming = int(chunk["incoming"])
            outgoing = int(chunk["outgoing"])
            chunks_by_label.setdefault(label, []).append(
                {
                    "id": str(chunk["chunk_id"]),
                    "incoming": incoming,
                    "outgoing": outgoing,
                    "downlink": incoming,
                    "uplink": outgoing,
                    "sampled_at": chunk.get("sampled_at"),
                }
            )

        for row in rows:
            stored = str(row["client_key"])
            if str(row.get("core") or "") == "l2tp" and stored in linked_l2tp:
                continue
            label = self._public_client_key(stored)
            if not label:
                continue
            if int(row["delta_incoming"]) == 0 and int(row["delta_outgoing"]) == 0:
                chunk_list = chunks_by_label.pop(label, [])
                if not chunk_list:
                    continue
            else:
                chunk_list = chunks_by_label.pop(label, [])
            published = {
                "core": str(row["core"]),
                "client_key": stored,
                "incoming": int(row["delta_incoming"]),
                "outgoing": int(row["delta_outgoing"]),
            }
            snapshot.setdefault(label, []).append(published)
            if stored != label:
                snapshot.setdefault(stored, []).append(published)
            users[label] = {
                "core": str(row["core"]),
                "uplink": int(row["delta_outgoing"]),
                "downlink": int(row["delta_incoming"]),
                "chunks": chunk_list,
            }

        for label, chunk_list in chunks_by_label.items():
            downlink = sum(int(item["downlink"]) for item in chunk_list)
            uplink = sum(int(item["uplink"]) for item in chunk_list)
            if downlink == 0 and uplink == 0:
                continue
            stored = label
            core = "xray"
            for chunk in chunks:
                if self._public_client_key(str(chunk["client_key"])) != label:
                    continue
                stored = str(chunk["client_key"])
                core = str(chunk["core"])
            users[label] = {
                "core": core,
                "uplink": uplink,
                "downlink": downlink,
                "chunks": chunk_list,
            }
            published = {
                "core": core,
                "client_key": stored,
                "incoming": downlink,
                "outgoing": uplink,
            }
            snapshot.setdefault(label, []).append(published)

        self._write_snapshot(snapshot)
        if persist_snapshot:
            await self._persist_fetch_snapshot(snapshot)
        else:
            self._schedule_persist_fetch_snapshot(snapshot)

        return {
            "sampled_at": await self.store.get_meta(
                AGENT_META_CORE,
                LAST_SAMPLE_META_KEY,
            ),
            "worker_lag_ms": await self._worker_lag_ms(),
            "users": users,
        }

    async def ack_chunk_ids(self, chunk_ids: list[str]) -> tuple[int, list[str]]:
        return await self.store.ack_traffic_chunk_ids(chunk_ids)

    async def ack_pending(self) -> int:
        rows = await self.store.list_traffic_pending()
        await self.store.ack_traffic_rows(rows)
        acked = len(rows)
        self._write_snapshot({})
        await self.store.set_meta(AGENT_META_CORE, self._snapshot_meta_key(), [])
        await self._release_pending_read()

        if acked:
            log.info("traffic ack applied clients=%s", acked)

        return acked

    async def ack_clients(
        self,
        client_keys: list[str],
        billed: dict[str, tuple[int, int]] | None = None,
        drop: list[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Ack the panel node_id keys the panel says it has billed.

        ``billed`` is the raw queue the panel already applied, keyed by the
        requested id. It is used only when that id is missing from the GET
        snapshot, and only those bytes are subtracted. Later samples stay queued.

        ``drop`` deletes the live pending row and moves the baseline to the
        current counter. The panel sends keys it will never bill. Bytes sampled
        after this call stay queued.
        """
        await self._load_persisted_aliases()
        billed = billed or {}
        requested = []
        seen: set[str] = set()
        for raw in client_keys:
            label = str(raw or "").strip()
            if not label or label in seen:
                continue
            seen.add(label)
            requested.append(label)

        drop_labels: list[str] = []
        drop_seen: set[str] = set()
        for raw in drop or []:
            label = str(raw or "").strip()
            if not label or label in drop_seen:
                continue
            drop_seen.add(label)
            drop_labels.append(label)

        # HTTP workers do not share memory; reload the snapshot that GET persisted.
        if not self._read_snapshot():
            await self._load_persisted_snapshot()

        acked: list[str] = []
        not_found: list[str] = []
        to_ack: list[dict[str, Any]] = []
        live_index: dict[str, list[dict[str, Any]]] | None = None

        for label in requested:
            canonical = self._canonical_key(label)
            rows = self._read_snapshot().get(label) or self._read_snapshot().get(canonical) or []
            if not rows:
                if live_index is None:
                    live_index = await self._live_pending_index()
                amounts = billed.get(label) or billed.get(canonical)
                rows = self._rows_for_billed_amount(live_index, label, canonical, amounts)
            if not rows:
                not_found.append(label)
                continue

            for row in rows:
                patched = dict(row)
                amounts = (
                    billed.get(label)
                    or billed.get(canonical)
                    or billed.get(self._public_client_key(str(row.get("client_key") or "")))
                )
                if amounts:
                    patched["billed_incoming"] = max(0, int(amounts[0]))
                    patched["billed_outgoing"] = max(0, int(amounts[1]))
                to_ack.append(patched)
            published = self._public_client_key(str(rows[0].get("client_key") or "")) or self._public_client_key(label)
            if published and published not in acked:
                acked.append(published)
            log.debug("traffic ack client=%s rows=%s", published or label, len(rows))

        await self.store.ack_billed_snapshots(to_ack)
        await self._forget_acked_snapshot(to_ack)

        acked_ids = set(acked)
        to_drop: list[str] = []
        for label in drop_labels:
            canonical = self._canonical_key(label)
            if label in acked_ids or canonical in acked_ids:
                continue
            to_drop.append(label)
        if to_drop:
            dropped, _missing = await self._drop_pending_keys(to_drop)
            for key in dropped:
                if key not in acked_ids:
                    acked.append(key)
                    acked_ids.add(key)
            not_found = [
                label
                for label in not_found
                if label not in acked_ids and self._canonical_key(label) not in acked_ids
            ]
            for label in to_drop:
                canonical = self._canonical_key(label)
                if label in acked_ids or canonical in acked_ids:
                    continue
                if label not in not_found:
                    not_found.append(label)

        if requested or drop_labels:
            await self._release_pending_read()
        if requested or drop_labels:
            log.info(
                "traffic ack summary requested=%s acked=%s not_found=%s rows=%s",
                len(requested),
                len(acked),
                len(not_found),
                len(to_ack),
            )
        return acked, not_found

    async def _drop_pending_keys(self, labels: list[str]) -> tuple[list[str], list[str]]:
        """Discard a pending queue the panel will not bill.

        The ack baseline moves to the current counter, so the next sample only
        queues bytes that arrive after this drop.
        """
        index = await self._live_pending_index()
        dropped: list[str] = []
        missing: list[str] = []
        rows_to_ack: list[dict[str, Any]] = []
        seen_rows: set[tuple[str, str]] = set()
        for label in labels:
            canonical = self._canonical_key(label)
            rows = index.get(label) or index.get(canonical) or []
            if not rows:
                missing.append(label)
                continue
            for row in rows:
                identity = (str(row.get("core") or ""), str(row.get("client_key") or ""))
                if not identity[0] or not identity[1] or identity in seen_rows:
                    continue
                seen_rows.add(identity)
                rows_to_ack.append(row)
            published = self._public_client_key(str(rows[0].get("client_key") or "")) or label
            if published not in dropped:
                dropped.append(published)
        if rows_to_ack:
            await self.store.ack_traffic_rows(rows_to_ack)
            await self._forget_acked_snapshot(rows_to_ack)
        return dropped, missing

    async def _live_pending_index(self) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        for row in await self.store.list_traffic_pending():
            stored = str(row.get("client_key") or "")
            public = self._public_client_key(stored)
            identity = (str(row.get("core") or ""), stored)
            for key in {stored, public}:
                if not key:
                    continue
                bucket = index.setdefault(key, [])
                if all(
                    (str(item.get("core") or ""), str(item.get("client_key") or "")) != identity
                    for item in bucket
                ):
                    bucket.append(row)
        return index

    def _rows_for_billed_amount(
        self,
        live_index: dict[str, list[dict[str, Any]]],
        label: str,
        canonical: str,
        amounts: tuple[int, int] | None,
    ) -> list[dict[str, Any]]:
        """Build snapshot rows that subtract only the bytes the panel applied."""
        if not amounts:
            return []
        left_in, left_out = max(0, int(amounts[0])), max(0, int(amounts[1]))
        if left_in == 0 and left_out == 0:
            return []

        synthetic: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for row in live_index.get(label) or live_index.get(canonical) or []:
            identity = (str(row.get("core") or ""), str(row.get("client_key") or ""))
            if not identity[0] or not identity[1] or identity in seen:
                continue
            seen.add(identity)
            if left_in == 0 and left_out == 0:
                break
            snap = self._snapshot_row_for_billed(row, left_in, left_out)
            used_in = int(snap["delta_incoming"])
            used_out = int(snap["delta_outgoing"])
            if used_in == 0 and used_out == 0:
                continue
            left_in -= used_in
            left_out -= used_out
            synthetic.append(snap)
        return synthetic

    @staticmethod
    def _snapshot_row_for_billed(row: dict[str, Any], billed_in: int, billed_out: int) -> dict[str, Any]:
        live_in = max(0, int(row.get("delta_incoming") or 0))
        live_out = max(0, int(row.get("delta_outgoing") or 0))
        current_in = max(0, int(row.get("current_incoming") or 0))
        current_out = max(0, int(row.get("current_outgoing") or 0))
        take_in = min(live_in, max(0, billed_in))
        take_out = min(live_out, max(0, billed_out))
        snap = dict(row)
        snap["delta_incoming"] = take_in
        snap["delta_outgoing"] = take_out
        # Counter at the billed queue, so the baseline moves there and later growth stays.
        snap["current_incoming"] = max(0, current_in - (live_in - take_in))
        snap["current_outgoing"] = max(0, current_out - (live_out - take_out))
        return snap

    async def _forget_acked_snapshot(self, rows: list[dict[str, Any]]) -> None:
        """A repeated POST of the same GET must not subtract the billed delta again."""
        forget = {
            (str(row.get("core") or ""), str(row.get("client_key") or ""))
            for row in rows
            if row.get("core") and row.get("client_key")
        }
        if not forget:
            return
        kept_memory: dict[str, list[dict[str, Any]]] = {}
        for label, items in self._read_snapshot().items():
            remaining = [
                row
                for row in items
                if (str(row.get("core") or ""), str(row.get("client_key") or "")) not in forget
            ]
            if remaining:
                kept_memory[label] = remaining
        self._write_snapshot(kept_memory)
        raw = await self.store.get_meta(AGENT_META_CORE, self._snapshot_meta_key(), [])
        if not isinstance(raw, list):
            return
        kept = [
            row
            for row in raw
            if isinstance(row, dict)
            and (str(row.get("core") or ""), str(row.get("client_key") or "")) not in forget
        ]
        await self.store.set_meta(AGENT_META_CORE, self._snapshot_meta_key(), kept)

    async def _persist_fetch_snapshot(self, snapshot: dict[str, list[dict[str, Any]]]) -> None:
        """Remember the pending bytes returned by GET so a later ack can subtract only those."""
        stored: dict[tuple[str, str], dict[str, Any]] = {}
        for rows in snapshot.values():
            for row in rows:
                core = str(row.get("core") or "")
                client_key = str(row.get("client_key") or "")
                if not core or not client_key:
                    continue
                stored[(core, client_key)] = {
                    "core": core,
                    "client_key": client_key,
                    "delta_incoming": int(row.get("delta_incoming") or 0),
                    "delta_outgoing": int(row.get("delta_outgoing") or 0),
                    "current_incoming": int(row.get("current_incoming") or 0),
                    "current_outgoing": int(row.get("current_outgoing") or 0),
                }
        await self.store.set_meta(AGENT_META_CORE, self._snapshot_meta_key(), list(stored.values()))

    async def _load_persisted_snapshot(self) -> None:
        raw = await self.store.get_meta(AGENT_META_CORE, self._snapshot_meta_key(), [])
        snapshot: dict[str, list[dict[str, Any]]] = {}
        if isinstance(raw, list):
            for row in raw:
                if not isinstance(row, dict):
                    continue
                stored = str(row.get("client_key") or "")
                label = self._public_client_key(stored)
                published = dict(row)
                if label:
                    snapshot.setdefault(label, []).append(published)
                if stored and stored != label:
                    snapshot.setdefault(stored, []).append(published)
        self._write_snapshot(snapshot)

    async def _without_absent_clients(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop pending rows for clients the agent no longer stores.

        A deleted subscribe leaves its last pending row behind, often still keyed
        by email from before node_id billing. Nothing samples that client again,
        so the row would otherwise be returned on every GET. Email of a client
        that is still stored is rewritten onto that client's node_id.
        """
        index = await self._stored_client_index()
        if not index:
            return rows

        changed = False
        dropped = 0
        for row in rows:
            core = str(row.get("core") or "")
            stored = str(row.get("client_key") or "")
            table = index.get(core)
            if table is None:
                continue
            target = table.get(stored) or table.get(self._public_client_key(stored))
            if not target:
                await self.store.delete_traffic_pending(core, stored)
                dropped += 1
                changed = True
                continue
            if stored == target:
                continue
            await self._fold_pending_onto(core, stored, target, row)
            changed = True

        if dropped:
            log.info("traffic pending dropped absent clients=%s", dropped)
        if not changed:
            return rows
        return await self.store.list_traffic_pending()

    async def _fold_pending_onto(
        self,
        core: str,
        stored: str,
        target: str,
        row: dict[str, Any],
    ) -> None:
        """Move one legacy pending key onto the live node_id without adding the bytes twice."""
        current = await self.store.get_traffic_pending(core, target)
        incoming = int(row.get("delta_incoming") or 0)
        outgoing = int(row.get("delta_outgoing") or 0)
        current_in = int(row.get("current_incoming") or 0)
        current_out = int(row.get("current_outgoing") or 0)
        if current is not None:
            other = int(current["delta_incoming"]) + int(current["delta_outgoing"])
            if incoming + outgoing <= other:
                await self.store.delete_traffic_pending(core, stored)
                return
        await self.store.upsert_traffic_pending(
            core,
            target,
            incoming,
            outgoing,
            current_in,
            current_out,
        )
        await self.store.delete_traffic_pending(core, stored)

    async def _stored_client_index(self) -> dict[str, dict[str, str]]:
        """Map every stored id and email to the client's node_id, per core.

        A core is omitted when it has no stored clients, so an empty or unread
        core cannot wipe a pending queue that still belongs to live users.
        """
        index: dict[str, dict[str, str]] = {}
        nested = (
            ("wireguard", "interface", "peers"),
            ("amnezia", "interface", "peers"),
            ("l2tp", "server", "users"),
            ("openvpn", "server", "users"),
        )
        for core, kind, field in nested:
            docs = await self.store.list_docs(core, kind)
            rows = [
                row
                for doc in docs
                if isinstance(doc, dict)
                for row in (doc.get(field) or [])
                if isinstance(row, dict)
            ]
            table = self._index_client_rows(rows)
            if table:
                index[core] = table

        xray_rows: list[dict[str, Any]] = []
        for kind in ("client_quota", "xray_disabled_client"):
            for row in await self.store.list_docs("xray", kind):
                if isinstance(row, dict):
                    xray_rows.append(row)
        xray = self._index_client_rows(xray_rows)
        if xray:
            index["xray"] = xray
        return index

    @staticmethod
    def _index_client_rows(rows: list[dict[str, Any]]) -> dict[str, str]:
        ids: set[str] = set()
        emails: list[tuple[str, str]] = []
        for row in rows:
            node = str(row.get("node_id") or row.get("id") or "").strip()
            if not node:
                continue
            ids.add(node)
            for key in (row.get("id"), row.get("node_id"), row.get("client_link_uuid")):
                text = str(key or "").strip()
                if text:
                    ids.add(text)
            email = str(row.get("email") or "").strip()
            if email:
                emails.append((email, node))

        table = {item: item for item in ids}
        ambiguous: set[str] = set()
        for email, node in emails:
            if email in ids or email in ambiguous:
                continue
            previous = table.get(email)
            if previous is not None and previous != node:
                table.pop(email, None)
                ambiguous.add(email)
                continue
            table[email] = node
        return table

    async def _linked_l2tp_client_keys(self) -> set[str]:
        """Canonical ids/emails of L2TP users linked to a WireGuard/Amnezia peer."""
        keys: set[str] = set()
        try:
            docs = await self.store.list_docs("l2tp", "server")
        except Exception:
            return keys
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            for user in doc.get("users") or []:
                if not isinstance(user, dict):
                    continue
                if not str(user.get("linked_peer_id") or "").strip():
                    continue
                for candidate in (user.get("id"), user.get("email")):
                    label = str(candidate or "").strip()
                    if label:
                        keys.add(label)
        return keys

    async def _drop_linked_l2tp_billing(self, driver: Any) -> None:
        """Remove pending/ack rows for companion L2TP users (WG peer owns billing)."""
        from agent.asyncutil import maybe_await

        try:
            servers = await maybe_await(driver.list_servers())
        except Exception:
            return
        for server in servers or []:
            if not isinstance(server, dict):
                continue
            for user in server.get("users") or []:
                if not isinstance(user, dict):
                    continue
                if not str(user.get("linked_peer_id") or "").strip():
                    continue
                await self.reset_client_record("l2tp", user)

    async def reset_client(self, core: str, client_key_label: str) -> None:
        """Drop ack/pending rows after panel delete or renew."""
        await self.store.delete_traffic_ack(core, client_key_label)
        await self.store.delete_traffic_pending(core, client_key_label)

    async def clear_pending_queue(
        self,
        registry: CoreRegistry | None = None,
    ) -> dict[str, int]:
        """Drop pending rows and align clients.incoming/outgoing with live kernel counters."""
        from agent.auth_scope import current_scope

        scope = current_scope()
        synced = 0
        if registry is not None:
            synced = await self._sync_kernel_cursors_for_reset(registry, scope)
        result = await self.store.clear_pending_traffic_queue(scope)
        await self._release_pending_read()
        self._write_snapshot({})
        await self.store.delete_meta(AGENT_META_CORE, f"{FETCH_SNAPSHOT_META_KEY}:{scope}")
        result["cursors_synced"] = synced
        log.warning(
            "pending queue cleared chunks=%s clients=%s legacy=%s cursors_synced=%s",
            result.get("chunks_deleted"),
            result.get("clients_cleared"),
            result.get("legacy_rows_deleted"),
            synced,
        )
        return result

    async def _sync_kernel_cursors_for_reset(self, registry: CoreRegistry, scope: str) -> int:
        """Set clients.incoming/outgoing from core counters (discard unacked pending)."""
        from agent.asyncutil import maybe_await
        from collections import defaultdict

        upserts: list[tuple[str, str, int, int]] = []
        seen: set[tuple[str, str]] = set()
        settings = registry.settings
        if hasattr(settings, "traffic_billing_cores") and callable(settings.traffic_billing_cores):
            cores = list(settings.traffic_billing_cores())
        else:
            cores = list(settings.cores())
        if "l2tp" in cores:
            cores = ["l2tp"] + [key for key in cores if key != "l2tp"]
        if "xray" in cores:
            try:
                await registry.get("xray").warm_usage_cache()
            except Exception:
                log.exception("pending reset: xray usage prewarm failed")
        skip_xray_kernel = bool(getattr(registry.settings, "traffic_xray_reset_stats", False))
        for core_key in cores:
            if core_key == "xray" and skip_xray_kernel:
                continue
            driver = registry.get(core_key)
            try:
                snapshot = await maybe_await(driver.usage_snapshot())
            except Exception:
                log.exception("pending reset: could not read usage snapshot core=%s", core_key)
                continue
            for sample in self._usage_rows(core_key, snapshot):
                label = str(sample["label"])
                pair = (str(core_key), label)
                if pair in seen:
                    continue
                seen.add(pair)
                upserts.append(
                    (
                        str(core_key),
                        label,
                        int(sample["incoming"]),
                        int(sample["outgoing"]),
                    )
                )
        chunk_totals: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        for chunk in await self.store.list_traffic_pending_chunks():
            key = (str(chunk.get("core") or ""), str(chunk.get("client_key") or ""))
            chunk_totals[key][0] += int(chunk.get("incoming") or 0)
            chunk_totals[key][1] += int(chunk.get("outgoing") or 0)
        for key, deltas in chunk_totals.items():
            if key in seen:
                continue
            core_name, client_id = key
            if not core_name or not client_id:
                continue
            client = await self.store.get_client_traffic_cursor(core_name, client_id)
            base_in, base_out = client if client is not None else (0, 0)
            upserts.append(
                (
                    core_name,
                    client_id,
                    base_in + int(deltas[0]),
                    base_out + int(deltas[1]),
                )
            )
        if not upserts:
            return 0
        cursor_map = {(str(c), str(k)): (int(i), int(o)) for c, k, i, o in upserts}
        for row in await self.store.list_traffic_identity():
            base = cursor_map.get((str(row.get("core") or ""), str(row.get("canonical_key") or "")))
            if base is None:
                continue
            alias = str(row.get("alias") or "").strip()
            core_name = str(row.get("core") or "").strip()
            if not alias or not core_name or (core_name, alias) in cursor_map:
                continue
            upserts.append((core_name, alias, base[0], base[1]))
        await self.store.bulk_set_client_traffic_cursors(scope, upserts)
        return len(cursor_map)

    async def reset_client_record(
        self,
        core: str,
        record: dict[str, Any],
        *extra_labels: str,
    ) -> None:
        """Clear traffic worker state for every identifier the panel may use."""
        seen: set[str] = set()
        for candidate in (
            record.get("id"),
            record.get("email"),
            *extra_labels,
        ):
            label = str(candidate or "").strip()
            if label and label not in seen:
                seen.add(label)
                await self.reset_client(core, label)

    async def last_sample_age_ms(self) -> int | None:
        return await self._worker_lag_ms()

    async def _worker_lag_ms(self) -> int | None:
        sampled_at = await self.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY)
        if not sampled_at:
            return None

        try:
            ts = datetime.fromisoformat(str(sampled_at).replace("Z", "+00:00"))
        except ValueError:
            return None

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return max(0, int((datetime.now(timezone.utc) - ts).total_seconds() * 1000))
