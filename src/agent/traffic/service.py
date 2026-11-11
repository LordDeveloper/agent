from __future__ import annotations

import asyncio
import os
import time
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
FETCH_SNAPSHOT_META_KEY = "traffic_fetch_snapshot"
FETCH_LOCK_META_KEY = "traffic_fetch_lock"
# Legacy meta lock TTL (GET no longer blocks on this). Ack still clears the row
# when present so upgrades from builds that held the lock do not leave stale meta.
PENDING_READ_LOCK_SECONDS = 20.0
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

    async def sample_all(self, registry: CoreRegistry) -> dict[str, int]:
        """Refresh pending deltas from every core at once (online not required).

        Each core reads its counters and writes its own pending rows without
        waiting for the other cores to finish their snapshot.
        """
        from agent.asyncutil import gather_independent

        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
        }

        cores = self._listed_cores(registry) or []
        if "l2tp" in cores:
            cores = ["l2tp"] + [key for key in cores if key != "l2tp"]

        sampled = await gather_independent(
            *(self._sample_core(registry, core_key) for core_key in cores),
            return_exceptions=True,
        )

        for item in sampled:
            if isinstance(item, Exception):
                log.exception("traffic sample failed: %s", item)
                continue
            for key in stats:
                if key == "pending":
                    # Each core reports the whole queue size after its commit.
                    stats[key] = max(stats[key], int(item.get(key, 0)))
                else:
                    stats[key] += int(item.get(key, 0))
        return stats

    async def _sample_core(self, registry: CoreRegistry, core_key: str) -> dict[str, int]:
        from agent.asyncutil import maybe_await

        driver = registry.get(core_key)
        if core_key == "l2tp":
            await self._drop_linked_l2tp_billing(driver)
        # One bulk snapshot per core (Xray user>>> grouped, WireGuard peer dump, …).
        snapshot = await maybe_await(driver.usage_snapshot())
        return await self._store_core_samples(core_key, snapshot)

    async def _store_core_samples(self, core_key: str, snapshot: Any) -> dict[str, int]:
        from agent.auth_scope import DEFAULT_SCOPE

        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
        }
        samples = self._usage_rows(core_key, snapshot)
        sampled_at = datetime.now(timezone.utc).isoformat()
        owners = await self.store.client_scopes()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for sample in samples:
            scope = owners.get((str(sample["core"]), str(sample["label"])), DEFAULT_SCOPE)
            grouped.setdefault(scope, []).append(sample)
        if not grouped:
            grouped[DEFAULT_SCOPE] = []

        for scope, group in grouped.items():
            stored = await self._commit_samples(group, sampled_at, scope, core_key)
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
        """If the last snapshot is stale, schedule a background ``sample_all``.

        Returns True when a refresh was scheduled. **Never awaits** the sample: the panel
        uses a ~20s HTTP timeout; ``sample_all`` can block longer when cores are slow, which
        caused cURL error 28 with 0 bytes. The GET always returns promptly with whatever is
        in the pending queue; the traffic worker or the next poll sees fresher data.
        """
        if max_sample_age_ms <= 0:
            self._schedule_sample_all(registry)
            return True

        age = await self.last_sample_age_ms()
        if age is not None and age <= max_sample_age_ms:
            return False

        self._schedule_sample_all(registry)
        return True

    async def _commit_samples(
        self,
        samples: list[dict[str, Any]],
        sampled_at: str,
        scope: str | None = None,
        core: str | None = None,
    ) -> dict[str, int]:
        from agent.auth_scope import current_scope

        def plan(acks: dict, pending: dict) -> dict[str, Any]:
            return self._plan_sample(samples, acks, pending, sampled_at)

        return await self.store.apply_traffic_sample(plan, scope or current_scope(), core)

    def _plan_sample(
        self,
        samples: list[dict[str, Any]],
        acks: dict[tuple[str, str], tuple[int, int]],
        pending: dict[tuple[str, str], dict[str, int]],
        sampled_at: str,
    ) -> dict[str, Any]:
        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
            "unchanged": 0,
        }
        ack_upserts: list[tuple[str, str, int, int]] = []
        ack_deletes: list[tuple[str, str]] = []
        # One pending entry per client. Later samples in this batch replace it.
        pending_upserts: dict[tuple[str, str], dict[str, Any]] = {}
        pending_deletes: set[tuple[str, str]] = set()
        identity_upserts: list[tuple[str, str, str]] = []

        def set_ack(core: str, key: str, incoming: int, outgoing: int) -> None:
            acks[(core, key)] = (incoming, outgoing)
            ack_upserts.append((core, key, incoming, outgoing))

        def delete_ack(core: str, key: str) -> None:
            if (core, key) not in acks:
                return
            del acks[(core, key)]
            ack_deletes.append((core, key))

        def set_pending(
            core: str,
            key: str,
            delta_incoming: int,
            delta_outgoing: int,
            current_incoming: int,
            current_outgoing: int,
        ) -> None:
            # Update the client's single pending. Do not append another row.
            row = {
                "delta_incoming": delta_incoming,
                "delta_outgoing": delta_outgoing,
                "current_incoming": current_incoming,
                "current_outgoing": current_outgoing,
            }
            pending[(core, key)] = row
            pending_upserts[(core, key)] = {"core": core, "client_key": key, **row}
            pending_deletes.discard((core, key))

        def delete_pending(core: str, key: str) -> None:
            if (core, key) not in pending:
                return
            del pending[(core, key)]
            pending_upserts.pop((core, key), None)
            pending_deletes.add((core, key))

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
            self._migrate_legacy_keys(
                core,
                label,
                email,
                client_id,
                set_ack=set_ack,
                delete_ack=delete_ack,
                set_pending=set_pending,
                delete_pending=delete_pending,
                acks=acks,
                pending=pending,
                protocol_id=protocol_id,
                protected=protected,
            )
            outcome = self._classify_sample(
                core,
                label,
                current_incoming,
                current_outgoing,
                acks=acks,
                pending=pending,
                set_ack=set_ack,
                set_pending=set_pending,
                delete_pending=delete_pending,
            )
            stats[outcome] = stats.get(outcome, 0) + 1
            for alias in (email, protocol_id):
                alias_text = str(alias or "").strip()
                # Another client's node_id is a primary key, not an alias of this one.
                if not alias_text or alias_text == label or alias_text in protected:
                    continue
                identity_upserts.append((core, alias_text, label))

        return {
            "stats": stats,
            "ack_upserts": ack_upserts,
            "ack_deletes": ack_deletes,
            "pending_upserts": list(pending_upserts.values()),
            "pending_deletes": list(pending_deletes),
            "identity_upserts": identity_upserts,
            "meta": (AGENT_META_CORE, LAST_SAMPLE_META_KEY, sampled_at),
        }

    @staticmethod
    def _migrate_legacy_keys(
        core: str,
        canonical_key: str,
        email: str,
        client_id: str,
        *,
        set_ack,
        delete_ack,
        set_pending,
        delete_pending,
        acks: dict[tuple[str, str], tuple[int, int]],
        pending: dict[tuple[str, str], dict[str, int]],
        protocol_id: str = "",
        protected: set[str] | None = None,
    ) -> None:
        """Move email and Xray-UUID traffic rows onto the panel node_id.

        Rows are moved, not added. Two aliases for one client are the same
        bytes, so the larger pending total is kept and the other is dropped.
        An alias that is another client's node_id in this sample is left alone.
        """
        del client_id
        if not canonical_key:
            return
        protected = protected or set()
        aliases: list[str] = []
        for name in (email, protocol_id):
            text = str(name or "").strip()
            if not text or text == canonical_key or text in aliases:
                continue
            if text in protected:
                continue
            aliases.append(text)
        if not aliases:
            return

        best_pending = pending.get((core, canonical_key))
        pending_changed = False
        best_total = -1
        if best_pending is not None:
            best_total = int(best_pending["delta_incoming"]) + int(best_pending["delta_outgoing"])
        for name in aliases:
            alias_pending = pending.get((core, name))
            if alias_pending is None:
                continue
            alias_total = int(alias_pending["delta_incoming"]) + int(alias_pending["delta_outgoing"])
            if best_pending is None or alias_total > best_total:
                best_pending = {
                    "delta_incoming": int(alias_pending["delta_incoming"]),
                    "delta_outgoing": int(alias_pending["delta_outgoing"]),
                    "current_incoming": int(alias_pending["current_incoming"]),
                    "current_outgoing": int(alias_pending["current_outgoing"]),
                }
                best_total = alias_total
                pending_changed = True
            delete_pending(core, name)
        if pending_changed and best_pending is not None:
            set_pending(
                core,
                canonical_key,
                int(best_pending["delta_incoming"]),
                int(best_pending["delta_outgoing"]),
                int(best_pending["current_incoming"]),
                int(best_pending["current_outgoing"]),
            )

        best_ack = acks.get((core, canonical_key))
        ack_changed = False
        for name in aliases:
            alias_ack = acks.get((core, name))
            if alias_ack is None:
                continue
            merged = alias_ack if best_ack is None else (
                max(int(best_ack[0]), int(alias_ack[0])),
                max(int(best_ack[1]), int(alias_ack[1])),
            )
            ack_changed = ack_changed or merged != best_ack
            best_ack = merged
            delete_ack(core, name)
        if ack_changed and best_ack is not None:
            set_ack(core, canonical_key, int(best_ack[0]), int(best_ack[1]))

    @staticmethod
    def _preserved_delta(
        pending: dict[tuple[str, str], dict[str, int]],
        core: str,
        client_key_label: str,
    ) -> tuple[int, int]:
        row = pending.get((core, client_key_label))
        if row is None:
            return 0, 0
        return int(row["delta_incoming"]), int(row["delta_outgoing"])

    @staticmethod
    def _classify_sample(
        core: str,
        client_key_label: str,
        current_incoming: int,
        current_outgoing: int,
        *,
        acks: dict[tuple[str, str], tuple[int, int]],
        pending: dict[tuple[str, str], dict[str, int]],
        set_ack,
        set_pending,
        delete_pending,
    ) -> str:
        preserved_in, preserved_out = TrafficService._preserved_delta(pending, core, client_key_label)
        last = pending.get((core, client_key_label))
        ack = acks.get((core, client_key_label))
        if ack is None:
            # First sight anchors the counters. Existing history is not queued.
            # A pending row that already existed stays billable.
            set_ack(
                core,
                client_key_label,
                current_incoming,
                current_outgoing,
            )
            if preserved_in > 0 or preserved_out > 0:
                set_pending(
                    core,
                    client_key_label,
                    preserved_in,
                    preserved_out,
                    current_incoming,
                    current_outgoing,
                )
                return "pending"
            delete_pending(core, client_key_label)
            return "initialized"

        ack_in, ack_out = int(ack[0]), int(ack[1])
        has_last = last is not None
        last_in = int(last["current_incoming"]) if has_last else ack_in
        last_out = int(last["current_outgoing"]) if has_last else ack_out
        bill_in, base_in = TrafficService._direction_delta(
            current_incoming,
            ack_in,
            preserved_in,
            last_in,
            has_last,
        )
        bill_out, base_out = TrafficService._direction_delta(
            current_outgoing,
            ack_out,
            preserved_out,
            last_out,
            has_last,
        )
        reset = current_incoming < last_in or current_outgoing < last_out
        if reset:
            log.warning(
                "traffic counter regression core=%s client=%s ack=(%s,%s) current=(%s,%s) preserved=(%s,%s)",
                core,
                client_key_label,
                ack_in,
                ack_out,
                current_incoming,
                current_outgoing,
                preserved_in,
                preserved_out,
            )
        if base_in != ack_in or base_out != ack_out:
            set_ack(core, client_key_label, base_in, base_out)
        if bill_in > 0 or bill_out > 0:
            set_pending(
                core,
                client_key_label,
                bill_in,
                bill_out,
                current_incoming,
                current_outgoing,
            )
            return "regressed" if reset else "pending"

        # Keep unacked bytes queued even when this tick added 0 (worker tick ≠ panel ack).
        if preserved_in > 0 or preserved_out > 0:
            set_pending(
                core,
                client_key_label,
                preserved_in,
                preserved_out,
                current_incoming,
                current_outgoing,
            )
            return "unchanged"

        delete_pending(core, client_key_label)
        return "regressed" if reset else "unchanged"

    @staticmethod
    def _direction_delta(
        current: int,
        baseline: int,
        preserved: int,
        last_observed: int,
        has_last: bool,
    ) -> tuple[int, int]:
        """Add this tick onto the client's one pending row.

        Tick matches the classic counter delta against the last stored counter
        (the pending row's current value, or the ack when there is no pending):

            tick = current if current < last else current - last

        Until a reset, that tick is added onto the pending already queued.
        A reset (current < last) still adds the whole new counter onto the
        unacked pending, then moves the baseline to the new counter. The
        same row is updated; a sample never inserts a second pending.
        """
        last = last_observed if has_last else baseline
        if current < last:
            return preserved + current, current
        return preserved + (current - last), baseline

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

    def _pending_reader_owner(self) -> str:
        override = getattr(self, "_pending_reader_id", None)
        if override:
            return str(override)
        return str(os.getpid())

    async def _claim_pending_read(self) -> bool:
        now = time.time()
        return await self.store.claim_meta_lock(
            AGENT_META_CORE,
            self._pending_lock_meta_key(),
            self._pending_reader_owner(),
            now + PENDING_READ_LOCK_SECONDS,
            now,
        )

    async def _pending_read_is_held(self) -> bool:
        raw = await self.store.get_meta(AGENT_META_CORE, self._pending_lock_meta_key(), None)
        if not isinstance(raw, dict):
            return False
        try:
            expires_at = float(raw.get("expires_at") or 0)
        except (TypeError, ValueError):
            return False
        return expires_at > time.time() and bool(str(raw.get("owner") or ""))

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
        rows = await self.store.list_traffic_pending()
        users: dict[str, dict[str, Any]] = {}
        snapshot: dict[str, list[dict[str, Any]]] = {}
        linked_l2tp = await self._linked_l2tp_client_keys()

        for row in rows:
            stored = str(row["client_key"])
            if str(row.get("core") or "") == "l2tp" and stored in linked_l2tp:
                continue
            label = self._public_client_key(stored)
            if not label:
                continue

            published = dict(row)
            snapshot.setdefault(label, []).append(published)
            if stored != label:
                snapshot.setdefault(stored, []).append(published)
            entry = {
                "core": row["core"],
                "uplink": int(row["delta_outgoing"]),
                "downlink": int(row["delta_incoming"]),
            }
            users[label] = entry

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

            to_ack.extend(rows)
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
