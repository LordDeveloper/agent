from __future__ import annotations

import asyncio
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
        self._fetch_snapshot: dict[str, list[dict[str, Any]]] = {}
        self._sample_lock = asyncio.Lock()
        self._sample_flight: asyncio.Task | None = None

    def _schedule_sample_all(self, registry: CoreRegistry) -> None:
        """Start a background ``sample_all`` if none is running (does not await)."""

        async def _run() -> None:
            try:
                await self.sample_all(registry)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("traffic background sample failed")
            finally:
                async with self._sample_lock:
                    if self._sample_flight is not None and self._sample_flight.done():
                        self._sample_flight = None

        async def _guard() -> None:
            async with self._sample_lock:
                if self._sample_flight is not None and not self._sample_flight.done():
                    return
                self._sample_flight = asyncio.create_task(_run())

        loop = asyncio.get_running_loop()
        loop.create_task(_guard())

    async def sample_all(self, registry: CoreRegistry) -> dict[str, int]:
        """Refresh pending deltas from core counters (online not required)."""
        from agent.asyncutil import gather_independent, maybe_await

        stats = {
            "clients_seen": 0,
            "pending": 0,
            "initialized": 0,
            "regressed": 0,
        }

        cores = list(registry.settings.cores())
        if "l2tp" in cores:
            cores = ["l2tp"] + [key for key in cores if key != "l2tp"]

        async def snapshot_of(core_key: str):
            driver = registry.get(core_key)
            if core_key == "l2tp":
                await self._drop_linked_l2tp_billing(driver)
            return core_key, await maybe_await(driver.usage_snapshot())

        sampled = await gather_independent(
            *(snapshot_of(core_key) for core_key in cores),
            return_exceptions=True,
        )

        samples: list[dict[str, Any]] = []
        for item in sampled:
            if isinstance(item, Exception):
                log.exception("traffic sample failed: %s", item)
                continue
            core_key, snapshot = item
            try:
                inbounds = snapshot.inbounds
            except Exception:
                log.exception("traffic sample failed core=%s", core_key)
                continue

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

        sampled_at = datetime.now(timezone.utc).isoformat()
        stored = await self._commit_samples(samples, sampled_at)
        stats.update(stored)
        return stats

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

    async def _commit_samples(self, samples: list[dict[str, Any]], sampled_at: str) -> dict[str, int]:
        def plan(acks: dict, pending: dict) -> dict[str, Any]:
            return self._plan_sample(samples, acks, pending, sampled_at)

        return await self.store.apply_traffic_sample(plan)

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
        pending_upserts: list[dict[str, Any]] = []
        pending_deletes: list[tuple[str, str]] = []
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
            row = {
                "delta_incoming": delta_incoming,
                "delta_outgoing": delta_outgoing,
                "current_incoming": current_incoming,
                "current_outgoing": current_outgoing,
            }
            pending[(core, key)] = row
            pending_upserts.append({"core": core, "client_key": key, **row})

        def delete_pending(core: str, key: str) -> None:
            if (core, key) not in pending:
                return
            del pending[(core, key)]
            pending_deletes.append((core, key))

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
            "pending_upserts": pending_upserts,
            "pending_deletes": pending_deletes,
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
        ack = acks.get((core, client_key_label))
        if ack is None:
            # First sight anchors the cumulative counters. Bytes already queued
            # under this key stay billable; the cumulative total is not queued.
            set_ack(
                core,
                client_key_label,
                current_incoming - preserved_in,
                current_outgoing - preserved_out,
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
        if current_incoming < ack_in or current_outgoing < ack_out:
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
            # A direction that fell is a new counter epoch: keep the bytes
            # already queued and anchor that direction. A direction that did
            # not fall keeps its normal delta, including growth in this sample.
            # Already-acked cumulative history is not queued again.
            bill_in = preserved_in if current_incoming < ack_in else current_incoming - ack_in
            bill_out = preserved_out if current_outgoing < ack_out else current_outgoing - ack_out
            set_ack(
                core,
                client_key_label,
                current_incoming - bill_in,
                current_outgoing - bill_out,
            )
            if bill_in > 0 or bill_out > 0:
                set_pending(
                    core,
                    client_key_label,
                    bill_in,
                    bill_out,
                    current_incoming,
                    current_outgoing,
                )
            else:
                delete_pending(core, client_key_label)
            return "regressed"

        delta_in = current_incoming - ack_in
        delta_out = current_outgoing - ack_out
        if delta_in > 0 or delta_out > 0:
            set_pending(
                core,
                client_key_label,
                delta_in,
                delta_out,
                current_incoming,
                current_outgoing,
            )
            return "pending"

        delete_pending(core, client_key_label)
        return "unchanged"

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

    async def pending_payload(self) -> dict[str, Any]:
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

        self._fetch_snapshot = snapshot

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
        self._fetch_snapshot = {}

        if acked:
            log.info("traffic ack applied clients=%s", acked)

        return acked

    async def ack_clients(self, client_keys: list[str]) -> tuple[list[str], list[str]]:
        """Ack the panel node_id keys the panel says it has billed."""
        await self._load_persisted_aliases()
        requested = []
        seen: set[str] = set()
        for raw in client_keys:
            label = str(raw or "").strip()
            if not label or label in seen:
                continue
            seen.add(label)
            requested.append(label)

        rows_by_key: dict[str, list[dict[str, Any]]] = {}
        for row in await self.store.list_traffic_pending():
            label = str(row["client_key"])
            rows_by_key.setdefault(label, []).append(row)

        acked: list[str] = []
        not_found: list[str] = []
        to_ack: list[dict[str, Any]] = []

        for label in requested:
            canonical = self._canonical_key(label)
            rows = (
                self._fetch_snapshot.get(label)
                or self._fetch_snapshot.get(canonical)
                or rows_by_key.get(label)
                or rows_by_key.get(canonical)
                or []
            )
            if not rows:
                not_found.append(label)
                continue

            to_ack.extend(rows)
            published = self._public_client_key(str(rows[0].get("client_key") or "")) or self._public_client_key(label)
            if published and published not in acked:
                acked.append(published)
            log.info("traffic ack client=%s rows=%s", published or label, len(rows))

        await self.store.ack_traffic_rows(to_ack)
        return acked, not_found

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
