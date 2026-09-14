from __future__ import annotations



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

PEER_CORES = frozenset({"wireguard", "amnezia", "l2tp"})

# Match WireGuardDriver online threshold: ignore idle counter noise as pending.

STALE_PEER_HANDSHAKE_SECONDS = 120





class TrafficService:

    """Samples cumulative client counters and tracks unreported deltas for the panel."""



    def __init__(self, store: Store):

        self.store = store



    def sample_all(self, registry: CoreRegistry) -> dict[str, int]:

        """Refresh pending deltas from live core counters (online not required)."""

        stats = {

            "clients_seen": 0,

            "pending": 0,

            "initialized": 0,

            "regressed": 0,

            "stale_handshake": 0,

            "pending_frozen": 0,

        }



        for core_key in registry.settings.cores():

            try:

                driver = registry.get(core_key)

                if core_key == "l2tp":

                    self._drop_linked_l2tp_billing(driver)

                snapshot = driver.usage_snapshot()

            except Exception:

                log.exception("traffic sample failed core=%s", core_key)

                continue



            for inbound in snapshot.inbounds:

                for client in inbound.clients:

                    label = client_key(client)

                    if not label:

                        continue


                    stats["clients_seen"] += 1

                    self._migrate_legacy_client_key(
                        core_key,
                        label,
                        str(getattr(client, "email", "") or "").strip(),
                        str(getattr(client, "id", "") or "").strip(),
                    )
                    outcome = self._process_sample(
                        core_key,

                        label,

                        int(client.incoming or 0),

                        int(client.outgoing or 0),

                        handshake_at=getattr(client, "handshake_at", None),

                    )

                    stats[outcome] = stats.get(outcome, 0) + 1



        pending = self.store.count_traffic_pending()

        stats["pending"] = pending

        self.store.set_meta(

            AGENT_META_CORE,

            LAST_SAMPLE_META_KEY,

            datetime.now(timezone.utc).isoformat(),

        )

        return stats


    def _migrate_legacy_client_key(
        self,
        core: str,
        canonical_key: str,
        email: str,
        client_id: str,
    ) -> None:
        """Move pre-node_id traffic rows to the canonical client id."""
        if not client_id or not email or client_id == email:
            return

        legacy_pending = self.store.get_traffic_pending(core, email)
        if legacy_pending is not None:
            current_pending = self.store.get_traffic_pending(core, canonical_key)
            if current_pending is None:
                self.store.upsert_traffic_pending(
                    core,
                    canonical_key,
                    int(legacy_pending["delta_incoming"]),
                    int(legacy_pending["delta_outgoing"]),
                    int(legacy_pending["current_incoming"]),
                    int(legacy_pending["current_outgoing"]),
                )
            self.store.delete_traffic_pending(core, email)

        legacy_ack = self.store.get_traffic_ack(core, email)
        if legacy_ack is not None:
            if self.store.get_traffic_ack(core, canonical_key) is None:
                self.store.set_traffic_ack(
                    core,
                    canonical_key,
                    int(legacy_ack["incoming"]),
                    int(legacy_ack["outgoing"]),
                )
            self.store.delete_traffic_ack(core, email)


    def _process_sample(

        self,

        core: str,

        client_key_label: str,

        current_incoming: int,

        current_outgoing: int,

        handshake_at: int | None = None,

    ) -> str:

        ack = self.store.get_traffic_ack(core, client_key_label)



        if ack is None:

            self.store.set_traffic_ack(core, client_key_label, current_incoming, current_outgoing)

            self.store.delete_traffic_pending(core, client_key_label)

            return "initialized"



        ack_in = int(ack["incoming"])

        ack_out = int(ack["outgoing"])



        if current_incoming < ack_in or current_outgoing < ack_out:

            log.warning(

                "traffic counter regression core=%s client=%s ack=(%s,%s) current=(%s,%s)",

                core,

                client_key_label,

                ack_in,

                ack_out,

                current_incoming,

                current_outgoing,

            )

            self.store.set_traffic_ack(core, client_key_label, current_incoming, current_outgoing)

            self.store.delete_traffic_pending(core, client_key_label)

            return "regressed"



        delta_in = current_incoming - ack_in

        delta_out = current_outgoing - ack_out



        if (delta_in > 0 or delta_out > 0) and self._peer_handshake_is_stale(core, handshake_at):

            return self._absorb_stale_peer_delta(

                core,

                client_key_label,

                current_incoming,

                current_outgoing,

            )



        if delta_in > 0 or delta_out > 0:

            self.store.upsert_traffic_pending(

                core,

                client_key_label,

                delta_in,

                delta_out,

                current_incoming,

                current_outgoing,

            )

            return "pending"



        self.store.delete_traffic_pending(core, client_key_label)

        return "unchanged"



    def _peer_handshake_is_stale(self, core: str, handshake_at: int | None) -> bool:

        if core not in PEER_CORES:

            return False



        if handshake_at is None or int(handshake_at) <= 0:

            return True



        return (time.time() - int(handshake_at)) > STALE_PEER_HANDSHAKE_SECONDS



    def _absorb_stale_peer_delta(

        self,

        core: str,

        client_key_label: str,

        current_incoming: int,

        current_outgoing: int,

    ) -> str:

        """

        WireGuard kernel counters can still tick slightly after the handshake ages out.

        Do not grow pending from that noise. Keep any already-queued real pending frozen

        and advance ``current_*`` so a later ack skips the phantom bytes.

        """

        existing = self.store.get_traffic_pending(core, client_key_label)

        if existing is None:

            self.store.set_traffic_ack(core, client_key_label, current_incoming, current_outgoing)

            self.store.delete_traffic_pending(core, client_key_label)

            return "stale_handshake"



        self.store.upsert_traffic_pending(

            core,

            client_key_label,

            int(existing["delta_incoming"]),

            int(existing["delta_outgoing"]),

            current_incoming,

            current_outgoing,

        )

        return "pending_frozen"



    def pending_payload(self) -> dict[str, Any]:

        rows = self.store.list_traffic_pending()

        users: dict[str, dict[str, Any]] = {}

        linked_l2tp = self._linked_l2tp_client_keys()



        for row in rows:

            label = str(row["client_key"])

            # Linked L2TP companions must never contribute to panel pending volume.
            if str(row.get("core") or "") == "l2tp" and label in linked_l2tp:

                continue

            users[label] = {

                "core": row["core"],

                "uplink": int(row["delta_outgoing"]),

                "downlink": int(row["delta_incoming"]),

            }



        return {

            "sampled_at": self.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY),

            "worker_lag_ms": self._worker_lag_ms(),

            "users": users,

        }



    def ack_pending(self) -> int:

        rows = self.store.list_traffic_pending()

        acked = 0



        for row in rows:

            self._ack_pending_row(row)

            acked += 1



        if acked:

            log.info("traffic ack applied clients=%s", acked)



        return acked



    def ack_clients(self, client_keys: list[str]) -> tuple[list[str], list[str]]:

        """Ack only the provided canonical client keys (panel node_id)."""

        requested = []

        seen: set[str] = set()

        for raw in client_keys:

            label = str(raw or "").strip()

            if not label or label in seen:

                continue

            seen.add(label)

            requested.append(label)



        rows_by_key: dict[str, list[dict[str, Any]]] = {}

        for row in self.store.list_traffic_pending():

            label = str(row["client_key"])

            rows_by_key.setdefault(label, []).append(row)



        acked: list[str] = []

        not_found: list[str] = []



        for label in requested:

            rows = rows_by_key.get(label) or []

            if not rows:

                not_found.append(label)

                continue



            for row in rows:

                self._ack_pending_row(row)



            acked.append(label)

            log.info("traffic ack client=%s rows=%s", label, len(rows))



        return acked, not_found



    def _ack_pending_row(self, row: dict[str, Any]) -> None:

        self.store.set_traffic_ack(

            row["core"],

            row["client_key"],

            int(row["current_incoming"]),

            int(row["current_outgoing"]),

        )

        self.store.delete_traffic_pending(row["core"], row["client_key"])



    def _linked_l2tp_client_keys(self) -> set[str]:

        """Canonical ids/emails of L2TP users linked to a WireGuard/Amnezia peer."""

        keys: set[str] = set()

        try:

            docs = self.store.list_docs("l2tp", "server")

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



    def _drop_linked_l2tp_billing(self, driver: Any) -> None:

        """Remove pending/ack rows for companion L2TP users (WG peer owns billing)."""

        try:

            servers = driver.list_servers()

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

                self.reset_client_record("l2tp", user)



    def reset_client(self, core: str, client_key_label: str) -> None:

        """Drop ack/pending rows after panel delete or renew."""

        self.store.delete_traffic_ack(core, client_key_label)

        self.store.delete_traffic_pending(core, client_key_label)



    def reset_client_record(self, core: str, record: dict[str, Any], *extra_labels: str) -> None:

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

                self.reset_client(core, label)



    def _worker_lag_ms(self) -> int | None:

        sampled_at = self.store.get_meta(AGENT_META_CORE, LAST_SAMPLE_META_KEY)

        if not sampled_at:

            return None



        try:

            ts = datetime.fromisoformat(str(sampled_at).replace("Z", "+00:00"))

        except ValueError:

            return None



        if ts.tzinfo is None:

            ts = ts.replace(tzinfo=timezone.utc)



        return max(0, int((datetime.now(timezone.utc) - ts).total_seconds() * 1000))


