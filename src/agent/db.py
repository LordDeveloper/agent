from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class Store:
    """Single SQLite database for agent state (inbounds, peers, audit, meta)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    core TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, kind, doc_id)
                );

                CREATE TABLE IF NOT EXISTS meta (
                    core TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (core, key)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS traffic_ack (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    incoming INTEGER NOT NULL DEFAULT 0,
                    outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                );

                CREATE TABLE IF NOT EXISTS traffic_pending (
                    core TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    delta_incoming INTEGER NOT NULL DEFAULT 0,
                    delta_outgoing INTEGER NOT NULL DEFAULT 0,
                    current_incoming INTEGER NOT NULL DEFAULT 0,
                    current_outgoing INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (core, client_key)
                );

                DROP TABLE IF EXISTS core_errors;
                """
            )
            self._conn.commit()

    def list_docs(self, core: str, kind: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM documents WHERE core = ? AND kind = ? ORDER BY doc_id",
                (core, kind),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def get_doc(self, core: str, kind: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                (core, kind, str(doc_id)),
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def put_doc(self, core: str, kind: str, doc_id: str, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO documents (core, kind, doc_id, data, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, kind, doc_id) DO UPDATE SET
                    data = excluded.data,
                    updated_at = datetime('now')
                """,
                (core, kind, str(doc_id), payload),
            )
            self._conn.commit()

    def delete_doc(self, core: str, kind: str, doc_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM documents WHERE core = ? AND kind = ? AND doc_id = ?",
                (core, kind, str(doc_id)),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def replace_docs(self, core: str, kind: str, docs: list[dict[str, Any]], id_key: str = "id") -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM documents WHERE core = ? AND kind = ?",
                (core, kind),
            )
            for doc in docs:
                doc_id = str(doc.get(id_key, ""))
                self._conn.execute(
                    """
                    INSERT INTO documents (core, kind, doc_id, data, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    """,
                    (core, kind, doc_id, json.dumps(doc, ensure_ascii=False)),
                )
            self._conn.commit()

    def get_meta(self, core: str, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE core = ? AND key = ?",
                (core, key),
            ).fetchone()
        if row is None:
            return default
        return json.loads(row["value"])

    def set_meta(self, core: str, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO meta (core, key, value) VALUES (?, ?, ?)
                ON CONFLICT(core, key) DO UPDATE SET value = excluded.value
                """,
                (core, key, json.dumps(value, ensure_ascii=False)),
            )
            self._conn.commit()

    def get_traffic_ack(self, core: str, client_key: str) -> dict[str, int] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT incoming, outgoing FROM traffic_ack
                WHERE core = ? AND client_key = ?
                """,
                (core, client_key),
            ).fetchone()
        if row is None:
            return None
        return {"incoming": int(row["incoming"]), "outgoing": int(row["outgoing"])}

    def set_traffic_ack(
        self,
        core: str,
        client_key: str,
        incoming: int,
        outgoing: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO traffic_ack (core, client_key, incoming, outgoing, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    incoming = excluded.incoming,
                    outgoing = excluded.outgoing,
                    updated_at = datetime('now')
                """,
                (core, client_key, incoming, outgoing),
            )
            self._conn.commit()

    def delete_traffic_ack(self, core: str, client_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM traffic_ack WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            self._conn.commit()

    def upsert_traffic_pending(
        self,
        core: str,
        client_key: str,
        delta_incoming: int,
        delta_outgoing: int,
        current_incoming: int,
        current_outgoing: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO traffic_pending (
                    core, client_key,
                    delta_incoming, delta_outgoing,
                    current_incoming, current_outgoing,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(core, client_key) DO UPDATE SET
                    delta_incoming = excluded.delta_incoming,
                    delta_outgoing = excluded.delta_outgoing,
                    current_incoming = excluded.current_incoming,
                    current_outgoing = excluded.current_outgoing,
                    updated_at = datetime('now')
                """,
                (
                    core,
                    client_key,
                    delta_incoming,
                    delta_outgoing,
                    current_incoming,
                    current_outgoing,
                ),
            )
            self._conn.commit()

    def delete_traffic_pending(self, core: str, client_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM traffic_pending WHERE core = ? AND client_key = ?",
                (core, client_key),
            )
            self._conn.commit()

    def list_traffic_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT core, client_key, delta_incoming, delta_outgoing,
                       current_incoming, current_outgoing, updated_at
                FROM traffic_pending
                ORDER BY core, client_key
                """,
            ).fetchall()
        return [dict(row) for row in rows]

    def count_traffic_pending(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM traffic_pending").fetchone()
        return int(row["c"]) if row else 0

    def audit(self, action: str, resource: str, detail: str = "") -> None:
        from datetime import datetime, timezone

        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (ts, action, resource, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), action, resource, detail),
            )
            self._conn.commit()
