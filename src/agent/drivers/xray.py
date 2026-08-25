from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import uuid
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from agent.audit import AuditLog
from agent.config import AgentSettings, XraySettings
from agent.db import Store
from agent.drivers.base import CoreDriver
from agent.drivers.xray_http import XrayHttpClient
from agent.errors import AgentError
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support import normalize_xray_client, record_is_enabled, xray_protocol_user
from agent.support.config_validate import (
    validate_xray_config,
    validate_xray_config_mutation,
    validate_xray_inbound,
)
from agent.support.xray_console import (
    MANAGED_SECTIONS,
    log_file_path,
    redact_secrets,
    restore_redacted_secrets,
    routing_without_rules,
    tail_file,
)
from agent.support.process import service_is_active
from agent.xray_service import api_base_from_config, xray_auth_from_config

_TAG_RE = re.compile(r"^inbound-(.+)$")
_XRAY_UNIT = "xray"
_CLIENT_BATCH_MAX = 200


class XrayDriver(CoreDriver):
    """
    Xray driver via customized HTTP API.
    Formats/templates stay on the bot; agent applies full inbound/client JSON.
    """

    key = "xray"
    label = "Xray"

    def __init__(
        self,
        settings: AgentSettings,
        audit: AuditLog,
        store: Store,
        client: XrayHttpClient | None = None,
    ):
        self.settings = settings
        self.audit = audit
        self.store = store
        self._client_override = client
        self._client: XrayHttpClient | None = None
        self._client_key: tuple[str, str, str] | None = None
        self._inbound_locks: dict[str, Lock] = {}
        self._inbound_locks_guard = Lock()

    def _resolved_xray_settings(self) -> XraySettings:
        base = self.settings.xray
        config_path = Path(base.config)
        api_base = api_base_from_config(config_path, base.api_base)
        username, password = xray_auth_from_config(config_path, base.username, base.password)
        return XraySettings(
            api_base=api_base,
            username=username,
            password=password,
            binary=base.binary,
            config=base.config,
            timeout=base.timeout,
            connect_timeout=base.connect_timeout,
        )

    @property
    def client(self) -> XrayHttpClient:
        if self._client_override is not None:
            return self._client_override

        resolved = self._resolved_xray_settings()
        key = (resolved.api_base, resolved.username, resolved.password)
        if self._client is None or self._client_key != key:
            if self._client is not None:
                self._client.close()
            self._client = XrayHttpClient(resolved)
            self._client_key = key
        return self._client

    def _reset_client(self) -> None:
        if self._client_override is not None:
            return
        if self._client is not None:
            self._client.close()
        self._client = None
        self._client_key = None

    def _ensure_api_ready(self) -> None:
        try:
            self.client.system()
            return
        except AgentError:
            pass

        from agent.xray_service import (
            ensure_xray_httpapi_config,
            ensure_xray_runtime,
            restart_xray_service,
            wait_xray_http_api,
        )

        base = self.settings.xray
        config_path = Path(base.config)
        changed = ensure_xray_httpapi_config(
            config_path,
            api_base=base.api_base,
            username=base.username,
            password=base.password,
        )
        self._reset_client()
        resolved = self._resolved_xray_settings()

        if changed:
            if service_is_active(_XRAY_UNIT):
                restart_xray_service(
                    binary=base.binary,
                    config_path=base.config,
                    api_base=base.api_base,
                    username=base.username,
                    password=base.password,
                )
            else:
                ensure_xray_runtime(
                    binary=base.binary,
                    config_path=base.config,
                    api_base=base.api_base,
                    username=base.username,
                    password=base.password,
                    start=True,
                )
        else:
            try:
                wait_xray_http_api(
                    api_base=resolved.api_base,
                    username=resolved.username,
                    password=resolved.password,
                    attempts=4,
                )
            except AgentError:
                if service_is_active(_XRAY_UNIT):
                    restart_xray_service(
                        binary=base.binary,
                        config_path=base.config,
                        api_base=base.api_base,
                        username=base.username,
                        password=base.password,
                    )
                else:
                    ensure_xray_runtime(
                        binary=base.binary,
                        config_path=base.config,
                        api_base=base.api_base,
                        username=base.username,
                        password=base.password,
                        start=True,
                    )

        self._reset_client()
        self.client.system()

    def capabilities(self) -> list[str]:
        return [
            "inbounds",
            "protocol_switch",
            "online_clients",
            "client_traffic",
            "ip_logs",
            "backup_restore",
            "config_file",
            "x25519",
            "source_ip_block",
            "routing_rules",
            "routing_replace",
            "clients_batch",
            "inbound_preserve_clients",
            "outbounds",
            "xray_console",
            "xray_logs",
        ]

    def installed(self) -> bool:
        return Path(self.settings.xray.binary).is_file() or shutil.which("xray") is not None

    def _api(self) -> XrayHttpClient:
        self._ensure_api_ready()
        return self.client

    def running(self) -> bool:
        if not self.installed():
            return False
        try:
            self.client.system()
            return True
        except AgentError:
            return False

    def version(self) -> str | None:
        binary = self._binary()
        if not binary:
            return None
        try:
            result = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5, check=False)
            return (result.stdout or result.stderr).strip().split("\n")[0] or None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def install(self) -> dict[str, Any]:
        from agent.ops import install_xray

        return install_xray()

    def enable(self) -> dict[str, Any]:
        from agent.ops import install_xray
        from agent.xray_service import binary_has_httpapi, ensure_xray_runtime

        xray = self.settings.xray
        binary = self._binary()
        if not binary or not binary_has_httpapi(binary):
            install_xray(force=True)

        return ensure_xray_runtime(
            binary=xray.binary,
            config_path=xray.config,
            api_base=xray.api_base,
            username=xray.username,
            password=xray.password,
            start=True,
        )

    def disable(self) -> dict[str, Any]:
        from agent.xray_service import stop_xray_service

        return stop_xray_service()

    def restart(self) -> dict[str, Any]:
        from agent.xray_service import restart_xray_service

        xray = self.settings.xray
        return restart_xray_service(
            binary=xray.binary,
            config_path=xray.config,
            api_base=xray.api_base,
            username=xray.username,
            password=xray.password,
        )

    def inbound_tag(self, inbound_id: int | str) -> str:
        if isinstance(inbound_id, str) and inbound_id.startswith("inbound-"):
            return inbound_id
        return f"inbound-{inbound_id}"

    def id_from_tag(self, tag: str) -> int | str | None:
        match = _TAG_RE.match(tag)
        if not match:
            return None
        value = match.group(1)
        return int(value) if value.isdigit() else value

    def _binary(self) -> str | None:
        if Path(self.settings.xray.binary).is_file():
            return self.settings.xray.binary
        return shutil.which("xray")

    def _validate_config_mutation(
        self,
        mutate: Callable[[dict[str, Any]], None],
        *,
        inbound: dict[str, Any] | None = None,
    ) -> None:
        if inbound is not None:
            validate_xray_inbound(inbound)

        binary = self._binary()
        if not binary:
            return

        config_path = Path(self.settings.xray.config)
        if not config_path.is_file():
            return

        validate_xray_config_mutation(binary, config_path, mutate)

    def _replace_inbound_in_config(self, config: dict[str, Any], inbound: dict[str, Any]) -> None:
        tag = str(inbound.get("tag") or "")
        inbounds = config.setdefault("inbounds", [])
        for idx, row in enumerate(inbounds):
            if str(row.get("tag")) == tag:
                inbounds[idx] = inbound
                return
        inbounds.append(inbound)

    def _merge_client_in_config(self, config: dict[str, Any], tag: str, client: dict[str, Any]) -> None:
        self._merge_clients_in_config(config, tag, [client])

    def _merge_clients_in_config(self, config: dict[str, Any], tag: str, clients: list[dict[str, Any]]) -> None:
        for row in config.setdefault("inbounds", []):
            if str(row.get("tag")) != tag:
                continue
            settings = row.setdefault("settings", {})
            existing = list(settings.get("clients") or settings.get("users") or [])
            by_key: dict[str, int] = {}
            for idx, current in enumerate(existing):
                email = str(current.get("email") or "").strip()
                cid = str(current.get("id") or "").strip()
                if email:
                    by_key[f"e:{email}"] = idx
                if cid:
                    by_key[f"i:{cid}"] = idx
            for client in clients:
                email = str(client.get("email") or "").strip()
                cid = str(client.get("id") or "").strip()
                idx = by_key.get(f"e:{email}") if email else None
                if idx is None and cid:
                    idx = by_key.get(f"i:{cid}")
                if idx is None:
                    existing.append(client)
                    idx = len(existing) - 1
                else:
                    existing[idx] = client
                if email:
                    by_key[f"e:{email}"] = idx
                if cid:
                    by_key[f"i:{cid}"] = idx
            settings["clients"] = existing
            if str(row.get("protocol") or "").lower() == "vless":
                settings["users"] = existing
                settings.setdefault("decryption", "none")
            if str(row.get("protocol") or "").lower() in {"shadowsocks", "ss"}:
                method = str(settings.get("method") or "").strip()
                if method == "":
                    if "method" in settings:
                        settings.pop("method", None)
                    if str(settings.get("password") or "").strip() == "":
                        settings.pop("password", None)
                settings.setdefault("network", "tcp,udp")
            return
        raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{tag}] not found in Xray config", 404)

    def _protocol_of(self, inbound: dict[str, Any]) -> str:
        return str(inbound.get("protocol") or "vless").strip().lower()

    def _inbound_lock(self, tag: str) -> Lock:
        with self._inbound_locks_guard:
            lock = self._inbound_locks.get(tag)
            if lock is None:
                lock = Lock()
                self._inbound_locks[tag] = lock
            return lock

    @staticmethod
    def _clients_of(inbound: dict[str, Any]) -> list[dict[str, Any]]:
        settings = inbound.get("settings") or {}
        rows = settings.get("clients") or settings.get("users") or []
        return [row for row in rows if isinstance(row, dict)]

    @classmethod
    def _clients_count(cls, inbound: dict[str, Any]) -> int:
        return len(cls._clients_of(inbound))

    def _inbound_summary(self, inbound: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": inbound.get("id"),
            "tag": inbound.get("tag"),
            "port": inbound.get("port"),
            "protocol": inbound.get("protocol"),
            "clients_count": self._clients_count(inbound),
        }

    @staticmethod
    def _strip_client_lists(settings: dict[str, Any] | None) -> dict[str, Any]:
        cleaned = dict(settings or {})
        cleaned.pop("clients", None)
        cleaned.pop("users", None)
        return cleaned

    def _apply_inbound_patch(
        self,
        existing: dict[str, Any],
        payload: dict[str, Any],
        *,
        preserve_clients: bool,
        reset_clients: bool = False,
    ) -> dict[str, Any]:
        """Merge inbound fields; keep existing clients unless explicitly replaced/reset."""
        inbound = deepcopy(existing)
        for key, value in payload.items():
            if key in {"id", "tag", "format", "preserve_clients", "reset_clients", "clients"}:
                continue
            if key == "settings" and isinstance(value, dict):
                continue
            inbound[key] = deepcopy(value)

        inbound["id"] = existing.get("id")
        inbound["tag"] = existing.get("tag") or inbound.get("tag")
        inbound.setdefault("listen", existing.get("listen", "0.0.0.0"))
        inbound.setdefault("streamSettings", existing.get("streamSettings") or {})
        inbound.setdefault("sniffing", existing.get("sniffing") or {})

        existing_clients = self._clients_of(existing)
        incoming_settings = payload.get("settings") if isinstance(payload.get("settings"), dict) else None
        settings = deepcopy(inbound.get("settings") or {})
        if incoming_settings is not None:
            settings.update(self._strip_client_lists(incoming_settings))
            if reset_clients:
                settings["clients"] = [
                    normalize_xray_client(c) for c in (incoming_settings.get("clients") or incoming_settings.get("users") or [])
                ]
            elif "clients" in incoming_settings or "users" in incoming_settings:
                if preserve_clients:
                    settings["clients"] = [normalize_xray_client(c) for c in existing_clients]
                else:
                    settings["clients"] = [
                        normalize_xray_client(c)
                        for c in (incoming_settings.get("clients") or incoming_settings.get("users") or [])
                    ]
            elif preserve_clients:
                settings["clients"] = [normalize_xray_client(c) for c in existing_clients]
        elif preserve_clients or not reset_clients:
            settings["clients"] = [normalize_xray_client(c) for c in existing_clients]
        inbound["settings"] = settings
        return inbound

    def _edit_inbound_preserving(self, inbound: dict[str, Any], *, preserve_clients: bool) -> None:
        api_payload = self._wire_inbound(inbound)
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        if preserve_clients:
            # Xray-core preserve_clients merges runtime/disk users; omit client lists so
            # format updates stay fast even with thousands of clients.
            slim = deepcopy(api_payload)
            settings = dict(slim.get("settings") or {})
            settings.pop("clients", None)
            settings.pop("users", None)
            slim["settings"] = settings
            self._api().edit_inbounds([slim], preserve_clients=True)
            return
        self._api().edit_inbounds([api_payload], preserve_clients=False)

    def _wire_clients(self, inbound: dict[str, Any], clients: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        protocol = self._protocol_of(inbound)
        settings = inbound.get("settings") or {}
        rows = clients if clients is not None else settings.get("clients") or settings.get("users") or []
        return [xray_protocol_user(protocol, client) for client in rows]

    def _wire_inbound(self, inbound: dict[str, Any]) -> dict[str, Any]:
        payload = deepcopy(inbound)
        payload.pop("id", None)
        settings = payload.setdefault("settings", {})
        native = self._wire_clients(payload)
        settings["clients"] = native
        protocol = self._protocol_of(payload)
        if protocol == "vless":
            settings.setdefault("decryption", "none")
            settings["users"] = native
        if protocol in {"shadowsocks", "ss"}:
            method = str(settings.get("method") or "").strip()
            clients = settings.get("clients") or settings.get("users") or []
            if method == "":
                if "method" in settings:
                    # Blank method key breaks Xray; AEAD multi-user omits it.
                    if clients:
                        settings.pop("method", None)
                        if str(settings.get("password") or "").strip() == "":
                            settings.pop("password", None)
                    else:
                        settings["method"] = "chacha20-ietf-poly1305"
            settings.setdefault("network", "tcp,udp")
        return payload

    def _normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        inbound = deepcopy(row)
        tag = str(inbound.get("tag") or "")
        inbound_id = self.id_from_tag(tag)
        if inbound_id is not None:
            inbound["id"] = inbound_id
        elif "id" not in inbound:
            inbound["id"] = tag
        inbound.setdefault("settings", {})
        inbound["settings"]["clients"] = [
            normalize_xray_client(client) for client in inbound["settings"].get("clients") or inbound["settings"].get("users") or []
        ]
        return inbound

    def list_inbounds(self) -> list[dict[str, Any]]:
        return [self._normalize(row) for row in self._api().list_inbounds()]

    def get_inbound(self, inbound_id: int | str) -> dict[str, Any]:
        tag = self.inbound_tag(inbound_id)
        for inbound in self.list_inbounds():
            if inbound.get("tag") == tag or str(inbound.get("id")) == str(inbound_id):
                return inbound
        raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{inbound_id}] not found", 404)

    def create_inbound(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload = {
            k: v
            for k, v in payload.items()
            if k not in {"format", "preserve_clients", "reset_clients"}
        }
        if not payload.get("protocol"):
            raise AgentError("VALIDATION_ERROR", "protocol is required; send full inbound config from the client")
        if not payload.get("port"):
            raise AgentError("VALIDATION_ERROR", "port is required")

        inbound_id = payload.get("id")
        if inbound_id is None:
            existing_ids: list[int] = []
            for row in self.list_inbounds():
                try:
                    existing_ids.append(int(row.get("id", 0)))
                except (TypeError, ValueError):
                    continue
            inbound_id = max(existing_ids + [0]) + 1

        inbound = deepcopy(payload)
        inbound["id"] = inbound_id
        inbound["tag"] = inbound.get("tag") or self.inbound_tag(inbound_id)
        inbound.setdefault("listen", "0.0.0.0")
        inbound.setdefault("settings", {})
        clients = [normalize_xray_client(c) for c in inbound["settings"].get("clients") or []]
        inbound["settings"]["clients"] = clients
        inbound.setdefault("streamSettings", {})
        inbound.setdefault("sniffing", {})

        api_payload = self._wire_inbound(inbound)
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        self._api().add_inbounds([api_payload])
        self.audit.record("create", f"xray/inbound/{inbound_id}")
        return self.get_inbound(inbound_id)

    def update_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_inbound(inbound_id)
        tag = str(existing.get("tag") or self.inbound_tag(inbound_id))
        preserve_clients = bool(payload.get("preserve_clients", True))
        reset_clients = bool(payload.get("reset_clients", False))
        if reset_clients:
            preserve_clients = False

        with self._inbound_lock(tag):
            existing = self.get_inbound(inbound_id)
            inbound = self._apply_inbound_patch(
                existing,
                payload,
                preserve_clients=preserve_clients,
                reset_clients=reset_clients,
            )
            self._edit_inbound_preserving(inbound, preserve_clients=preserve_clients)
            self.audit.record("update", f"xray/inbound/{inbound_id}")
            return self.get_inbound(inbound_id)

    def refresh_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        """Rebuild protocol/stream for an inbound without delete+create when possible."""
        existing = self.get_inbound(inbound_id)
        tag = str(existing.get("tag") or self.inbound_tag(inbound_id))
        reset_clients = bool(payload.pop("reset_clients", False))
        preserve_clients = not reset_clients
        payload = {k: v for k, v in payload.items() if k != "format"}
        payload.setdefault("port", existing.get("port"))

        with self._inbound_lock(tag):
            existing = self.get_inbound(inbound_id)
            inbound = self._apply_inbound_patch(
                existing,
                payload,
                preserve_clients=preserve_clients,
                reset_clients=reset_clients,
            )
            # Prefer in-place edit so clients stay attached and we avoid remove+add churn.
            self._edit_inbound_preserving(inbound, preserve_clients=preserve_clients)
            self.audit.record("update", f"xray/inbound/{inbound_id}/refresh")
            return self.get_inbound(inbound_id)

    def patch_inbound_settings(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update port/stream/sniffing/settings without rewriting client lists."""
        payload = dict(payload or {})
        payload["preserve_clients"] = True
        payload.pop("reset_clients", None)
        started = time.perf_counter()
        inbound = self.update_inbound(inbound_id, payload)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        summary = self._inbound_summary(inbound)
        self.audit.record("update", f"xray/inbound/{inbound_id}/settings", detail=f"ms={elapsed_ms};clients={summary.get('clients_count')}")
        return summary

    def delete_inbound(self, inbound_id: int | str) -> bool:
        inbound = self.get_inbound(inbound_id)
        self._api().remove_inbounds([str(inbound.get("tag"))])
        self.audit.record("delete", f"xray/inbound/{inbound_id}")
        return True

    def _find_client(self, inbound: dict[str, Any], client_key: str) -> dict[str, Any] | None:
        for client in self._clients_of(inbound):
            if str(client.get("id")) == client_key or str(client.get("email")) == client_key:
                return client
        return None

    def _index_clients(self, inbound: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        by_email: dict[str, dict[str, Any]] = {}
        by_id: dict[str, dict[str, Any]] = {}
        for client in self._clients_of(inbound):
            email = str(client.get("email") or "").strip()
            cid = str(client.get("id") or "").strip()
            if email:
                by_email[email] = client
            if cid:
                by_id[cid] = client
        return by_email, by_id

    def add_client(self, inbound_id: int | str, client: dict[str, Any]) -> dict[str, Any]:
        result = self.batch_clients(inbound_id, [client], mode="upsert")
        if result.get("failed"):
            errors = result.get("errors") or []
            message = errors[0].get("message") if errors else "client upsert failed"
            raise AgentError("VALIDATION_ERROR", str(message), 422)
        rows = result.get("clients") or []
        return rows[0] if rows else normalize_xray_client(client)

    def batch_clients(
        self,
        inbound_id: int | str,
        clients: list[dict[str, Any]],
        *,
        mode: str = "upsert",
    ) -> dict[str, Any]:
        mode_key = str(mode or "upsert").strip().lower()
        if mode_key not in {"upsert", "add", "update"}:
            raise AgentError("VALIDATION_ERROR", "mode must be upsert|add|update", 422)
        if len(clients) > _CLIENT_BATCH_MAX:
            raise AgentError(
                "VALIDATION_ERROR",
                f"client batch limit is {_CLIENT_BATCH_MAX} per request",
                413,
            )

        inbound = self.get_inbound(inbound_id)
        inbound = self._ensure_shadowsocks_method(inbound)
        tag = str(inbound["tag"])
        protocol = self._protocol_of(inbound)
        started = time.perf_counter()
        succeeded = 0
        failed = 0
        errors: list[dict[str, str]] = []
        applied: list[dict[str, Any]] = []

        with self._inbound_lock(tag):
            inbound = self.get_inbound(inbound_id)
            inbound = self._ensure_shadowsocks_method(inbound)
            by_email, by_id = self._index_clients(inbound)

            to_add: list[dict[str, Any]] = []
            to_edit: list[dict[str, Any]] = []
            add_meta: list[dict[str, Any]] = []
            edit_meta: list[dict[str, Any]] = []

            for raw in clients:
                if not isinstance(raw, dict):
                    failed += 1
                    errors.append({"email": "", "message": "client must be an object"})
                    continue
                try:
                    client = normalize_xray_client(raw)
                    client.setdefault("id", str(uuid.uuid4()))
                    if not client.get("email"):
                        client["email"] = str(client["id"])[:8]
                    email = str(client.get("email") or "").strip()
                    cid = str(client.get("id") or "").strip()
                    existing = by_email.get(email) if email else None
                    if existing is None and cid:
                        existing = by_id.get(cid)

                    if mode_key == "add" and existing is not None:
                        failed += 1
                        errors.append({"email": email, "message": "client already exists"})
                        continue
                    if mode_key == "update" and existing is None:
                        failed += 1
                        errors.append({"email": email, "message": "client not found"})
                        continue

                    if not record_is_enabled(client):
                        if existing is not None:
                            try:
                                self._api().remove_users(tag, [str(existing.get("email") or email)])
                                succeeded += 1
                                applied.append(client)
                            except AgentError as exc:
                                failed += 1
                                errors.append({"email": email, "message": exc.message})
                        else:
                            succeeded += 1
                            applied.append(client)
                        continue

                    native = xray_protocol_user(protocol, client)
                    if existing is not None:
                        to_edit.append(native)
                        edit_meta.append(client)
                    else:
                        to_add.append(native)
                        add_meta.append(client)
                except Exception as exc:  # noqa: BLE001 — partial success per row
                    failed += 1
                    errors.append(
                        {
                            "email": str((raw or {}).get("email") or ""),
                            "message": f"{type(exc).__name__}: {exc}",
                        }
                    )

            def _flush(op: str, rows: list[dict[str, Any]], meta: list[dict[str, Any]]) -> None:
                nonlocal succeeded, failed
                if not rows:
                    return
                try:
                    self._validate_config_mutation(
                        lambda cfg, _rows=rows: self._merge_clients_in_config(cfg, tag, _rows),
                    )
                    if op == "add":
                        result = self._api().add_users(
                            tag,
                            rows,
                            protocol=protocol,
                            inbound_settings=inbound.get("settings"),
                        )
                    elif op == "upsert":
                        result = self._api().upsert_users(
                            tag,
                            rows,
                            protocol=protocol,
                            inbound_settings=inbound.get("settings"),
                        )
                    else:
                        result = self._api().edit_users(
                            tag,
                            rows,
                            protocol=protocol,
                            inbound_settings=inbound.get("settings"),
                        )
                    if isinstance(result, dict) and ("failed" in result or "errors" in result):
                        batch_ok = int(result.get("succeeded") or 0)
                        batch_fail = int(result.get("failed") or 0)
                        succeeded += batch_ok
                        failed += batch_fail
                        for err in result.get("errors") or []:
                            if isinstance(err, dict):
                                errors.append(
                                    {
                                        "email": str(err.get("email") or ""),
                                        "message": str(err.get("message") or "failed"),
                                    }
                                )
                        if batch_ok:
                            # Best-effort: keep metas whose email is not in error list.
                            failed_emails = {
                                str(err.get("email") or "")
                                for err in (result.get("errors") or [])
                                if isinstance(err, dict)
                            }
                            applied.extend(
                                [row for row in meta if str(row.get("email") or "") not in failed_emails]
                            )
                        return
                    succeeded += len(meta)
                    applied.extend(meta)
                except AgentError as exc:
                    if exc.status == 413:
                        failed += len(meta)
                        for client in meta:
                            errors.append({"email": str(client.get("email") or ""), "message": exc.message})
                        return
                    # Fall back to per-user so one bad row does not fail the chunk.
                    for row, client in zip(rows, meta):
                        email = str(client.get("email") or "")
                        try:
                            self._validate_config_mutation(
                                lambda cfg, _row=row: self._merge_client_in_config(cfg, tag, _row),
                            )
                            if op == "add":
                                self._api().add_users(
                                    tag,
                                    [row],
                                    protocol=protocol,
                                    inbound_settings=inbound.get("settings"),
                                )
                            elif op == "upsert":
                                self._api().upsert_users(
                                    tag,
                                    [row],
                                    protocol=protocol,
                                    inbound_settings=inbound.get("settings"),
                                )
                            else:
                                self._api().edit_users(
                                    tag,
                                    [row],
                                    protocol=protocol,
                                    inbound_settings=inbound.get("settings"),
                                )
                            succeeded += 1
                            applied.append(client)
                        except AgentError as row_exc:
                            failed += 1
                            errors.append({"email": email, "message": row_exc.message})
                        except Exception as row_exc:  # noqa: BLE001
                            failed += 1
                            errors.append({"email": email, "message": f"{type(row_exc).__name__}: {row_exc}"})
                except Exception as exc:  # noqa: BLE001
                    for client in meta:
                        failed += 1
                        errors.append(
                            {
                                "email": str(client.get("email") or ""),
                                "message": f"{type(exc).__name__}: {exc}",
                            }
                        )

            if mode_key == "upsert":
                _flush("upsert", to_add + to_edit, add_meta + edit_meta)
            else:
                _flush("edit", to_edit, edit_meta)
                _flush("add", to_add, add_meta)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self.audit.record(
            "update",
            f"xray/inbound/{inbound_id}/clients/batch",
            f"mode={mode_key} succeeded={succeeded} failed={failed} ms={elapsed_ms}",
        )
        return {
            "ok": failed == 0,
            "succeeded": succeeded,
            "failed": failed,
            "errors": errors,
            "clients": applied,
            "ms": elapsed_ms,
        }

    def batch_remove_clients(
        self,
        inbound_id: int | str,
        *,
        emails: list[str] | None = None,
        ids: list[str] | None = None,
    ) -> dict[str, Any]:
        email_keys = [str(e).strip() for e in (emails or []) if str(e).strip()]
        id_keys = [str(i).strip() for i in (ids or []) if str(i).strip()]
        if not email_keys and not id_keys:
            raise AgentError("VALIDATION_ERROR", "emails or ids required", 422)
        if len(email_keys) + len(id_keys) > _CLIENT_BATCH_MAX:
            raise AgentError(
                "VALIDATION_ERROR",
                f"client batch limit is {_CLIENT_BATCH_MAX} per request",
                413,
            )

        inbound = self.get_inbound(inbound_id)
        tag = str(inbound["tag"])
        started = time.perf_counter()
        remove_emails: list[str] = []
        errors: list[dict[str, str]] = []
        succeeded = 0
        failed = 0

        with self._inbound_lock(tag):
            inbound = self.get_inbound(inbound_id)
            by_email, by_id = self._index_clients(inbound)
            seen: set[str] = set()
            for email in email_keys:
                row = by_email.get(email)
                if row is None:
                    failed += 1
                    errors.append({"email": email, "message": "client not found"})
                    continue
                target = str(row.get("email") or email)
                if target not in seen:
                    seen.add(target)
                    remove_emails.append(target)
            for cid in id_keys:
                row = by_id.get(cid)
                if row is None:
                    failed += 1
                    errors.append({"email": cid, "message": "client not found"})
                    continue
                target = str(row.get("email") or cid)
                if target not in seen:
                    seen.add(target)
                    remove_emails.append(target)

            if remove_emails:
                try:
                    self._api().remove_users(tag, remove_emails)
                    succeeded = len(remove_emails)
                except AgentError as exc:
                    for email in remove_emails:
                        try:
                            self._api().remove_users(tag, [email])
                            succeeded += 1
                        except AgentError as row_exc:
                            failed += 1
                            errors.append({"email": email, "message": row_exc.message})
                    if succeeded == 0 and not errors:
                        raise exc

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self.audit.record(
            "delete",
            f"xray/inbound/{inbound_id}/clients/batch",
            f"succeeded={succeeded} failed={failed} ms={elapsed_ms}",
        )
        return {
            "ok": failed == 0,
            "succeeded": succeeded,
            "failed": failed,
            "errors": errors,
            "ms": elapsed_ms,
        }

    def _ensure_shadowsocks_method(self, inbound: dict[str, Any]) -> dict[str, Any]:
        """Repair blank Shadowsocks method keys left by legacy broken inbounds."""
        if self._protocol_of(inbound) not in {"shadowsocks", "ss"}:
            return inbound

        settings = inbound.setdefault("settings", {})
        method = str(settings.get("method") or "").strip()
        clients = settings.get("clients") or settings.get("users") or []
        if method != "":
            return inbound
        if "method" not in settings:
            return inbound

        if clients:
            settings.pop("method", None)
            if str(settings.get("password") or "").strip() == "":
                settings.pop("password", None)
        else:
            settings["method"] = "chacha20-ietf-poly1305"

        settings.setdefault("network", "tcp,udp")
        api_payload = self._wire_inbound(inbound)
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        self._api().edit_inbounds([api_payload], preserve_clients=True)
        inbound_id = inbound.get("id") or self.id_from_tag(str(inbound.get("tag") or ""))
        if inbound_id is None:
            return inbound
        return self.get_inbound(inbound_id)

    def update_client(self, inbound_id: int | str, client_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        inbound = self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        merged = normalize_xray_client({**current, **payload})
        result = self.batch_clients(inbound_id, [merged], mode="update")
        if result.get("failed"):
            errors = result.get("errors") or []
            message = errors[0].get("message") if errors else "client update failed"
            raise AgentError("VALIDATION_ERROR", str(message), 422)
        rows = result.get("clients") or []
        return rows[0] if rows else merged

    def delete_client(self, inbound_id: int | str, client_key: str) -> bool:
        inbound = self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        email = str(current.get("email") or client_key)
        result = self.batch_remove_clients(inbound_id, emails=[email])
        if result.get("failed") and result.get("succeeded", 0) == 0:
            errors = result.get("errors") or []
            message = errors[0].get("message") if errors else "client delete failed"
            raise AgentError("VALIDATION_ERROR", str(message), 422)
        return True

    def reset_client_traffic(self, inbound_id: int | str, client_key: str) -> dict[str, Any]:
        inbound = self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        email = str(current.get("email") or client_key)
        self._api().reset_user_traffic(email)
        return current

    def client_ips(self, email: str) -> list[str]:
        # Xray reports currently-online IPs, not an accumulating log.
        # Do not hide live addresses after a "clear" — the bot needs them for device lists.
        return self._api().online_ips(email)

    def clear_client_ips(self, email: str) -> bool:
        return True

    def backup(self) -> dict[str, Any]:
        return {
            "inbounds": self.list_inbounds(),
            "outbounds": self._api().list_outbounds(),
            "rules": self._api().list_rules(),
        }

    def restore(self, payload: dict[str, Any]) -> bool:
        desired = list(payload.get("inbounds") or [])
        existing = self.list_inbounds()
        if existing:
            self._api().remove_inbounds([str(i.get("tag")) for i in existing if i.get("tag")])
        cleaned = []
        for row in desired:
            item = deepcopy(row)
            item.pop("id", None)
            settings = item.setdefault("settings", {})
            settings["clients"] = [normalize_xray_client(c) for c in settings.get("clients") or []]
            cleaned.append(self._wire_inbound(item))
        if cleaned:
            self._api().add_inbounds(cleaned)
        if payload.get("outbounds"):
            try:
                self._api().add_outbounds(list(payload["outbounds"]))
            except AgentError:
                pass
        if payload.get("rules"):
            try:
                self._api().add_rules(list(payload["rules"]))
            except AgentError:
                pass
        self.audit.record("restore", "xray")
        return True

    def import_config(self, config: dict[str, Any], path: str | None = None) -> dict[str, Any]:
        binary = self._binary()
        if binary:
            validate_xray_config(binary, config)
        result = self._api().import_config(config, path=path)
        self.audit.record("import", "xray/config")
        return result

    def x25519(self) -> dict[str, str]:
        binary = self._binary()
        if not binary:
            raise AgentError("UNSUPPORTED_CAPABILITY", "xray binary not found for x25519", 400)
        try:
            result = subprocess.run([binary, "x25519"], capture_output=True, text=True, timeout=10, check=False)
            keys: dict[str, str] = {}
            for line in (result.stdout or "").strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    keys[k.strip().lower()] = v.strip()
            if keys:
                return keys
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        raise AgentError("UNSUPPORTED_CAPABILITY", "x25519 generation failed", 400)

    def read_config(self) -> dict[str, Any]:
        path = Path(self.settings.xray.config)
        if not path.is_file():
            raise AgentError("CONFIG_NOT_FOUND", f"Xray config not found: {path}", 404)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentError("VALIDATION_ERROR", f"Invalid Xray config JSON: {exc}", 422) from exc
        if not isinstance(data, dict):
            raise AgentError("VALIDATION_ERROR", "Xray config must be a JSON object", 422)
        return data

    def dumped_config(self) -> dict[str, Any]:
        return redact_secrets(self.read_config())

    def apply_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(config, dict) or not config:
            raise AgentError("VALIDATION_ERROR", "Xray config must be a non-empty object", 422)

        path = Path(self.settings.xray.config)
        current: dict[str, Any] = {}
        if path.is_file():
            try:
                current = self.read_config()
            except AgentError:
                current = {}
        payload = restore_redacted_secrets(config, current)
        if not isinstance(payload, dict):
            raise AgentError("VALIDATION_ERROR", "Xray config must be a JSON object", 422)

        binary = self._binary()
        if binary:
            validate_xray_config(binary, payload)

        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(serialized, encoding="utf-8")
        tmp.replace(path)

        try:
            result = self._api().import_config(payload, path=str(path))
        except AgentError:
            from agent.xray_service import restart_xray_service

            xray = self.settings.xray
            result = restart_xray_service(
                binary=xray.binary,
                config_path=xray.config,
                api_base=xray.api_base,
                username=xray.username,
                password=xray.password,
            )
        self.audit.record("update", "xray/config")
        return result if isinstance(result, dict) else {"ok": True}

    def replace_section(self, section: str, value: Any) -> dict[str, Any]:
        name = str(section or "").strip()
        if name not in MANAGED_SECTIONS:
            raise AgentError("VALIDATION_ERROR", f"Unsupported Xray section [{name}]", 422)
        config = self.read_config()
        if value in (None, {}, []):
            config.pop(name, None)
        elif name == "routing" and isinstance(value, dict):
            current = dict(config.get("routing") or {})
            keep_rules = "rules" not in value
            rules = current.get("rules")
            current.update(value)
            if keep_rules and rules is not None:
                current["rules"] = rules
            config["routing"] = current
        else:
            config[name] = value
        return self.apply_config(config)

    def console(self) -> dict[str, Any]:
        config: dict[str, Any] = {}
        config_error: str | None = None
        try:
            config = self.read_config()
        except AgentError as exc:
            config_error = exc.message

        outbounds: list[dict[str, Any]] = list(config.get("outbounds") or [])
        rules: list[dict[str, Any]] = list((config.get("routing") or {}).get("rules") or [])
        api_ok = False
        api_error: str | None = None
        try:
            outbounds = self.list_outbounds()
            rules = self.list_rules()
            api_ok = True
        except AgentError as exc:
            api_error = exc.message

        inbound_tags = [str(row.get("tag")) for row in (config.get("inbounds") or []) if row.get("tag")]
        outbound_tags = [str(row.get("tag")) for row in outbounds if isinstance(row, dict) and row.get("tag")]

        return {
            "config_path": self.settings.xray.config,
            "config_error": config_error,
            "api_ok": api_ok,
            "api_error": api_error,
            "log": config.get("log") or {},
            "dns": config.get("dns") or {},
            "routing": routing_without_rules(config.get("routing") if isinstance(config.get("routing"), dict) else {}),
            "policy": config.get("policy") or {},
            "reverse": config.get("reverse") or {},
            "observatory": config.get("observatory") or {},
            "burstObservatory": config.get("burstObservatory") or {},
            "stats": config.get("stats") if isinstance(config.get("stats"), dict) else {},
            "metrics": config.get("metrics") or {},
            "transport": config.get("transport") or {},
            "outbounds": outbounds,
            "rules": rules,
            "inbound_tags": inbound_tags,
            "outbound_tags": outbound_tags,
        }

    def tail_logs(self, kind: str = "error", lines: int = 200) -> dict[str, Any]:
        requested = str(kind or "error").strip().lower()
        if requested not in {"error", "access", "all"}:
            requested = "error"
        lines = max(20, min(int(lines or 200), 2000))
        log = {}
        try:
            log = dict(self.read_config().get("log") or {})
        except AgentError:
            log = {}

        paths = {
            "error": log_file_path(log, "error"),
            "access": log_file_path(log, "access"),
        }
        kinds = ("error", "access") if requested == "all" else (requested,)
        files: dict[str, dict[str, Any]] = {}
        for name in kinds:
            path = paths.get(name)
            files[name] = {
                "path": str(path) if path else None,
                "content": tail_file(path, lines) if path else "",
                "missing": path is None or not path.is_file(),
            }

        return {
            "kind": requested,
            "lines": lines,
            "loglevel": log.get("loglevel") or log.get("logLevel") or "",
            "files": files,
        }

    def restart_logger(self) -> dict[str, Any]:
        result = self._api().restart_logger()
        self.audit.record("update", "xray/logger")
        return result if isinstance(result, dict) else {"ok": True}

    def list_outbounds(self) -> list[dict[str, Any]]:
        return self._api().list_outbounds()

    def add_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self._api().add_outbounds(outbounds)

    def edit_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self._api().edit_outbounds(outbounds)

    def remove_outbounds(self, tags: list[str]) -> dict[str, Any]:
        return self._api().remove_outbounds(tags)

    def list_rules(self) -> list[dict[str, Any]]:
        return self._api().list_rules()

    def add_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        return self._api().add_rules(rules)

    def edit_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {"updated": 0}
        for rule in rules:
            result = self._api().edit_rule(rule)
        return result

    def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        return self._api().remove_rules(tags)

    def replace_rules(self, rules: list[dict[str, Any]], routing_extras: dict[str, Any] | None = None) -> dict[str, Any]:
        """Atomically replace routing.rules (native API when available, else config section)."""
        extras = dict(routing_extras or {})
        started = time.perf_counter()
        try:
            result = self._api().replace_rules(list(rules), **extras)
        except AgentError as exc:
            # Older Xray builds lack /api/rules/replace — fall back to config section write.
            if exc.status not in {404, 405, 501}:
                # Also treat "unknown path" style validation as missing endpoint.
                message = (exc.message or "").lower()
                if "not found" not in message and "unknown" not in message and exc.status != 422:
                    raise
            routing = dict(extras)
            routing["rules"] = list(rules)
            result = self.replace_section("routing", routing)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self.audit.record(
            "update",
            "xray/rules/replace",
            f"rules_count={len(rules)} ms={elapsed_ms}",
        )
        return {
            "ok": True,
            "rules_count": len(rules),
            "ms": elapsed_ms,
            "result": result if isinstance(result, dict) else {"ok": True},
        }

    def upsert_rules(
        self,
        *,
        remove_tags: list[str] | None = None,
        add: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        tags = [str(t).strip() for t in (remove_tags or []) if str(t).strip()]
        rows = [row for row in (add or []) if isinstance(row, dict)]
        started = time.perf_counter()
        removed = 0
        if tags:
            self._api().remove_rules(tags)
            removed = len(tags)
        added = 0
        if rows:
            self._api().add_rules(rows, should_append=True)
            added = len(rows)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self.audit.record(
            "update",
            "xray/rules/upsert",
            f"removed={removed} added={added} ms={elapsed_ms}",
        )
        return {"ok": True, "removed": removed, "added": added, "ms": elapsed_ms}

    def block_source_ips(self, source_ips: list[str], **kwargs: Any) -> dict[str, Any]:
        return self._api().block_source_ips(source_ips, **kwargs)

    def usage_snapshot(self) -> UsageSnapshotModel:
        inbounds = self.list_inbounds()
        user_groups = self._api().stats_query_grouped("user>>>", "user")
        inbound_groups = self._api().stats_query_grouped("inbound>>>", "inbound")
        user_traffic = dict(user_groups.get("user") or {})
        inbound_traffic = dict(inbound_groups.get("inbound") or {})

        rows: list[InboundUsageModel] = []
        for inbound in inbounds:
            tag = str(inbound.get("tag") or "")
            counters = dict(inbound_traffic.get(tag) or {})
            clients: list[ClientUsageModel] = []
            for client in inbound.get("settings", {}).get("clients", []):
                email = str(client.get("email") or "")
                traffic = dict(user_traffic.get(email) or {})
                clients.append(
                    ClientUsageModel(
                        id=str(client.get("id") or email),
                        email=email or None,
                        incoming=int(traffic.get("downlink") or 0),
                        outgoing=int(traffic.get("uplink") or 0),
                        inbound_id=inbound.get("id"),
                    )
                )
            rows.append(
                InboundUsageModel(
                    id=inbound.get("id"),
                    tag=tag,
                    incoming=int(counters.get("downlink") or sum(c.incoming for c in clients)),
                    outgoing=int(counters.get("uplink") or sum(c.outgoing for c in clients)),
                    clients=clients,
                )
            )
        return UsageSnapshotModel(inbounds=rows)

    def online_users(self) -> list[str]:
        if not self.running():
            return []
        return self._api().online_users()

    def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import online_traffic_from_snapshot

        try:
            body = self._api().online_traffic()
        except AgentError as exc:
            if exc.status != 404:
                raise
            return online_traffic_from_snapshot(self)

        users = body.get("users") or {}
        if not isinstance(users, dict):
            return online_traffic_from_snapshot(self)
        out: dict[str, dict[str, int]] = {}
        for email, row in users.items():
            if not isinstance(row, dict):
                continue
            entry: dict[str, int] = {}
            for key in ("uplink", "downlink", "sessions"):
                if key in row and row[key] is not None:
                    entry[key] = int(row[key])
            out[str(email)] = entry
        return out
