from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import aiofiles
import aiofiles.os

from agent.audit import AuditLog
from agent.config import AgentSettings, XraySettings
from agent.db import Store
from agent.drivers.base import CoreDriver
from agent.drivers.xray_http import XrayHttpClient, retain_fresh_online_ips
from agent.errors import AgentError
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support import (
    emails_on_other_inbounds,
    normalize_xray_client,
    record_is_enabled,
    xray_client_rows,
    xray_protocol_user,
)
from agent.support.disable_reason import mark_panel_disabled
from agent.support.quota import apply_quota_meta, quota_meta_from_client
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
from agent.logutil import get_logger
from agent.support.process import run, service_is_active
from agent.support.proxy_protocol_forwarder import (
    stop_forwarders,
    sync_forwarders_from_inbounds,
)
from agent.asyncutil import bounded_gather, gather_independent, maybe_await
from agent.support import aiofs
from agent.xray_service import api_base_from_config, describe_httpapi_guard, xray_auth_from_config

_TAG_RE = re.compile(r"^inbound-(.+)$")
_XRAY_UNIT = "xray"
_CLIENT_BATCH_MAX = 200
# A handful of clients should not wait on a stats dump of every user.
_SMALL_CLIENT_BATCH = 8
# Overlap per-client Xray writes. Wall time stays near one call, not N calls.
_CLIENT_PARALLELISM = 32
_QUOTA_KIND = "client_quota"
_DISABLED_KIND = "xray_disabled_client"
_log = get_logger("xray")


def _is_missing_user_error(exc: AgentError) -> bool:
    message = str(exc.message or "").lower()
    return int(exc.status or 0) == 404 or "not found" in message or "does not exist" in message or "doesn't exist" in message


def _is_inbound_missing_error(exc: AgentError) -> bool:
    message = str(exc.message or "").lower()
    return "inbound" in message and "not found" in message


def clients_already_on_inbound(
    clients: list[dict[str, Any]],
    by_email: dict[str, dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Rows whose email or id is already on this inbound.

    A brand-new client has no Xray counters. Querying stats for it only adds a
    round trip to create/move, which is what makes a single config feel stuck.
    """
    known: list[dict[str, Any]] = []
    for raw in clients:
        if not isinstance(raw, dict):
            continue
        email = str(raw.get("email") or "").strip()
        cid = str(raw.get("id") or "").strip()
        if (email and email in by_email) or (cid and cid in by_id):
            known.append(raw)
    return known


def _is_existing_user_error(exc: AgentError) -> bool:
    message = str(exc.message or "").lower()
    if _is_missing_user_error(exc):
        return False
    return "already" in message or "duplicate" in message or "exist" in message


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
        self._settings_cache: tuple[int | None, XraySettings] | None = None
        self._api_ready_until = 0.0
        self._inbound_locks: dict[str, asyncio.Lock] = {}
        self._config_lock = threading.Lock()
        self._config_cache: tuple[str, int, int, dict[str, Any]] | None = None
        # Quota and the traffic worker both used to dump every user's counters.
        # Share one in-flight query and reuse it until the next traffic sample.
        self._usage_gate: asyncio.Lock | None = None
        self._usage_flight: asyncio.Task | None = None
        self._usage_cache: tuple[float, UsageSnapshotModel] | None = None

    def _resolved_xray_settings(self) -> XraySettings:
        base = self.settings.xray
        config_path = Path(base.config)
        try:
            mtime = config_path.stat().st_mtime_ns
        except OSError:
            mtime = None
        cached = self._settings_cache
        if cached is not None and cached[0] == mtime:
            return cached[1]

        api_base = api_base_from_config(config_path, base.api_base)
        username, password = xray_auth_from_config(config_path, base.username, base.password)
        resolved = XraySettings(
            api_base=api_base,
            username=username,
            password=password,
            binary=base.binary,
            config=base.config,
            timeout=base.timeout,
            connect_timeout=base.connect_timeout,
        )
        self._settings_cache = (mtime, resolved)
        return resolved

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
        self._api_ready_until = 0.0

    async def _ensure_api_ready(self) -> None:
        """Ensure HTTP API is reachable without restarting a live xray.service (keep connections)."""
        try:
            await maybe_await(self.client.system())
            return
        except AgentError:
            pass

        from agent.xray_service import (
            ensure_xray_httpapi_config,
            ensure_xray_running,
            wait_xray_http_api,
        )

        base = self.settings.xray
        config_path = Path(base.config)
        # Sync httpapi block on disk if needed — never restart solely for that drift.
        ensure_xray_httpapi_config(
            config_path,
            api_base=base.api_base,
            username=base.username,
            password=base.password,
        )
        self._reset_client()
        resolved = self._resolved_xray_settings()

        if await service_is_active(_XRAY_UNIT):
            await wait_xray_http_api(
                api_base=resolved.api_base,
                username=resolved.username,
                password=resolved.password,
                attempts=40,
                delay=0.3,
            )
        else:
            await ensure_xray_running(
                binary=base.binary,
                config_path=base.config,
                api_base=base.api_base,
                username=base.username,
                password=base.password,
            )

        self._reset_client()
        await maybe_await(self.client.system())

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
            "routing_test",
            "clients_batch",
            "inbound_preserve_clients",
            "outbounds",
            "xray_console",
            "xray_logs",
        ]

    def installed(self) -> bool:
        return Path(self.settings.xray.binary).is_file() or shutil.which("xray") is not None

    async def _api(self) -> XrayHttpClient:
        # A live client was checked moments ago. Skipping the stats ping and the
        # config re-read keeps a single delete from repeating that work.
        if (
            self._client_override is None
            and self._client is not None
            and time.monotonic() < self._api_ready_until
        ):
            return self._client
        await self._ensure_api_ready()
        if self._client_override is None:
            self._api_ready_until = time.monotonic() + 15.0
        return self.client

    async def _api_call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        api = await self._api()
        return await maybe_await(getattr(api, name)(*args, **kwargs))

    async def running(self) -> bool:
        if not self.installed():
            return False
        try:
            await maybe_await(self.client.system())
            return True
        except AgentError:
            return False

    async def version(self) -> str | None:
        binary = self._binary()
        if not binary:
            return None
        try:
            result = await run([binary, "version"], timeout=5, check=False)
            return (result.stdout or result.stderr).strip().split("\n")[0] or None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def install(self) -> dict[str, Any]:
        from agent.ops import install_xray

        return await install_xray()

    async def enable(self) -> dict[str, Any]:
        from agent.ops import install_xray
        from agent.xray_service import binary_has_httpapi, ensure_xray_running

        xray = self.settings.xray
        binary = self._binary()
        if not binary or not binary_has_httpapi(binary):
            await install_xray(force=True)

        # Keep-alive: start only when down; never bounce an already-running unit.
        return await ensure_xray_running(
            binary=xray.binary,
            config_path=xray.config,
            api_base=xray.api_base,
            username=xray.username,
            password=xray.password,
        )

    async def disable(self) -> dict[str, Any]:
        from agent.xray_service import stop_xray_service

        stop_forwarders(self.settings)
        return await stop_xray_service()

    async def restart(self) -> dict[str, Any]:
        from agent.xray_service import restart_xray_service

        xray = self.settings.xray
        return await restart_xray_service(
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
        for candidate in (self.settings.xray.binary, shutil.which("xray")):
            if candidate and Path(candidate).is_file():
                return str(candidate)
        return None

    async def _validate_config_mutation(
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

        await validate_xray_config_mutation(binary, config_path, mutate)

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

    def _inbound_lock(self, tag: str) -> asyncio.Lock:
        lock = self._inbound_locks.get(tag)
        if lock is None:
            lock = asyncio.Lock()
            self._inbound_locks[tag] = lock
        return lock

    @staticmethod
    def _is_api_inbound(row: dict[str, Any]) -> bool:
        tag = str(row.get("tag") or "").strip().lower()
        protocol = str(row.get("protocol") or "").strip().lower()
        return tag == "api" or protocol in {"dokodemo-door", "tunnel"}

    def _row_matches_inbound_id(self, row: dict[str, Any], inbound_id: int | str, tag: str) -> bool:
        row_tag = str(row.get("tag") or "").strip()
        return row_tag == tag or str(row.get("id") or "") == str(inbound_id)

    async def list_quota_inbounds(self) -> list[dict[str, Any]]:
        """Quota checks use the on-disk user list, not /api/inbounds/list."""
        inbounds = await self._quota_inbounds_from_cache()
        await self._overlay_quota(inbounds, include_flags=False)
        return inbounds

    async def _quota_inbounds_from_cache(self) -> list[dict[str, Any]]:
        """Shallow client copies. A full deepcopy of config.json stalls the loop."""
        try:
            config = await self._cached_config()
        except AgentError:
            return []
        rows: list[dict[str, Any]] = []
        for raw in config.get("inbounds") or []:
            if not isinstance(raw, dict) or self._is_api_inbound(raw):
                continue
            inbound = self._shell_from_row(raw)
            settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
            clients = [
                dict(client)
                for client in (settings.get("clients") or settings.get("users") or [])
                if isinstance(client, dict)
            ]
            inbound["settings"]["clients"] = clients
            rows.append(inbound)
        return rows

    async def _inbound_shell(
        self,
        inbound_id: int | str,
        *,
        include_clients: bool = True,
    ) -> dict[str, Any]:
        """Inbound settings from disk (or one live row). Does not list every user."""
        tag = self.inbound_tag(inbound_id)
        try:
            copied = await self._copy_inbound_from_disk(inbound_id, tag, include_clients)
        except AgentError:
            copied = None
        if copied is not None:
            return copied
        for row in await self._api_call("list_inbounds", ):
            if not isinstance(row, dict):
                continue
            if self._row_matches_inbound_id(row, inbound_id, tag):
                if include_clients:
                    return self._normalize(row)
                return self._shell_from_row(row)
        raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{inbound_id}] not found", 404)

    async def _copy_inbound_from_disk(
        self,
        inbound_id: int | str,
        tag: str,
        include_clients: bool,
    ) -> dict[str, Any] | None:
        config = await self._cached_config()
        for row in config.get("inbounds") or []:
            if not isinstance(row, dict):
                continue
            if not self._row_matches_inbound_id(row, inbound_id, tag):
                continue
            if include_clients:
                return self._normalize(row)
            return self._shell_from_row(row)
        return None

    async def _attach_live_users(self, inbound: dict[str, Any]) -> dict[str, Any]:
        tag = str(inbound.get("tag") or "").strip()
        try:
            live = await self._api_call("list_users", tag) if tag else []
        except AgentError:
            live = []
        inbound.setdefault("settings", {})["clients"] = [
            normalize_xray_client(client) for client in live if isinstance(client, dict)
        ]
        return inbound

    async def _lookup_clients_for_batch(
        self,
        tag: str,
        clients: list[dict[str, Any]],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        emails: list[str] = []
        seen: set[str] = set()
        for raw in clients:
            if not isinstance(raw, dict):
                continue
            email = str(raw.get("email") or "").strip()
            if not email or email in seen:
                continue
            seen.add(email)
            emails.append(email)

        async def lookup(email: str) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
            try:
                rows = await self._api_call("list_users", tag, email)
            except AgentError:
                return {}, {}
            return self._index_user_rows(
                [normalize_xray_client(row) for row in rows if isinstance(row, dict)]
            )

        parts = await bounded_gather(
            [lambda email=email: lookup(email) for email in emails],
            limit=_CLIENT_PARALLELISM,
        )
        by_email: dict[str, dict[str, Any]] = {}
        by_id: dict[str, dict[str, Any]] = {}
        for part in parts:
            if not isinstance(part, tuple):
                continue
            extra_email, extra_id = part
            by_email.update(extra_email)
            by_id.update(extra_id)
        return by_email, by_id

    async def client_traffic_counters(self, key: str) -> tuple[int, int]:
        """One user's cumulative counters. Does not dump every user on the node."""
        label = str(key or "").strip()
        if not label:
            return 0, 0
        return await self._live_counters_for(label, "")

    async def _live_counters_for(self, email: str, cid: str) -> tuple[int, int]:
        api = await self._api()
        query = getattr(api, "stats_query", None)
        if not callable(query):
            return 0, 0
        for key in (email, cid):
            if not key:
                continue
            try:
                rows = await maybe_await(query(f"user>>>{key}>>>traffic>>>"))
            except Exception:
                continue
            incoming = outgoing = 0
            found = False
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or "")
                try:
                    value = int(row.get("value") or 0)
                except (TypeError, ValueError):
                    continue
                if name.endswith(">>>downlink"):
                    incoming = value
                    found = True
                elif name.endswith(">>>uplink"):
                    outgoing = value
                    found = True
            if found:
                return incoming, outgoing
        return 0, 0

    @staticmethod
    def _clients_of(inbound: dict[str, Any]) -> list[dict[str, Any]]:
        return xray_client_rows(inbound)

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

    async def _edit_inbound_preserving(self, inbound: dict[str, Any], *, preserve_clients: bool) -> None:
        self._pause_proxy_forwarders()
        try:
            api_payload = self._wire_inbound(inbound)
            await self._validate_config_mutation(
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
                await self._api_call("edit_inbounds", [slim], preserve_clients=True)
                return
            await self._api_call("edit_inbounds", [api_payload], preserve_clients=False)
        finally:
            await self._resume_proxy_forwarders()

    def _wire_clients(self, inbound: dict[str, Any], clients: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        protocol = self._protocol_of(inbound)
        settings = inbound.get("settings") or {}
        rows = clients if clients is not None else settings.get("clients") or settings.get("users") or []
        return [
            xray_protocol_user(protocol, client, inbound_settings=settings)
            for client in rows
        ]

    def _wire_inbound(self, inbound: dict[str, Any]) -> dict[str, Any]:
        payload = deepcopy(inbound)
        payload.pop("id", None)
        for key in (
            "format",
            "remark",
            "is_enabled",
            "enable",
            "expiryTime",
            "expires_at",
            "total",
            "up",
            "down",
            "incoming",
            "outgoing",
            "skip_template",
            "clientMethod",
            "share",
            "acceptProxyProtocol",
            "extra",
            "preserve_clients",
            "reset_clients",
        ):
            payload.pop(key, None)

        stream = payload.get("streamSettings")
        if isinstance(stream, dict):
            # Panel-only share hosts; Xray streamConfig rejects this key.
            stream.pop("domainSettings", None)

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

    async def list_inbounds(self) -> list[dict[str, Any]]:
        inbounds = [self._normalize(row) for row in await self._api_call("list_inbounds", )]
        await self._overlay_quota(inbounds, include_flags=False)
        return inbounds

    async def sync_proxy_protocol_forwarders(self) -> dict[str, Any]:
        try:
            return sync_forwarders_from_inbounds(await self.list_inbounds(), settings=self.settings)
        except AgentError as exc:
            _log.warning("pp-forward sync skipped: %s", exc.message)
            return {"enabled": True, "rules": 0, "running": False, "error": exc.code}

    def _pause_proxy_forwarders(self) -> None:
        """Release public listen ports before Xray rebinding (port-1 conflicts)."""
        stop_forwarders(self.settings)

    async def _resume_proxy_forwarders(self) -> None:
        try:
            await self.sync_proxy_protocol_forwarders()
        except Exception as exc:  # noqa: BLE001 — best-effort restore after failed edit
            _log.warning("pp-forward resync failed: %s", exc)

    async def get_inbound(self, inbound_id: int | str, *, include_clients: bool = True) -> dict[str, Any]:
        inbound = await self._inbound_shell(inbound_id, include_clients=include_clients)
        if not include_clients:
            return inbound
        inbound = await self._attach_live_users(inbound)
        await self._overlay_quota([inbound], include_flags=False)
        return inbound

    async def _batch_inbound(self, inbound_id: int | str) -> dict[str, Any]:
        """One inbound plus its live users. Prefer targeted lookups for upserts."""
        return await self._attach_live_users(await self._inbound_shell(inbound_id))

    async def create_inbound(self, payload: dict[str, Any]) -> dict[str, Any]:
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
            for row in await self.list_inbounds():
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
        await self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        self._pause_proxy_forwarders()
        try:
            await self._api_call("add_inbounds", [api_payload])
        finally:
            await self._resume_proxy_forwarders()
        await self.audit.record("create", f"xray/inbound/{inbound_id}")
        return await self.get_inbound(inbound_id)

    async def update_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        existing = await self.get_inbound(inbound_id)
        tag = str(existing.get("tag") or self.inbound_tag(inbound_id))
        preserve_clients = bool(payload.get("preserve_clients", True))
        reset_clients = bool(payload.get("reset_clients", False))
        if reset_clients:
            preserve_clients = False

        async with self._inbound_lock(tag):
            existing = await self.get_inbound(inbound_id)
            inbound = self._apply_inbound_patch(
                existing,
                payload,
                preserve_clients=preserve_clients,
                reset_clients=reset_clients,
            )
            await self._edit_inbound_preserving(inbound, preserve_clients=preserve_clients)
            await self.audit.record("update", f"xray/inbound/{inbound_id}")
            return await self.get_inbound(inbound_id)

    async def refresh_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        """Rebuild protocol/stream for an inbound without delete+create when possible."""
        existing = await self.get_inbound(inbound_id)
        tag = str(existing.get("tag") or self.inbound_tag(inbound_id))
        reset_clients = bool(payload.pop("reset_clients", False))
        preserve_clients = not reset_clients
        payload = {k: v for k, v in payload.items() if k != "format"}
        payload.setdefault("port", existing.get("port"))

        async with self._inbound_lock(tag):
            existing = await self.get_inbound(inbound_id)
            inbound = self._apply_inbound_patch(
                existing,
                payload,
                preserve_clients=preserve_clients,
                reset_clients=reset_clients,
            )
            # Prefer in-place edit so clients stay attached and we avoid remove+add churn.
            await self._edit_inbound_preserving(inbound, preserve_clients=preserve_clients)
            await self.audit.record("update", f"xray/inbound/{inbound_id}/refresh")
            return await self.get_inbound(inbound_id)

    async def patch_inbound_settings(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update port/stream/sniffing/settings without rewriting client lists."""
        payload = dict(payload or {})
        payload["preserve_clients"] = True
        payload.pop("reset_clients", None)
        started = time.perf_counter()
        inbound = await self.update_inbound(inbound_id, payload)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        summary = self._inbound_summary(inbound)
        await self.audit.record("update", f"xray/inbound/{inbound_id}/settings", detail=f"ms={elapsed_ms};clients={summary.get('clients_count')}")
        return summary

    async def delete_inbound(self, inbound_id: int | str) -> bool:
        inbound = await self.get_inbound(inbound_id)
        self._pause_proxy_forwarders()
        try:
            await self._api_call("remove_inbounds", [str(inbound.get("tag"))])
        finally:
            await self._resume_proxy_forwarders()
        await self.audit.record("delete", f"xray/inbound/{inbound_id}")
        return True

    def _find_client(self, inbound: dict[str, Any], client_key: str) -> dict[str, Any] | None:
        for client in self._clients_of(inbound):
            if self._row_matches_key(client, client_key):
                return client
        return None

    @staticmethod
    def _row_matches_key(client: dict[str, Any], key: str) -> bool:
        # VLESS/VMess use id. Shadowsocks and Trojan use email, and the panel
        # node_id is often stored only as the user password.
        return key in {
            str(client.get("id") or "").strip(),
            str(client.get("uuid") or "").strip(),
            str(client.get("email") or "").strip(),
            str(client.get("password") or "").strip(),
        }

    async def get_client_record(self, inbound_id: int | str, client_key: str) -> dict[str, Any]:
        """Return client metadata from config.json (includes disabled / quota rows)."""
        key = str(client_key or "").strip()
        if not key:
            raise AgentError("VALIDATION_ERROR", "client key is required", 422)

        tag = self.inbound_tag(inbound_id)
        try:
            disk_client = await self._client_copy_from_disk(inbound_id, key)
        except AgentError:
            disk_client = None
        if disk_client is not None:
            return await self._with_stored_quota(disk_client, include_flags=True)

        # users/add updates the users API. config.json can omit that row.
        # get_inbound() would list every user first and sit past the panel's
        # 15s timeout with no response bytes. Match this key only.
        live = await self._find_live_user(tag, key)
        if live is not None:
            return await self._live_client_record(normalize_xray_client(live), key)

        stored = await self._find_disabled_client(key)
        if stored is not None:
            return stored

        raise AgentError("CLIENT_NOT_FOUND", f"Client [{key}] not found", 404)

    async def _client_copy_from_disk(self, inbound_id: int | str, key: str) -> dict[str, Any] | None:
        """One client off the cached document. Does not copy the rest of the file."""
        config = await self._cached_config()
        tag = self.inbound_tag(inbound_id)
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            inbound_tag = str(inbound.get("tag") or "").strip()
            if inbound_tag != tag and str(inbound.get("id") or "") != str(inbound_id):
                continue
            client = self._find_client(inbound, key)
            if client is not None:
                return normalize_xray_client(client)
        return None

    async def _live_client_record(self, client: dict[str, Any], key: str) -> dict[str, Any]:
        row = await self._with_stored_quota(client, include_flags=True)
        row["is_enabled"] = True
        await self._forget_disabled_keys([
            key,
            str(row.get("id") or ""),
            str(row.get("email") or ""),
            str(row.get("password") or ""),
        ])
        return row

    async def _find_live_user(self, tag: str, key: str) -> dict[str, Any] | None:
        users: list[dict[str, Any]] = []
        try:
            users = await self._api_call("list_users", tag, key)
        except AgentError:
            users = []
        for user in users:
            if isinstance(user, dict) and self._row_matches_key(user, key):
                return user
        # The users API filters by email only. A UUID that is not on disk has
        # to walk every user. Log it before the call: the panel gives up at 15s
        # and the access log is written only after this returns.
        _log.warning("xray client lookup scanning all users tag=%s key=%s", tag, key)
        try:
            users = await self._api_call("list_users", tag)
        except AgentError:
            return None
        for user in users:
            if not isinstance(user, dict):
                continue
            cid = str(user.get("id") or user.get("uuid") or "").strip()
            email = str(user.get("email") or "").strip()
            password = str(user.get("password") or "").strip()
            if key in {cid, email, password}:
                if not user.get("id") and cid:
                    user = {**user, "id": cid}
                return user
        return None

    async def diagnose_client(self, client_key: str, inbound_id: int | str | None = None) -> dict[str, Any]:
        from agent.support.client_diagnose import diagnose_xray_client, diagnose_xray_clients_by_key

        key = str(client_key or "").strip()
        if not key:
            raise ValueError("client key is required")

        if inbound_id is not None and str(inbound_id).strip() != "":
            return await diagnose_xray_client(self, inbound_id, key)

        return await diagnose_xray_clients_by_key(self, key)

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

    def _index_user_rows(
        self, rows: list[dict[str, Any]]
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        by_email: dict[str, dict[str, Any]] = {}
        by_id: dict[str, dict[str, Any]] = {}
        for user in rows:
            if not isinstance(user, dict):
                continue
            email = str(user.get("email") or "").strip()
            cid = str(user.get("id") or user.get("uuid") or "").strip()
            password = str(user.get("password") or "").strip()
            if email:
                by_email[email] = user
            if cid:
                by_id[cid] = user
            elif password:
                by_id[password] = user
        return by_email, by_id

    async def _visible_user_index(
        self,
        tag: str,
        emails: list[str] | None = None,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        """Users visible on this inbound. Prefer per-email lookups."""
        wanted = [str(email).strip() for email in (emails or []) if str(email).strip()]
        try:
            if wanted:
                parts = await bounded_gather(
                    [lambda email=email: self._api_call("list_users", tag, email) for email in wanted],
                    limit=_CLIENT_PARALLELISM,
                )
                rows: list[dict[str, Any]] = []
                for part in parts:
                    if isinstance(part, Exception):
                        raise part
                    rows.extend(part or [])
            else:
                rows = await self._api_call("list_users", tag)
        except AgentError:
            return {}, {}
        return self._index_user_rows(rows)

    def _response_client(
        self,
        client: dict[str, Any],
        by_email: dict[str, dict[str, Any]],
        by_id: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Return the identity the server actually stored.

        Shadowsocks often has no uuid. GET then only works with the email, so
        the panel can replace node_id with that key.
        """
        email = str(client.get("email") or "").strip()
        cid = str(client.get("id") or "").strip()
        row = by_email.get(email) if email else None
        if row is None and cid:
            row = by_id.get(cid)
        if not isinstance(row, dict):
            return client
        live_id = str(row.get("id") or row.get("uuid") or "").strip()
        live_email = str(row.get("email") or "").strip()
        stamped = dict(client)
        if live_id:
            stamped["id"] = live_id
        elif live_email:
            stamped["id"] = live_email
        if live_email:
            stamped["email"] = live_email
        return stamped

    def _client_uuid_visible(
        self,
        client: dict[str, Any],
        by_id: dict[str, dict[str, Any]],
        by_email: dict[str, dict[str, Any]],
    ) -> bool:
        cid = str(client.get("id") or "").strip()
        email = str(client.get("email") or "").strip()
        password = str(client.get("password") or "").strip()
        if cid and cid in by_id:
            return True
        if password and password in by_id:
            return True
        row = by_email.get(email) if email else None
        if row is None:
            return False
        # Shadowsocks and Trojan have no uuid on the user. An email hit is this
        # client. A VLESS row with a different id is a different client.
        live_id = str(row.get("id") or row.get("uuid") or "").strip()
        if not live_id:
            return True
        return bool(cid) and live_id == cid

    async def _commit_clients_to_inbound(
        self,
        tag: str,
        clients: list[dict[str, Any]],
        *,
        protocol: str,
        inbound_settings: dict[str, Any] | None,
    ) -> None:
        """Write uuids into the inbound document when users/add leaves them out."""
        current: dict[str, Any] | None = None
        for row in await self._api_call("list_inbounds", ):
            if str(row.get("tag") or "").strip() == tag:
                current = row
                break
        if current is None:
            raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{tag}] not found", 404)

        by_email, by_id = self._index_user_rows(self._clients_of(current))
        try:
            extra_email, extra_id = self._index_user_rows(await self._api_call("list_users", tag))
        except AgentError:
            extra_email, extra_id = {}, {}
        for email, row in extra_email.items():
            by_email.setdefault(email, row)
        for cid, row in extra_id.items():
            by_id.setdefault(cid, row)

        for raw in clients:
            if not isinstance(raw, dict):
                continue
            native = xray_protocol_user(protocol, raw, inbound_settings=inbound_settings)
            email = str(native.get("email") or "").strip()
            cid = str(native.get("id") or "").strip()
            stale = by_email.get(email) if email else None
            stale_id = str((stale or {}).get("id") or "").strip()
            if stale is not None and cid and stale_id and stale_id != cid:
                by_email.pop(email, None)
                by_id.pop(stale_id, None)
            if cid and cid in by_id:
                old_email = str(by_id[cid].get("email") or "").strip()
                if old_email:
                    by_email.pop(old_email, None)
                by_id.pop(cid, None)
            if email:
                by_email[email] = native
            if cid:
                by_id[cid] = native

        deduped: list[dict[str, Any]] = []
        seen: set[int] = set()
        for row in list(by_email.values()) + list(by_id.values()):
            marker = id(row)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(row)

        settings = dict(current.get("settings") or {})
        if isinstance(inbound_settings, dict):
            for key, value in inbound_settings.items():
                if key not in {"clients", "users"}:
                    settings[key] = value
        settings["clients"] = deduped
        settings["users"] = deduped
        if str(protocol or "").lower() == "vless":
            settings.setdefault("decryption", "none")

        payload = dict(current)
        for key in (
            "id",
            "remark",
            "is_enabled",
            "enable",
            "expiryTime",
            "expires_at",
            "total",
            "up",
            "down",
            "incoming",
            "outgoing",
            "format",
            "preserve_clients",
            "reset_clients",
        ):
            payload.pop(key, None)
        stream = payload.get("streamSettings")
        if isinstance(stream, dict):
            stream = dict(stream)
            stream.pop("domainSettings", None)
            payload["streamSettings"] = stream
        payload["tag"] = tag
        payload["protocol"] = str(current.get("protocol") or protocol)
        payload["settings"] = settings
        await self._api_call("edit_inbounds", [payload], preserve_clients=False)

    async def _write_client_rows(
        self,
        op: str,
        tag: str,
        rows: list[dict[str, Any]],
        *,
        protocol: str,
        inbound_settings: Any,
    ) -> dict[int, str]:
        """Write each client on its own request and overlap those requests."""
        if not rows:
            return {}
        method = "edit_users" if op == "edit" else "add_users"
        kwargs = {
            "protocol": protocol,
            "inbound_settings": inbound_settings,
            "atomic": False,
            "parallel": True,
        }

        async def one(index: int, row: dict[str, Any]) -> tuple[int, str | None, bool]:
            try:
                await self._api_call(method, tag, [row], **kwargs)
            except AgentError as exc:
                missing = XrayHttpClient._is_http_route_missing(exc)
                return index, exc.message, missing
            except Exception as exc:  # noqa: BLE001
                return index, f"{type(exc).__name__}: {exc}", False
            return index, None, False

        outcomes = await bounded_gather(
            [lambda index=index, row=row: one(index, row) for index, row in enumerate(rows)],
            limit=_CLIENT_PARALLELISM,
        )
        typed: list[tuple[int, str | None, bool]] = [
            item if isinstance(item, tuple) else (0, str(item), False)
            for item in outcomes
        ]
        if any(route_missing for _index, _message, route_missing in typed):
            await self._api_call(method, tag, rows, protocol=protocol, inbound_settings=inbound_settings, atomic=False, parallel=False)
            return {}
        return {
            index: message
            for index, message, _route_missing in typed
            if message
        }

    async def _apply_clients_bulk(
        self,
        op: str,
        tag: str,
        rows: list[dict[str, Any]],
        meta: list[dict[str, Any]],
        *,
        protocol: str,
        inbound_settings: Any,
    ) -> tuple[int, int, list[dict[str, str]], list[dict[str, Any]]]:
        write_errors = await self._write_client_rows(
            op,
            tag,
            rows,
            protocol=protocol,
            inbound_settings=inbound_settings,
        )

        # An add/edit HTTP 200 is not enough. Xray often reports succeeded while
        # the panel uuid is still absent, and an email-only hit is a different client.
        # Repair every missing row with one inbound write, not another API call each.
        pairs = list(zip(rows, meta))
        succeeded = len(pairs)
        failed = 0
        errors: list[dict[str, str]] = []
        pending: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for index, (row, client) in enumerate(pairs):
            message = write_errors.get(index)
            if message is None:
                pending.append((row, client))
                continue
            succeeded -= 1
            failed += 1
            errors.append({
                "email": str(client.get("email") or ""),
                "id": str(client.get("id") or ""),
                "message": message,
            })
        if not pending:
            return max(0, succeeded), failed, errors, []

        verify_emails = [str(client.get("email") or "").strip() for _row, client in pending]
        by_email, by_id = await self._visible_user_index(tag, verify_emails)
        missing: list[tuple[dict[str, Any], dict[str, Any]]] = []
        kept: list[dict[str, Any]] = []
        for row, client in pending:
            if self._client_uuid_visible(client, by_id, by_email):
                kept.append(self._response_client(client, by_email, by_id))
            else:
                missing.append((row, client))

        commit_error: str | None = None
        if missing:
            try:
                await self._commit_clients_to_inbound(
                    tag,
                    [row for row, _client in missing],
                    protocol=protocol,
                    inbound_settings=inbound_settings if isinstance(inbound_settings, dict) else None,
                )
            except AgentError as exc:
                commit_error = exc.message
            by_email, by_id = await self._visible_user_index(
                tag,
                [str(client.get("email") or "").strip() for _row, client in missing],
            )
            for _row, client in missing:
                email = str(client.get("email") or "")
                if self._client_uuid_visible(client, by_id, by_email):
                    kept.append(self._response_client(client, by_email, by_id))
                    continue
                succeeded -= 1
                failed += 1
                errors.append(
                    {
                        "email": email,
                        "id": str(client.get("id") or ""),
                        "message": commit_error or "client was not created on the inbound",
                    }
                )

        return max(0, succeeded), failed, errors, kept

    async def add_client(self, inbound_id: int | str, client: dict[str, Any]) -> dict[str, Any]:
        result = await self.batch_clients(inbound_id, [client], mode="upsert")
        if result.get("failed"):
            errors = result.get("errors") or []
            message = errors[0].get("message") if errors else "client upsert failed"
            raise AgentError("VALIDATION_ERROR", str(message), 422)
        rows = result.get("clients") or []
        return rows[0] if rows else normalize_xray_client(client)

    async def batch_clients(
        self,
        inbound_id: int | str,
        clients: list[dict[str, Any]],
        *,
        mode: str = "upsert",
        atomic: bool = False,
    ) -> dict[str, Any]:
        mode_key = str(mode or "upsert").strip().lower()
        if mode_key == "edit":
            mode_key = "update"
        if mode_key not in {"upsert", "add", "update"}:
            raise AgentError("VALIDATION_ERROR", "mode must be upsert|add|edit|update", 422)
        if len(clients) > _CLIENT_BATCH_MAX:
            raise AgentError(
                "PAYLOAD_TOO_LARGE",
                f"client batch limit is {_CLIENT_BATCH_MAX} per request",
                413,
            )

        inbound = await self._inbound_shell(inbound_id)
        inbound = await self._ensure_shadowsocks_method(inbound)
        tag = str(inbound["tag"])
        protocol = self._protocol_of(inbound)
        # Protocol change keeps the email and adds a new uuid on another inbound.
        # Drop that email everywhere else first, or the old protocol stays usable.
        await self._release_emails_from_other_inbounds(
            [str(raw.get("email") or "") for raw in clients if isinstance(raw, dict)],
            tag,
        )
        started = time.perf_counter()
        succeeded = 0
        failed = 0
        errors: list[dict[str, str]] = []
        applied: list[dict[str, Any]] = []

        self._traffic_index_cache = None
        # The grouped stats query used to run while this inbound lock was held,
        # so the next sync on the same inbound wrote nothing until every user
        # on the node had been counted.
        traffic_index: dict[str, dict[str, int]] = {}
        if len(clients) > _SMALL_CLIENT_BATCH:
            _log.info(
                "xray batch loading full user traffic index tag=%s clients=%s",
                tag,
                len(clients),
            )
            traffic_index = await self._user_traffic_index()
        lock = self._inbound_lock(tag)
        if lock.locked():
            _log.warning("xray inbound lock busy tag=%s clients=%s", tag, len(clients))
        wait_started = time.perf_counter()
        async with lock:
            waited_ms = (time.perf_counter() - wait_started) * 1000
            if waited_ms >= 500:
                _log.warning("xray inbound lock acquired tag=%s waited_ms=%.0f", tag, waited_ms)
            inbound = await self._inbound_shell(inbound_id)
            inbound = await self._ensure_shadowsocks_method(inbound)
            by_email, by_id = self._index_clients(inbound)
            live_email, live_id = await self._lookup_clients_for_batch(tag, clients)
            by_email.update(live_email)
            by_id.update(live_id)
            # One client update does not need every user's counters.
            # New rows are not in the index, so a create does not query stats.
            if len(clients) <= _SMALL_CLIENT_BATCH:
                traffic_index = {}
                known = clients_already_on_inbound(clients, by_email, by_id)
                if known:
                    await self._prefetch_zero_baselines(known)
            elif not traffic_index:
                await self._prefetch_zero_baselines(clients)

            to_add: list[dict[str, Any]] = []
            to_edit: list[dict[str, Any]] = []
            add_meta: list[dict[str, Any]] = []
            edit_meta: list[dict[str, Any]] = []
            to_remove: list[str] = []
            remove_meta: list[dict[str, Any]] = []
            # Email hit with a different panel uuid. Removed in one users/remove
            # after the loop; a per-client call would add a full Xray wait each.
            stale_replacements: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

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
                    # Canonical identity is panel node_id (Xray id). Match id
                    # first so a rotated credential never collides with a stale
                    # row that still claims the same email alias.
                    existing = by_id.get(cid) if cid else None
                    if existing is None and email:
                        existing = by_email.get(email)

                    if mode_key == "add" and existing is not None:
                        failed += 1
                        errors.append({"email": email, "message": "client already exists"})
                        continue
                    if mode_key == "update" and existing is None:
                        failed += 1
                        errors.append({"email": email, "message": "client not found"})
                        continue

                    if not record_is_enabled(client):
                        # Xray does not enforce enable=false on VLESS/VMess/Trojan
                        # (and ignores it on Shadowsocks). Leaving the user on the
                        # inbound keeps the credential working after the panel has
                        # marked the quota finished. Remove them from the data plane
                        # and keep a disabled record so list/diagnose still see them.
                        # A client that was never created stays absent.
                        client["is_enabled"] = False
                        remove_email = ""
                        if existing is not None:
                            remove_email = str(existing.get("email") or email).strip()
                        else:
                            live_row = (by_id.get(cid) if cid else None) or (by_email.get(email) if email else None)
                            if isinstance(live_row, dict):
                                remove_email = str(live_row.get("email") or email).strip()
                            else:
                                remove_email = await self._live_user_email(tag, cid, email)
                        prior = await self._find_disabled_client(cid or email)
                        if existing is None and prior is None and not remove_email:
                            succeeded += 1
                            applied.append(client)
                            continue
                        await self._remember_disabled_client(inbound_id, tag, client)
                        if remove_email:
                            to_remove.append(remove_email)
                            remove_meta.append(client)
                        else:
                            succeeded += 1
                            applied.append(client)
                        continue

                    self._stamp_live_baseline(client, traffic_index)
                    client["is_enabled"] = True
                    native = xray_protocol_user(
                        protocol,
                        client,
                        inbound_settings=inbound.get("settings"),
                    )
                    native["enable"] = True
                    native["is_enabled"] = True
                    if existing is not None:
                        existing_id = str(existing.get("id") or "").strip()
                        # Edit keeps the old uuid. The panel looks the client up
                        # by node_id, so an email hit with another id must be replaced.
                        if cid and existing_id and existing_id != cid:
                            stale_email = str(existing.get("email") or email).strip()
                            if stale_email:
                                stale_replacements.append((stale_email, native, client))
                            else:
                                to_add.append(native)
                                add_meta.append(client)
                        else:
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

            async def _flush(
                op: str,
                rows: list[dict[str, Any]],
                meta: list[dict[str, Any]],
            ) -> tuple[int, int, list[dict[str, str]], list[dict[str, Any]]]:
                if not rows:
                    return 0, 0, [], []
                try:
                    # Do not spawn `xray -test` here. That loads the whole config
                    # and runs into the same 60s ceiling as the panel request.
                    return await self._apply_clients_bulk(
                        op,
                        tag,
                        rows,
                        meta,
                        protocol=protocol,
                        inbound_settings=inbound.get("settings"),
                    )
                except AgentError as exc:
                    if exc.status == 413 or len(rows) == 1:
                        message = exc.message
                        return (
                            0,
                            len(meta),
                            [{"email": str(client.get("email") or ""), "message": message} for client in meta],
                            [],
                        )
                    mid = len(rows) // 2
                    left, right = await asyncio.gather(
                        _flush(op, rows[:mid], meta[:mid]),
                        _flush(op, rows[mid:], meta[mid:]),
                    )
                    return (
                        left[0] + right[0],
                        left[1] + right[1],
                        left[2] + right[2],
                        left[3] + right[3],
                    )
                except Exception as exc:  # noqa: BLE001
                    return (
                        0,
                        len(meta),
                        [
                            {
                                "email": str(client.get("email") or ""),
                                "message": f"{type(exc).__name__}: {exc}",
                            }
                            for client in meta
                        ],
                        [],
                    )

            stale_emails = [email for email, _native, _client in stale_replacements]
            removed_emails = await self._remove_live_clients(tag, [*to_remove, *stale_emails], errors)
            for email, client in zip(to_remove, remove_meta):
                if email in removed_emails:
                    succeeded += 1
                    applied.append(client)
                else:
                    failed += 1
            for email, native, client in stale_replacements:
                if email in removed_emails:
                    to_add.append(native)
                    add_meta.append(client)
                else:
                    failed += 1
            # Adds and edits target disjoint emails, so they can overlap.
            add_part, edit_part = await asyncio.gather(
                _flush("add", to_add, add_meta),
                _flush("edit", to_edit, edit_meta),
            )
            for part_ok, part_fail, part_errors, part_applied in (add_part, edit_part):
                succeeded += part_ok
                failed += part_fail
                errors.extend(part_errors)
                applied.extend(part_applied)

            await self._forget_disabled_clients([row for row in applied if record_is_enabled(row)])
            await self._save_client_quotas(applied)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        await self.audit.record(
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

    async def batch_remove_clients(
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
                "PAYLOAD_TOO_LARGE",
                f"client batch limit is {_CLIENT_BATCH_MAX} per request",
                413,
            )

        inbound = await self.get_inbound(inbound_id)
        tag = str(inbound["tag"])
        started = time.perf_counter()
        remove_emails: list[str] = []
        errors: list[dict[str, str]] = []
        succeeded = 0
        failed = 0

        async with self._inbound_lock(tag):
            inbound = await self.get_inbound(inbound_id)
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
                # Panel prune sends the email as an id when the SS user has no uuid.
                row = by_id.get(cid) or by_email.get(cid)
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
                    await self._api_call("remove_users", tag, remove_emails)
                    succeeded = len(remove_emails)
                    await self._forget_client_quotas(remove_emails + id_keys)
                    await self._forget_disabled_keys(remove_emails + id_keys)
                except AgentError as exc:
                    async def drop_one(email: str) -> tuple[str, str | None]:
                        try:
                            await self._api_call("remove_users", tag, [email])
                            return email, None
                        except AgentError as row_exc:
                            return email, row_exc.message

                    outcomes = await bounded_gather(
                        [lambda email=email: drop_one(email) for email in remove_emails],
                        limit=_CLIENT_PARALLELISM,
                    )
                    forgotten: list[str] = []
                    for outcome in outcomes:
                        if not isinstance(outcome, tuple):
                            continue
                        email, message = outcome
                        if message is None:
                            succeeded += 1
                            forgotten.append(email)
                        else:
                            failed += 1
                            errors.append({"email": email, "message": message})
                    if forgotten:
                        await self._forget_client_quotas(forgotten + id_keys)
                        await self._forget_disabled_keys(forgotten + id_keys)
                    if succeeded == 0 and not errors:
                        raise exc

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        await self.audit.record(
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

    async def _live_user_email(self, tag: str, client_id: str, email: str) -> str:
        """Email of a user that is live even when inbounds/list omitted the row."""
        try:
            by_email, by_id = await self._visible_user_index(tag, [email] if email else None)
        except Exception:
            return ""
        row = by_id.get(client_id) if client_id else None
        if row is None and email:
            row = by_email.get(email)
        if not isinstance(row, dict):
            return ""
        return str(row.get("email") or email or "").strip()

    async def _remove_live_clients(
        self,
        tag: str,
        emails: list[str],
        errors: list[dict[str, str]],
    ) -> set[str]:
        """Drop credentials from the running inbound. Missing users are already cut."""
        unique: list[str] = []
        seen: set[str] = set()
        for email in emails:
            if email and email not in seen:
                seen.add(email)
                unique.append(email)
        if not unique:
            return set()

        removed: set[str] = set()
        try:
            await self._api_call("remove_users", tag, unique)
            removed.update(unique)
        except AgentError:
            async def drop_one(email: str) -> tuple[str, str | None]:
                try:
                    await self._api_call("remove_users", tag, [email])
                    return email, None
                except AgentError as exc:
                    if _is_missing_user_error(exc):
                        return email, None
                    return email, exc.message
                except Exception as exc:  # noqa: BLE001
                    return email, f"{type(exc).__name__}: {exc}"

            outcomes = await bounded_gather(
                [lambda email=email: drop_one(email) for email in unique],
                limit=_CLIENT_PARALLELISM,
            )
            for outcome in outcomes:
                if not isinstance(outcome, tuple):
                    continue
                email, message = outcome
                if message is None:
                    removed.add(email)
                else:
                    errors.append({"email": email, "message": message})
        except Exception as exc:  # noqa: BLE001
            for email in unique:
                errors.append({"email": email, "message": f"{type(exc).__name__}: {exc}"})
            return removed

        # users/remove can report success and leave the credential in place.
        # A disable that did not actually drop the user must fail so the panel retries.
        try:
            by_email, _by_id = await self._visible_user_index(tag, unique)
        except Exception:
            by_email = {}
        still = {email for email in removed if email in by_email}
        for email in still:
            errors.append({
                "email": email,
                "message": "client is still on the live inbound after disable",
            })
        return removed - still

    async def _save_client_quotas(self, clients: list[dict[str, Any]]) -> None:
        puts: list[tuple[str, dict[str, Any]]] = []
        deletes: list[str] = []
        for client in clients:
            if not isinstance(client, dict):
                continue
            meta = quota_meta_from_client(client)
            doc_id = str(meta.get("id") or meta.get("email") or "").strip()
            if not doc_id:
                continue
            puts.append((doc_id, meta))
            email = str(meta.get("email") or "").strip()
            cid = str(meta.get("id") or "").strip()
            if cid and email and email != cid:
                deletes.append(email)
        if not puts and not deletes:
            return
        await self.store.write_docs(self.key, _QUOTA_KIND, puts, deletes)

    def _stamp_disabled_client(self, client: dict[str, Any]) -> dict[str, Any]:
        row = normalize_xray_client(client)
        row["is_enabled"] = False
        if not str(row.get("disabled_reason") or "").strip():
            mark_panel_disabled(row)
        return row

    async def _remember_disabled_client(self, inbound_id: int | str, tag: str, client: dict[str, Any]) -> None:
        row = self._stamp_disabled_client(client)
        doc_id = str(row.get("id") or row.get("email") or "").strip()
        if not doc_id:
            return
        row["inbound_id"] = str(inbound_id)
        row["inbound_tag"] = str(tag or "")
        await self.store.put_doc(self.key, _DISABLED_KIND, doc_id, row)
        email = str(row.get("email") or "").strip()
        if email and email != doc_id:
            await self.store.delete_doc(self.key, _DISABLED_KIND, email)

    async def _disabled_docs(self) -> list[dict[str, Any]]:
        try:
            rows = await self.store.list_docs(self.key, _DISABLED_KIND)
        except Exception:
            return []
        return [row for row in rows if isinstance(row, dict)]

    async def _find_disabled_client(self, client_key: str) -> dict[str, Any] | None:
        key = str(client_key or "").strip()
        if not key:
            return None
        for row in await self._disabled_docs():
            cid = str(row.get("id") or "").strip()
            email = str(row.get("email") or "").strip()
            if key == cid or key == email:
                found = normalize_xray_client(row)
                found["is_enabled"] = False
                if row.get("disabled_reason"):
                    found["disabled_reason"] = row.get("disabled_reason")
                if row.get("disabled_at"):
                    found["disabled_at"] = row.get("disabled_at")
                if isinstance(row.get("disabled_detail"), dict):
                    found["disabled_detail"] = row.get("disabled_detail")
                return found
        return None

    async def _forget_disabled_clients(self, clients: list[dict[str, Any]]) -> None:
        keys: list[str] = []
        for client in clients:
            if not isinstance(client, dict):
                continue
            cid = str(client.get("id") or "").strip()
            email = str(client.get("email") or "").strip()
            password = str(client.get("password") or "").strip()
            if cid:
                keys.append(cid)
            if email:
                keys.append(email)
            if password:
                keys.append(password)
        await self._forget_disabled_keys(keys)

    async def _forget_disabled_keys(self, keys: list[str]) -> None:
        wanted = {str(key).strip() for key in keys if str(key).strip()}
        if not wanted:
            return
        for row in await self._disabled_docs():
            cid = str(row.get("id") or "").strip()
            email = str(row.get("email") or "").strip()
            password = str(row.get("password") or "").strip()
            doc_id = cid or email
            if doc_id and (cid in wanted or email in wanted or password in wanted or doc_id in wanted):
                await self.store.delete_doc(self.key, _DISABLED_KIND, doc_id)

    async def present_inbounds(self, inbounds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Show quota-disabled clients that were removed from live Xray."""
        docs = await self._disabled_docs()
        if not docs:
            return inbounds
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            inbound_id = str(inbound.get("id") or "")
            tag = str(inbound.get("tag") or "")
            settings = inbound.setdefault("settings", {})
            clients = list(settings.get("clients") or [])
            seen: set[str] = set()
            for client in clients:
                if not isinstance(client, dict):
                    continue
                cid = str(client.get("id") or "").strip()
                email = str(client.get("email") or "").strip()
                if cid:
                    seen.add(cid)
                if email:
                    seen.add(email)
            for row in docs:
                doc_inbound = str(row.get("inbound_id") or "")
                doc_tag = str(row.get("inbound_tag") or "")
                if not ((inbound_id and doc_inbound == inbound_id) or (tag and doc_tag == tag)):
                    continue
                cid = str(row.get("id") or "").strip()
                email = str(row.get("email") or "").strip()
                if (cid and cid in seen) or (email and email in seen):
                    continue
                clients.append(await self._find_disabled_client(cid or email) or normalize_xray_client(row))
                if cid:
                    seen.add(cid)
                if email:
                    seen.add(email)
            settings["clients"] = clients
        return inbounds

    async def _user_traffic_index(self) -> dict[str, dict[str, int]]:
        api = await self._api()
        query = getattr(api, "stats_query_grouped", None)
        if not callable(query):
            return {}
        try:
            groups = await maybe_await(query("user>>>", "user"))
        except Exception:
            return {}
        if not isinstance(groups, dict):
            return {}
        users = groups.get("user") or {}
        return dict(users) if isinstance(users, dict) else {}

    @staticmethod
    def _stamp_live_baseline(client: dict[str, Any], index: dict[str, dict[str, int]]) -> None:
        """Copy live counters onto a zero baseline without a per-client stats query."""
        if int(client.get("_incoming") or 0) != 0 or int(client.get("_outgoing") or 0) != 0:
            return
        email = str(client.get("email") or "").strip()
        cid = str(client.get("id") or "").strip()
        traffic = index.get(email) if email else None
        if not isinstance(traffic, dict) and cid:
            traffic = index.get(cid)
        if not isinstance(traffic, dict):
            return
        live_in = int(traffic.get("downlink") or 0)
        live_out = int(traffic.get("uplink") or 0)
        if live_in <= 0 and live_out <= 0:
            return
        client["_incoming"] = live_in
        client["_outgoing"] = live_out

    async def _prefetch_zero_baselines(self, clients: list[dict[str, Any]]) -> None:
        """Parallel per-user stats only when the grouped traffic index is unavailable."""
        pending = [
            raw
            for raw in clients
            if isinstance(raw, dict)
            and record_is_enabled(raw)
            and int(raw.get("_incoming") or 0) == 0
            and int(raw.get("_outgoing") or 0) == 0
        ]
        if not pending:
            return

        async def fill(raw: dict[str, Any]) -> None:
            client = normalize_xray_client(raw)
            await self._raise_zero_baseline_to_live(client)
            raw["_incoming"] = int(client.get("_incoming") or 0)
            raw["_outgoing"] = int(client.get("_outgoing") or 0)

        await bounded_gather(
            [lambda raw=raw: fill(raw) for raw in pending],
            limit=_CLIENT_PARALLELISM,
        )

    async def _raise_zero_baseline_to_live(self, client: dict[str, Any]) -> None:
        """A renewed client is pushed with a zero baseline while Xray still has old counters.

        Leaving that gap makes the quota enforcer treat history as new usage and cut the
        client again immediately after volume renewal.
        """
        if int(client.get("_incoming") or 0) != 0 or int(client.get("_outgoing") or 0) != 0:
            return
        email = str(client.get("email") or "").strip()
        cid = str(client.get("id") or "").strip()
        live_in, live_out = await self._live_counters_for(email, cid)
        if live_in <= 0 and live_out <= 0:
            return
        client["_incoming"] = live_in
        client["_outgoing"] = live_out

    async def _forget_client_quotas(self, keys: list[str]) -> None:
        wanted = {str(key).strip() for key in keys if str(key).strip()}
        if not wanted:
            return
        for row in await self.store.list_docs(self.key, _QUOTA_KIND):
            if not isinstance(row, dict):
                continue
            cid = str(row.get("id") or "").strip()
            email = str(row.get("email") or "").strip()
            doc_id = cid or email
            if doc_id and (cid in wanted or email in wanted or doc_id in wanted):
                await self.store.delete_doc(self.key, _QUOTA_KIND, doc_id)

    async def _quota_index(self) -> dict[str, dict[str, Any]]:
        index: dict[str, dict[str, Any]] = {}
        try:
            rows = await self.store.list_docs(self.key, _QUOTA_KIND)
        except Exception:
            return index
        for row in rows:
            if not isinstance(row, dict):
                continue
            cid = str(row.get("id") or "").strip()
            email = str(row.get("email") or "").strip()
            if cid:
                index[f"i:{cid}"] = row
            if email:
                index[f"e:{email}"] = row
        return index

    async def _with_stored_quota(self, client: dict[str, Any], *, include_flags: bool) -> dict[str, Any]:
        index = await self._quota_index()
        cid = str(client.get("id") or "").strip()
        email = str(client.get("email") or "").strip()
        meta = index.get(f"i:{cid}") if cid else None
        if meta is None and email:
            meta = index.get(f"e:{email}")
        if meta:
            apply_quota_meta(client, meta, include_flags=include_flags)
        return client

    async def _overlay_quota(self, inbounds: list[dict[str, Any]], *, include_flags: bool) -> None:
        index = await self._quota_index()
        if not index:
            return
        for inbound in inbounds:
            for client in self._clients_of(inbound):
                cid = str(client.get("id") or "").strip()
                email = str(client.get("email") or "").strip()
                meta = index.get(f"i:{cid}") if cid else None
                if meta is None and email:
                    meta = index.get(f"e:{email}")
                if meta:
                    apply_quota_meta(client, meta, include_flags=include_flags)

    async def _ensure_shadowsocks_method(self, inbound: dict[str, Any]) -> dict[str, Any]:
        """Repair blank Shadowsocks cipher keys left by legacy broken inbounds."""
        from agent.support import repair_shadowsocks_settings

        if self._protocol_of(inbound) not in {"shadowsocks", "ss"}:
            return inbound

        settings = inbound.setdefault("settings", {})
        if not repair_shadowsocks_settings(settings):
            return inbound

        settings.setdefault("network", "tcp,udp")
        api_payload = self._wire_inbound(inbound)
        await self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        await self._api_call("edit_inbounds", [api_payload], preserve_clients=True)
        inbound_id = inbound.get("id") or self.id_from_tag(str(inbound.get("tag") or ""))
        if inbound_id is None:
            return inbound
        return await self.get_inbound(inbound_id)

    async def update_client(self, inbound_id: int | str, client_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        # Canonical key is panel ``node_id`` (Xray ``id``); always try it first,
        # then fall back to the configured email alias from the payload.
        inbound = await self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        payload_email = ""
        try:
            payload_email = str((payload or {}).get("email") or "").strip()
        except Exception:
            payload_email = ""
        if current is None and payload_email and payload_email != str(client_key or "").strip():
            current = self._find_client(inbound, payload_email)
        if current is None:
            merged = normalize_xray_client(payload)
            merged.setdefault("id", client_key)
            if not merged.get("email"):
                merged["email"] = payload_email or client_key
            mode = "upsert"
        else:
            merged = normalize_xray_client({**current, **payload})
            # Never rename the stored canonical id through an update payload.
            stored_id = str(current.get("id") or "").strip()
            if stored_id:
                merged["id"] = stored_id
            if not str(merged.get("email") or "").strip():
                merged["email"] = payload_email or str(current.get("email") or client_key)
            mode = "update"
        result = await self.batch_clients(inbound_id, [merged], mode=mode)
        if result.get("failed"):
            errors = result.get("errors") or []
            message = errors[0].get("message") if errors else "client update failed"
            raise AgentError("VALIDATION_ERROR", str(message), 422)
        rows = result.get("clients") or []
        return rows[0] if rows else merged

    async def _disk_email(self, inbound_id: int | str, tag: str, client_key: str) -> str:
        """Email for this client in config.json when the live list missed the row."""
        key = str(client_key or "").strip()
        if not key:
            return ""
        try:
            config = await self.read_config()
        except AgentError:
            return ""
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            inbound_tag = str(inbound.get("tag") or "").strip()
            if inbound_tag != tag and str(inbound.get("id") or "") != str(inbound_id):
                continue
            for row in xray_client_rows(inbound):
                cid = str(row.get("id") or "").strip()
                email = str(row.get("email") or "").strip()
                if key == cid or key == email:
                    return email or key
        return ""

    async def _release_emails_from_other_inbounds(
        self,
        emails: list[str],
        keep_tag: str,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Remove these emails from every inbound except keep_tag.

        One local config read. remove_users runs only for tags that still have
        a matching row, so a normal upsert does not walk the live API.
        """
        if config is None:
            try:
                plan = await self._emails_on_other_inbounds(emails, keep_tag)
            except AgentError:
                return
        else:
            plan = emails_on_other_inbounds(config, set(emails), keep_tag)

        async def drop(tag: str, found: list[str]) -> None:
            for offset in range(0, len(found), _CLIENT_BATCH_MAX):
                chunk = found[offset : offset + _CLIENT_BATCH_MAX]
                try:
                    await self._api_call("remove_users", tag, chunk)
                except AgentError as exc:
                    message = str(exc.message or "").lower()
                    if int(exc.status or 0) == 404 or "not found" in message:
                        continue
                    raise

        await gather_independent(*(drop(tag, found) for tag, found in plan.items()))

    async def delete_client(self, inbound_id: int | str, client_key: str) -> bool:
        key = str(client_key or "").strip()
        if not key:
            raise AgentError("VALIDATION_ERROR", "client key is required", 422)

        try:
            tag, email = await self._locate_disk_client(inbound_id, key)
        except AgentError:
            tag, email = "", ""
        if not email:
            # Panel sends the email as the path key. Remove that key directly.
            # Listing every user is the 15s timeout on a busy inbound, and it
            # only matters when the key is a uuid that config.json does not have.
            tag = self.inbound_tag(inbound_id)
            try:
                await self._api_call("remove_users", tag, [key])
                email = key
            except AgentError as exc:
                if _is_inbound_missing_error(exc) or not _is_missing_user_error(exc):
                    raise
                email = await self._client_email_from_users(tag, key)
                if not email or email == key:
                    raise AgentError("CLIENT_NOT_FOUND", f"Client [{key}] not found", 404) from exc
                try:
                    await self._api_call("remove_users", tag, [email])
                except AgentError as remove_exc:
                    if _is_missing_user_error(remove_exc):
                        raise AgentError("CLIENT_NOT_FOUND", f"Client [{key}] not found", 404) from remove_exc
                    raise
        else:
            try:
                await self._api_call("remove_users", tag, [email])
            except AgentError as exc:
                if _is_missing_user_error(exc):
                    raise AgentError("CLIENT_NOT_FOUND", f"Client [{key}] not found", 404) from exc
                raise

        await self._forget_client_keys([key, email])
        await self._release_emails_from_other_inbounds([email], tag)
        await self.audit.record("delete", f"xray/inbound/{inbound_id}/clients/{key}", email)
        return True

    async def _emails_on_other_inbounds(self, emails: list[str], keep_tag: str) -> dict[str, list[str]]:
        config = await self._cached_config()
        return emails_on_other_inbounds(config, set(emails), keep_tag)

    async def _locate_disk_client(self, inbound_id: int | str, client_key: str) -> tuple[str, str]:
        config = await self._cached_config()
        return self._client_email_in_config(config, inbound_id, client_key)

    def _client_email_in_config(
        self,
        config: dict[str, Any] | None,
        inbound_id: int | str,
        client_key: str,
    ) -> tuple[str, str]:
        if not isinstance(config, dict):
            return "", ""
        wanted_tag = self.inbound_tag(inbound_id)
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            inbound_tag = str(inbound.get("tag") or "").strip()
            if inbound_tag != wanted_tag and str(inbound.get("id") or "") != str(inbound_id):
                continue
            for row in xray_client_rows(inbound):
                if not self._row_matches_key(row, client_key):
                    continue
                email = str(row.get("email") or "").strip()
                return inbound_tag or wanted_tag, email or client_key
        return "", ""

    async def _client_email_from_users(self, tag: str, client_key: str) -> str:
        try:
            users = await self._api_call("list_users", tag, client_key)
        except AgentError:
            users = []
        for row in users:
            if not isinstance(row, dict) or not self._row_matches_key(row, client_key):
                continue
            email = str(row.get("email") or "").strip()
            return email or client_key
        _log.warning("xray client delete scanning all users tag=%s key=%s", tag, client_key)
        try:
            users = await self._api_call("list_users", tag)
        except AgentError:
            return ""
        for row in users:
            if not isinstance(row, dict) or not self._row_matches_key(row, client_key):
                continue
            email = str(row.get("email") or "").strip()
            return email or client_key
        return ""

    async def _forget_client_keys(self, keys: list[str]) -> None:
        seen: set[str] = set()
        for key in keys:
            key = str(key or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            await self.store.delete_doc(self.key, _QUOTA_KIND, key)
            await self.store.delete_doc(self.key, _DISABLED_KIND, key)

    async def reset_client_traffic(self, inbound_id: int | str, client_key: str) -> dict[str, Any]:
        inbound = await self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        email = str(current.get("email") or client_key)
        await self._api_call("reset_user_traffic", email)
        await self.audit.record("reset_traffic", f"xray/client/{client_key}")
        return current

    async def client_ips(self, email: str) -> list[str]:
        # Xray reports currently-online IPs, not an accumulating log.
        # Do not hide live addresses after a "clear" — the bot needs them for device lists.
        return await self._api_call("online_ips", email)

    async def client_ip_last_seen(self, email: str) -> dict[str, Any]:
        """``{ip: lastSeen}`` for sessions Xray still considers online."""
        return await self._api_call("online_ip_last_seen", email)

    def clear_client_ips(self, email: str) -> bool:
        return True

    async def backup(self) -> dict[str, Any]:
        inbounds, outbounds, rules = await gather_independent(
            self.list_inbounds(),
            self._api_call("list_outbounds"),
            self._api_call("list_rules"),
        )
        return {
            "inbounds": inbounds,
            "outbounds": outbounds,
            "rules": rules,
        }

    async def restore(self, payload: dict[str, Any]) -> bool:
        desired = list(payload.get("inbounds") or [])
        existing = await self.list_inbounds()
        if existing:
            await self._api_call("remove_inbounds", [str(i.get("tag")) for i in existing if i.get("tag")])
        cleaned = []
        for row in desired:
            item = deepcopy(row)
            item.pop("id", None)
            settings = item.setdefault("settings", {})
            settings["clients"] = [normalize_xray_client(c) for c in settings.get("clients") or []]
            cleaned.append(self._wire_inbound(item))
        if cleaned:
            await self._api_call("add_inbounds", cleaned)
        if payload.get("outbounds"):
            try:
                await self._api_call("add_outbounds", list(payload["outbounds"]))
            except AgentError:
                pass
        if payload.get("rules"):
            try:
                await self._api_call("add_rules", list(payload["rules"]))
            except AgentError:
                pass
        await self.audit.record("restore", "xray")
        return True

    async def import_config(self, config: dict[str, Any], path: str | None = None) -> dict[str, Any]:
        binary = self._binary()
        if binary:
            await validate_xray_config(binary, config)
        result = await self._api_call("import_config", config, path=path)
        await self.audit.record("import", "xray/config")
        return result

    async def x25519(self) -> dict[str, str]:
        binary = self._binary()
        if not binary:
            raise AgentError("UNSUPPORTED_CAPABILITY", "xray binary not found for x25519", 400)
        try:
            result = await run([binary, "x25519"], timeout=10, check=False)
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

    async def read_config(self) -> dict[str, Any]:
        """Private copy of the whole file. Hot paths must not use this."""
        return deepcopy(await self._cached_config())

    async def _cached_config(self) -> dict[str, Any]:
        """Parsed config.json. Callers may read it and must not mutate it."""
        path = Path(self.settings.xray.config)
        path_str = str(path)
        if not await aiofiles.os.path.isfile(path_str):
            with self._config_lock:
                self._config_cache = None
            raise AgentError("CONFIG_NOT_FOUND", f"Xray config not found: {path}", 404)
        try:
            stat = await aiofiles.os.stat(path_str)
        except OSError as exc:
            raise AgentError("VALIDATION_ERROR", f"Invalid Xray config JSON: {exc}", 422) from exc
        key = (path_str, stat.st_mtime_ns, stat.st_size)
        with self._config_lock:
            cached = self._config_cache
            if cached is not None and (cached[0], cached[1], cached[2]) == key:
                return cached[3]
        try:
            raw = await aiofs.read_text(path)
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentError("VALIDATION_ERROR", f"Invalid Xray config JSON: {exc}", 422) from exc
        if not isinstance(data, dict):
            raise AgentError("VALIDATION_ERROR", "Xray config must be a JSON object", 422)
        with self._config_lock:
            self._config_cache = (key[0], key[1], key[2], data)
        return data

    def _invalidate_config_cache(self) -> None:
        with self._config_lock:
            self._config_cache = None

    def _shell_from_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Inbound fields without copying every client object."""
        settings = row.get("settings") if isinstance(row.get("settings"), dict) else {}
        raw_clients = settings.get("clients") or settings.get("users") or []
        count = len(raw_clients) if isinstance(raw_clients, list) else 0
        inbound: dict[str, Any] = {}
        for key, value in row.items():
            if key == "settings":
                continue
            inbound[key] = deepcopy(value) if isinstance(value, (dict, list)) else value
        slim: dict[str, Any] = {}
        for key, value in settings.items():
            if key in {"clients", "users"}:
                continue
            slim[key] = deepcopy(value) if isinstance(value, (dict, list)) else value
        slim["clients"] = []
        slim["users"] = []
        inbound["settings"] = slim
        inbound["clients_count"] = count
        tag = str(inbound.get("tag") or "")
        inbound_id = self.id_from_tag(tag)
        if inbound_id is not None:
            inbound["id"] = inbound_id
        elif "id" not in inbound:
            inbound["id"] = tag
        return inbound

    async def _read_config(self) -> dict[str, Any]:
        return await self.read_config()

    async def dumped_config(self) -> dict[str, Any]:
        return redact_secrets(await self.read_config())

    async def apply_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(config, dict) or not config:
            raise AgentError("VALIDATION_ERROR", "Xray config must be a non-empty object", 422)

        path = Path(self.settings.xray.config)
        current: dict[str, Any] = {}
        if await aiofiles.os.path.isfile(str(path)):
            try:
                current = await self.read_config()
            except AgentError:
                current = {}
        payload = restore_redacted_secrets(config, current)
        if not isinstance(payload, dict):
            raise AgentError("VALIDATION_ERROR", "Xray config must be a JSON object", 422)

        # Panel/API dumps can omit critical top-level keys. Keep disk values when omitted.
        for key in ("api", "httpapi", "inbounds", "outbounds", "routing"):
            if key not in config and key in current:
                payload[key] = current[key]

        from agent.support.config_validate import normalize_xray_config_shapes
        from agent.xray_service import ensure_traffic_stats_in_config

        normalize_xray_config_shapes(payload)
        ensure_traffic_stats_in_config(payload)

        binary = self._binary()
        if binary:
            await validate_xray_config(binary, payload)

        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        await aiofs.atomic_write(path, serialized)
        self._invalidate_config_cache()

        try:
            result = await self._api_call("import_config", payload, path=str(path))
        except AgentError:
            from agent.xray_service import ensure_xray_running

            xray = self.settings.xray
            # Prefer keep-alive: if the unit is already up, do not restart (drops connections).
            # When down, start loads the config we just wrote to disk.
            if await service_is_active(_XRAY_UNIT):
                raise
            result = await ensure_xray_running(
                binary=xray.binary,
                config_path=xray.config,
                api_base=xray.api_base,
                username=xray.username,
                password=xray.password,
            )
            result = {
                "ok": True,
                "started": True,
                "import": "skipped_loaded_on_start",
                "service": result,
            }
        await self.audit.record("update", "xray/config")
        return result if isinstance(result, dict) else {"ok": True}

    async def replace_section(self, section: str, value: Any) -> dict[str, Any]:
        name = str(section or "").strip()
        if name not in MANAGED_SECTIONS:
            raise AgentError("VALIDATION_ERROR", f"Unsupported Xray section [{name}]", 422)
        config = await self.read_config()
        if value is None:
            config.pop(name, None)
        elif name == "stats":
            # Empty object enables the Stats module; never treat {} / [] as "delete".
            config["stats"] = value if isinstance(value, dict) else {}
        elif value in ({}, []):
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
        return await self.apply_config(config)

    async def console(self) -> dict[str, Any]:
        config: dict[str, Any] = {}
        config_error: str | None = None
        try:
            config = await self.read_config()
        except AgentError as exc:
            config_error = exc.message

        outbounds: list[dict[str, Any]] = list(config.get("outbounds") or [])
        rules: list[dict[str, Any]] = list((config.get("routing") or {}).get("rules") or [])
        api_ok = False
        api_error: str | None = None
        try:
            outbounds, rules = await gather_independent(
                self.list_outbounds(),
                self.list_rules(),
            )
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

    async def tail_logs(self, kind: str = "error", lines: int = 200) -> dict[str, Any]:
        requested = str(kind or "error").strip().lower()
        if requested not in {"error", "access", "all"}:
            requested = "error"
        lines = max(20, min(int(lines or 200), 2000))
        log = {}
        try:
            log = dict((await self.read_config()).get("log") or {})
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

    async def restart_logger(self) -> dict[str, Any]:
        result = await self._api_call("restart_logger", )
        await self.audit.record("update", "xray/logger")
        return result if isinstance(result, dict) else {"ok": True}

    async def list_outbounds(self) -> list[dict[str, Any]]:
        return await self._api_call("list_outbounds", )

    async def add_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._api_call("add_outbounds", outbounds)

    async def edit_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._api_call("edit_outbounds", outbounds)

    async def remove_outbounds(self, tags: list[str]) -> dict[str, Any]:
        return await self._api_call("remove_outbounds", tags)

    async def list_rules(self) -> list[dict[str, Any]]:
        return await self._api_call("list_rules", )

    async def add_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._api_call("add_rules", rules)

    async def append_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        """Xray POST /api/rules/add?should_append=true. Never replaces the rule list."""
        result = await self._api_call("add_rules", rules, should_append=True)
        self.restrict_config_permissions()
        await self.audit.record("update", "xray/rules/append", f"count={len(rules)}")
        return result if isinstance(result, dict) else {"ok": True}

    def restrict_config_permissions(self) -> None:
        path = Path(self.settings.xray.config)
        if path.is_file():
            os.chmod(path, 0o600)

    def httpapi_guard(self) -> dict[str, Any]:
        path = Path(self.settings.xray.config)
        httpapi: dict[str, Any] = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            raw = data.get("httpapi") if isinstance(data, dict) else None
            if isinstance(raw, dict):
                httpapi = raw
        base = self.settings.xray
        return describe_httpapi_guard(httpapi, base.username, base.password)

    def ensure_httpapi_auth(self) -> dict[str, Any]:
        """Write Agent XRAY_USERNAME/PASSWORD into httpapi when the block is empty."""
        from agent.xray_service import ensure_xray_httpapi_config

        base = self.settings.xray
        username = str(base.username or "").strip()
        password = str(base.password or "").strip()
        if username and password:
            ensure_xray_httpapi_config(
                Path(base.config),
                api_base=base.api_base,
                username=username,
                password=password,
            )
            try:
                self.restrict_config_permissions()
            except OSError:
                pass
        return self.httpapi_guard()

    async def edit_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        if not rules:
            return {"updated": 0}
        results = await bounded_gather(
            [lambda rule=rule: self._api_call("edit_rule", rule) for rule in rules],
            limit=_CLIENT_PARALLELISM,
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, AgentError):
                raise item
            if isinstance(item, Exception):
                raise AgentError("EXEC_ERROR", f"{type(item).__name__}: {item}", 500)
        return {"updated": len(rules)}

    async def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        return await self._api_call("remove_rules", tags)

    async def replace_rules(self, rules: list[dict[str, Any]], routing_extras: dict[str, Any] | None = None) -> dict[str, Any]:
        """Atomically replace routing.rules (native API when available, else config section)."""
        extras = dict(routing_extras or {})
        started = time.perf_counter()
        # Prefer native /api/rules/replace — full config import validates+reloads Xray
        # and made region sync / panel ops feel stuck after v0.4.64.
        try:
            result = await self._api_call("replace_rules", list(rules), **extras)
        except AgentError as exc:
            # Older/buggy Xray builds: missing replace route, or replace returns
            # invalid_json / empty body — fall back to config section write.
            message = (exc.message or "").lower()
            missing = exc.status in {404, 405, 501} or "not found" in message or "unknown" in message
            broken_body = (
                exc.status in {400, 422}
                and (
                    "invalid_json" in message
                    or "incomplete json" in message
                    or "empty or incomplete" in message
                )
            )
            if not missing and not broken_body:
                raise
            routing = {
                key: value
                for key, value in extras.items()
                if key in {"domainStrategy", "domainMatcher", "balancers"} and value is not None
            }
            routing["rules"] = list(rules)
            result = await self.replace_section("routing", routing)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        await self.audit.record(
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

    async def upsert_rules(
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
            await self._api_call("remove_rules", tags)
            removed = len(tags)
        added = 0
        if rows:
            await self._api_call("add_rules", rows, should_append=True)
            added = len(rows)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        await self.audit.record(
            "update",
            "xray/rules/upsert",
            f"removed={removed} added={added} ms={elapsed_ms}",
        )
        return {"ok": True, "removed": removed, "added": added, "ms": elapsed_ms}

    async def test_routing(self, attrs: dict[str, Any]) -> dict[str, Any]:
        from agent.support.routing_test import test_routing_rules

        rules = await self.list_rules()
        if not rules:
            try:
                config = await self.read_config()
                routing = config.get("routing") if isinstance(config, dict) else None
                raw = routing.get("rules") if isinstance(routing, dict) else None
                if isinstance(raw, list):
                    rules = [row for row in raw if isinstance(row, dict)]
            except Exception:  # noqa: BLE001
                rules = []

        result = test_routing_rules(
            rules,
            attrs,
            config_path=self.settings.xray.config,
            binary_path=self.settings.xray.binary,
        )
        result["rules_count"] = len(rules)
        return result

    async def block_source_ips(self, source_ips: list[str], **kwargs: Any) -> dict[str, Any]:
        return await self._api_call("block_source_ips", source_ips, **kwargs)

    def cached_usage_snapshot(self, max_age: float = 30.0) -> UsageSnapshotModel | None:
        """Last full stats dump, if it is still inside the traffic sample window."""
        cached = self._usage_cache
        if cached is None:
            return None
        stored_at, snapshot = cached
        if time.monotonic() - stored_at > max_age:
            return None
        return snapshot

    async def usage_snapshot(self) -> UsageSnapshotModel:
        if self._usage_gate is None:
            self._usage_gate = asyncio.Lock()
        async with self._usage_gate:
            flight = self._usage_flight
            if flight is None:
                flight = asyncio.create_task(self._load_usage_snapshot())
                self._usage_flight = flight
        try:
            return await asyncio.shield(flight)
        finally:
            if self._usage_gate is not None:
                async with self._usage_gate:
                    if self._usage_flight is flight and flight.done():
                        self._usage_flight = None

    async def _load_usage_snapshot(self) -> UsageSnapshotModel:
        snapshot = await self._build_usage_snapshot()
        self._usage_cache = (time.monotonic(), snapshot)
        return snapshot

    async def _build_usage_snapshot(self) -> UsageSnapshotModel:
        user_groups, inbound_groups = await gather_independent(
            self._api_call("stats_query_grouped", "user>>>", "user"),
            self._api_call("stats_query_grouped", "inbound>>>", "inbound"),
        )
        user_traffic = dict(user_groups.get("user") or {})
        inbound_traffic = dict(inbound_groups.get("inbound") or {})
        try:
            identity_rows = await self._usage_identity_rows()
        except AgentError:
            identity_rows = []
        inbounds = [
            {
                "id": inbound_id,
                "tag": tag,
                "settings": {"clients": [{"id": cid, "email": email} for cid, email in clients]},
            }
            for inbound_id, tag, clients in identity_rows
        ]
        seen: set[str] = set()

        rows: list[InboundUsageModel] = []
        for inbound in inbounds:
            tag = str(inbound.get("tag") or "")
            counters = dict(inbound_traffic.get(tag) or {})
            clients: list[ClientUsageModel] = []
            for client in inbound.get("settings", {}).get("clients", []):
                cid = str(client.get("id") or "").strip()
                email = str(client.get("email") or "").strip()
                # Xray runtime stats are keyed by email alias while the panel
                # bills by canonical node_id. Keep both identifiers on the row
                # and prefer the matching alias before summing to zero traffic.
                traffic = dict(user_traffic.get(email) or {})
                if not traffic and cid and cid in user_traffic:
                    traffic = dict(user_traffic.get(cid) or {})
                if email:
                    seen.add(email)
                if cid:
                    seen.add(cid)
                canonical = cid or email
                clients.append(
                    ClientUsageModel(
                        id=canonical,
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

        leftover: list[ClientUsageModel] = []
        for email, traffic in user_traffic.items():
            label = str(email or "").strip()
            if not label or label in seen or not isinstance(traffic, dict):
                continue
            leftover.append(
                ClientUsageModel(
                    id=label,
                    email=label,
                    incoming=int(traffic.get("downlink") or 0),
                    outgoing=int(traffic.get("uplink") or 0),
                )
            )
        if leftover:
            rows.append(
                InboundUsageModel(
                    id="stats",
                    tag="stats",
                    incoming=sum(c.incoming for c in leftover),
                    outgoing=sum(c.outgoing for c in leftover),
                    clients=leftover,
                )
            )
        return UsageSnapshotModel(inbounds=rows)

    async def online_users(self) -> list[str]:
        if not await self.running():
            return []
        users = await self._api_call("online_users", )
        alias = await self._client_email_aliases()
        return [alias.get(str(item), str(item)) for item in users]

    async def online_ips_map(self) -> dict[str, Any]:
        if not await self.running():
            return {}
        try:
            body = await self._api_call("online_all", )
        except AgentError as exc:
            if exc.status in (404, 405, 501, 422):
                # Older Xray builds lack online/all — assemble from iplist locally
                # so panel still gets one bulk /stats/online/ips (or /stats/live) call.
                return await self._online_ips_map_from_iplist()
            raise

        users = body.get("users") or []
        if isinstance(users, dict):
            rows = [{"email": key, "ips": value} for key, value in users.items()]
        elif isinstance(users, list):
            rows = [row for row in users if isinstance(row, dict)]
        else:
            rows = []

        alias = await self._client_email_aliases()
        out: dict[str, Any] = {}
        for row in rows:
            email = str(row.get("email") or row.get("id") or "").strip()
            if email == "":
                continue
            ips = retain_fresh_online_ips(row["ips"] if "ips" in row else row)
            out[email] = ips
            cid = alias.get(email)
            if cid and cid != email:
                out[cid] = ips
        return out

    async def _online_ips_map_from_iplist(self) -> dict[str, Any]:
        """Fallback when GET /api/stats/online/all is missing (localhost iplist loop)."""
        try:
            raw_users = await self._api_call("online_users", )
        except AgentError:
            return {}

        emails = [str(item).strip() for item in raw_users or [] if str(item).strip()]
        alias = await self._client_email_aliases()

        async def fetch(email: str) -> tuple[str, Any]:
            try:
                ips = await self._api_call("online_ips", email)
            except AgentError:
                ips = []
            return email, ips

        parts = await bounded_gather(
            [lambda email=email: fetch(email) for email in emails],
            limit=_CLIENT_PARALLELISM,
        )
        out: dict[str, Any] = {}
        for part in parts:
            if not isinstance(part, tuple):
                continue
            email, ips = part
            out[email] = ips
            cid = alias.get(email)
            if cid and cid != email:
                out[cid] = ips
        return out

    async def _usage_identity_rows(self) -> list[tuple[Any, str, list[tuple[str, str]]]]:
        config = await self._cached_config()
        rows: list[tuple[Any, str, list[tuple[str, str]]]] = []
        for raw in config.get("inbounds") or []:
            if not isinstance(raw, dict) or self._is_api_inbound(raw):
                continue
            tag = str(raw.get("tag") or "")
            inbound_id = self.id_from_tag(tag)
            if inbound_id is None:
                inbound_id = raw.get("id", tag)
            settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
            clients: list[tuple[str, str]] = []
            for client in settings.get("clients") or settings.get("users") or []:
                if not isinstance(client, dict):
                    continue
                clients.append(
                    (str(client.get("id") or "").strip(), str(client.get("email") or "").strip())
                )
            rows.append((inbound_id, tag, clients))
        return rows

    async def _client_email_aliases(self) -> dict[str, str]:
        alias: dict[str, str] = {}
        try:
            for _inbound_id, _tag, clients in await self._usage_identity_rows():
                for cid, email in clients:
                    if email and cid:
                        alias[email] = cid
        except Exception:
            return {}
        return alias

    async def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import online_traffic_from_snapshot

        try:
            body = await self._api_call("online_traffic", )
        except AgentError as exc:
            if exc.status != 404:
                raise
            return await online_traffic_from_snapshot(self)

        users = body.get("users") or {}
        if not isinstance(users, dict):
            return await online_traffic_from_snapshot(self)
        try:
            alias = await self._client_email_aliases()
        except Exception:
            alias = {}
        out: dict[str, dict[str, int]] = {}
        for email, row in users.items():
            if not isinstance(row, dict):
                continue
            entry: dict[str, int] = {}
            for key in ("uplink", "downlink", "sessions"):
                if key in row and row[key] is not None:
                    entry[key] = int(row[key])
            label = str(email)
            out[label] = entry
            canonical = alias.get(label)
            if canonical and canonical != label:
                out[canonical] = entry
        # Xray /api/stats/online/traffic may return session presence without
        # uplink/downlink; fall back to QueryStats snapshot counters.
        if out and not any(
            int(row.get("uplink") or 0) > 0 or int(row.get("downlink") or 0) > 0
            for row in out.values()
        ):
            return await online_traffic_from_snapshot(self)
        return out
