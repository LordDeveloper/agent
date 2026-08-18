from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from agent.audit import AuditLog
from agent.config import AgentSettings, XraySettings
from agent.db import Store
from agent.drivers.base import CoreDriver
from agent.drivers.xray_http import XrayHttpClient
from agent.errors import AgentError
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support import normalize_xray_client, record_is_enabled
from agent.support.config_validate import (
    validate_xray_config,
    validate_xray_config_mutation,
    validate_xray_inbound,
)
from agent.support.process import service_is_active
from agent.xray_service import api_base_from_config, xray_auth_from_config

_TAG_RE = re.compile(r"^inbound-(.+)$")
_XRAY_UNIT = "xray"


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
            "outbounds",
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
        from agent.xray_service import ensure_xray_runtime

        xray = self.settings.xray
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
        for row in config.setdefault("inbounds", []):
            if str(row.get("tag")) != tag:
                continue
            settings = row.setdefault("settings", {})
            clients = list(settings.get("clients") or [])
            replaced = False
            for idx, current in enumerate(clients):
                if str(current.get("id")) == str(client.get("id")) or str(current.get("email")) == str(
                    client.get("email")
                ):
                    clients[idx] = client
                    replaced = True
                    break
            if not replaced:
                clients.append(client)
            settings["clients"] = clients
            return
        raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{tag}] not found in Xray config", 404)

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
            normalize_xray_client(client) for client in inbound["settings"].get("clients") or []
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
        payload = {k: v for k, v in payload.items() if k != "format"}
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

        api_payload = {k: v for k, v in inbound.items() if k != "id"}
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        self._api().add_inbounds([api_payload])
        self.audit.record("create", f"xray/inbound/{inbound_id}")
        return self.get_inbound(inbound_id)

    def update_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        inbound = self.get_inbound(inbound_id)
        payload = {k: v for k, v in payload.items() if k not in ("id", "tag", "format")}
        inbound.update(payload)
        if "settings" in payload and isinstance(payload["settings"], dict):
            clients = payload["settings"].get("clients")
            if clients is not None:
                inbound["settings"]["clients"] = [normalize_xray_client(c) for c in clients]
        api_payload = {k: v for k, v in inbound.items() if k != "id"}
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )
        self._api().edit_inbounds([api_payload])
        self.audit.record("update", f"xray/inbound/{inbound_id}")
        return self.get_inbound(inbound_id)

    def refresh_inbound(self, inbound_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_inbound(inbound_id)
        clients = existing.get("settings", {}).get("clients", [])
        reset_clients = bool(payload.pop("reset_clients", False))
        payload = {k: v for k, v in payload.items() if k != "format"}
        payload["id"] = inbound_id
        payload.setdefault("port", existing.get("port"))
        if not reset_clients:
            settings = deepcopy(payload.get("settings") or {})
            settings.setdefault("clients", clients)
            payload["settings"] = settings

        inbound = deepcopy(payload)
        inbound["id"] = inbound_id
        inbound["tag"] = inbound.get("tag") or self.inbound_tag(inbound_id)
        inbound.setdefault("listen", existing.get("listen", "0.0.0.0"))
        inbound.setdefault("settings", {})
        inbound.setdefault("streamSettings", existing.get("streamSettings") or {})
        inbound.setdefault("sniffing", existing.get("sniffing") or {})
        api_payload = {k: v for k, v in inbound.items() if k != "id"}
        self._validate_config_mutation(
            lambda cfg: self._replace_inbound_in_config(cfg, api_payload),
            inbound=api_payload,
        )

        self.delete_inbound(inbound_id)
        return self.create_inbound(payload)

    def delete_inbound(self, inbound_id: int | str) -> bool:
        inbound = self.get_inbound(inbound_id)
        self._api().remove_inbounds([str(inbound.get("tag"))])
        self.audit.record("delete", f"xray/inbound/{inbound_id}")
        return True

    def _find_client(self, inbound: dict[str, Any], client_key: str) -> dict[str, Any] | None:
        for client in inbound.get("settings", {}).get("clients", []):
            if str(client.get("id")) == client_key or str(client.get("email")) == client_key:
                return client
        return None

    def add_client(self, inbound_id: int | str, client: dict[str, Any]) -> dict[str, Any]:
        inbound = self.get_inbound(inbound_id)
        client = normalize_xray_client(client)
        client.setdefault("id", str(uuid.uuid4()))
        if not client.get("email"):
            client["email"] = str(client["id"])[:8]

        existing = self._find_client(inbound, str(client["id"])) or self._find_client(
            inbound, str(client.get("email"))
        )
        tag = str(inbound["tag"])
        if not record_is_enabled(client):
            if existing:
                self.delete_client(inbound_id, str(existing.get("email") or existing.get("id")))
            return client

        if existing:
            self._validate_config_mutation(
                lambda cfg: self._merge_client_in_config(cfg, tag, client),
            )
            self._api().edit_users(tag, [client])
            self.audit.record("update", f"xray/client/{client['id']}")
        else:
            self._validate_config_mutation(
                lambda cfg: self._merge_client_in_config(cfg, tag, client),
            )
            self._api().add_users(tag, [client])
            self.audit.record("create", f"xray/client/{client['id']}")
        return client

    def update_client(self, inbound_id: int | str, client_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        inbound = self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        merged = normalize_xray_client({**current, **payload})
        if not record_is_enabled(merged):
            self.delete_client(inbound_id, client_key)
            return merged
        self._validate_config_mutation(
            lambda cfg: self._merge_client_in_config(cfg, str(inbound["tag"]), merged),
        )
        self._api().edit_users(str(inbound["tag"]), [merged])
        self.audit.record("update", f"xray/client/{client_key}")
        return merged

    def delete_client(self, inbound_id: int | str, client_key: str) -> bool:
        inbound = self.get_inbound(inbound_id)
        current = self._find_client(inbound, client_key)
        if current is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Client [{client_key}] not found", 404)
        email = str(current.get("email") or client_key)
        self._api().remove_users(str(inbound["tag"]), [email])
        self.audit.record("delete", f"xray/client/{client_key}")
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
        blocked = set(self.store.get_meta(self.key, f"cleared_ips:{email}", []) or [])
        return [ip for ip in self._api().online_ips(email) if ip not in blocked]

    def clear_client_ips(self, email: str) -> bool:
        # Live sessions cannot be flushed remotely; mark current IPs ignored until reconnect.
        current = self._api().online_ips(email)
        self.store.set_meta(self.key, f"cleared_ips:{email}", current)
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
            cleaned.append(item)
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

    def list_outbounds(self) -> list[dict[str, Any]]:
        return self._api().list_outbounds()

    def add_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self._api().add_outbounds(outbounds)

    def remove_outbounds(self, tags: list[str]) -> dict[str, Any]:
        return self._api().remove_outbounds(tags)

    def list_rules(self) -> list[dict[str, Any]]:
        return self._api().list_rules()

    def add_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        return self._api().add_rules(rules)

    def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        return self._api().remove_rules(tags)

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
