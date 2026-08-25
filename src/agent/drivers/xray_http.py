from __future__ import annotations

import json
from threading import Lock
from typing import Any

import httpx

from agent.config import XraySettings
from agent.errors import AgentError


class XrayHttpClient:
    """Client for customized Xray-core HTTP API (`app/httpapi`)."""

    def __init__(self, settings: XraySettings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        base = settings.api_base.rstrip("/")
        auth = None
        if settings.username and settings.password:
            auth = (settings.username, settings.password)
        self._lock = Lock()
        self._client = httpx.Client(
            base_url=base,
            auth=auth,
            timeout=httpx.Timeout(settings.timeout, connect=settings.connect_timeout),
            headers={"Accept": "application/json"},
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | list | None = None,
        json_body: Any = None,
        files: Any = None,
        data: Any = None,
    ) -> Any:
        headers = {"Content-Type": "application/json"} if files is None and json_body is not None else None
        try:
            with self._lock:
                response = self._client.request(
                    method,
                    path,
                    params=params,
                    json=json_body if files is None else None,
                    files=files,
                    data=data,
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise AgentError("CONFIG_NOT_FOUND", f"Xray HTTP API unreachable: {exc}", 502) from exc

        if response.status_code == 401:
            raise AgentError("INVALID_CREDENTIALS", "Xray HTTP API unauthorized", 401)

        if response.status_code >= 400:
            try:
                body = response.json()
                message = str(body.get("error") or body.get("message") or body)
            except Exception:
                message = response.text or "unknown"
            raise AgentError(
                "VALIDATION_ERROR",
                f"Xray HTTP API error ({response.status_code}): {message}",
                response.status_code,
            )

        if not response.content:
            return {}
        try:
            return response.json()
        except Exception:
            return {"raw": response.text}

    def get(self, path: str, params: dict | list | None = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, payload: dict | None = None) -> Any:
        return self._request("POST", path, json_body=payload or {})

    def system(self) -> dict[str, Any]:
        return self.get("/api/stats/sys")

    def online_users(self) -> list[str]:
        body = self.get("/api/stats/online/users")
        users: list[str] = []
        for item in body.get("users") or []:
            if isinstance(item, str) and item.strip():
                users.append(item.strip())
                continue
            if isinstance(item, dict):
                value = item.get("email") or item.get("id") or item.get("user")
                if value:
                    users.append(str(value))
        return users

    def online_ips(self, email: str) -> list[str]:
        body = self.get("/api/stats/online/iplist", params={"email": email})
        ips = body.get("ips") or {}
        if isinstance(ips, dict):
            return list(ips.keys())
        if isinstance(ips, list):
            return [str(i) for i in ips]
        return []

    def online_all(self, emails: list[str] | None = None) -> dict[str, Any]:
        params = [("email", email) for email in emails] if emails else None
        return self.get("/api/stats/online/all", params=params)

    def online_traffic(self, *, reset: bool = False) -> dict[str, Any]:
        params: dict[str, str] = {}
        if reset:
            params["reset"] = "true"
        return self.get("/api/stats/online/traffic", params=params or None)

    def stats_query(
        self,
        pattern: str,
        *,
        reset: bool = False,
        online_only: bool = False,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"pattern": pattern}
        if reset:
            params["reset"] = "true"
        if online_only:
            params["online_only"] = "true"
        body = self.get("/api/stats/query", params=params)
        return list(body.get("stat") or [])

    def stats_query_grouped(
        self,
        pattern: str,
        group: str | None = None,
        *,
        online_only: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"pattern": pattern, "grouped": "true"}
        if group:
            params["group"] = group
        if online_only:
            params["online_only"] = "true"
        body = self.get("/api/stats/query", params=params)
        return dict(body.get("stats") or {})

    def reset_user_traffic(self, email: str) -> None:
        self.get("/api/stats", params={"name": f"user>>>{email}>>>traffic>>>uplink", "reset": "true"})
        self.get("/api/stats", params={"name": f"user>>>{email}>>>traffic>>>downlink", "reset": "true"})

    def restart_logger(self) -> dict[str, Any]:
        return self.post("/api/logger/restart")

    def list_inbounds(self) -> list[dict[str, Any]]:
        body = self.get("/api/inbounds/list")
        return list(body.get("inbounds") or [])

    def add_inbounds(self, inbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self.post("/api/inbounds/add", {"inbounds": inbounds})

    def edit_inbounds(
        self,
        inbounds: list[dict[str, Any]],
        *,
        preserve_clients: bool | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"inbounds": inbounds}
        if preserve_clients is not None:
            payload["preserve_clients"] = bool(preserve_clients)
        return self.post("/api/inbounds/edit", payload)

    def remove_inbounds(self, tags: list[str]) -> dict[str, Any]:
        return self.post("/api/inbounds/remove", {"tags": tags})

    def add_users(
        self,
        tag: str,
        clients: list[dict[str, Any]],
        *,
        protocol: str | None = None,
        inbound_settings: dict[str, Any] | None = None,
        atomic: bool = False,
    ) -> dict[str, Any]:
        from agent.support import xray_users_settings

        inbound: dict[str, Any] = {
            "tag": tag,
            "settings": xray_users_settings(protocol or "vless", inbound_settings, clients),
        }
        if protocol:
            inbound["protocol"] = protocol
        payload: dict[str, Any] = {"inbounds": [inbound]}
        if atomic:
            payload["atomic"] = True
        return self.post("/api/inbounds/users/add", payload)

    def edit_users(
        self,
        tag: str,
        clients: list[dict[str, Any]],
        *,
        protocol: str | None = None,
        inbound_settings: dict[str, Any] | None = None,
        atomic: bool = False,
    ) -> dict[str, Any]:
        from agent.support import xray_users_settings

        inbound: dict[str, Any] = {
            "tag": tag,
            "settings": xray_users_settings(protocol or "vless", inbound_settings, clients),
        }
        if protocol:
            inbound["protocol"] = protocol
        payload: dict[str, Any] = {"inbounds": [inbound]}
        if atomic:
            payload["atomic"] = True
        return self.post("/api/inbounds/users/edit", payload)

    def upsert_users(
        self,
        tag: str,
        clients: list[dict[str, Any]],
        *,
        protocol: str | None = None,
        inbound_settings: dict[str, Any] | None = None,
        atomic: bool = False,
    ) -> dict[str, Any]:
        from agent.support import xray_users_settings

        inbound: dict[str, Any] = {
            "tag": tag,
            "settings": xray_users_settings(protocol or "vless", inbound_settings, clients),
        }
        if protocol:
            inbound["protocol"] = protocol
        payload: dict[str, Any] = {"inbounds": [inbound]}
        if atomic:
            payload["atomic"] = True
        return self.post("/api/inbounds/users/upsert", payload)

    def remove_users(self, tag: str, emails: list[str], *, atomic: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"tag": tag, "emails": emails}
        if atomic:
            payload["atomic"] = True
        return self.post("/api/inbounds/users/remove", payload)

    def list_users(self, tag: str, email: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"tag": tag}
        if email:
            params["email"] = email
        body = self.get("/api/inbounds/users", params=params)
        return list(body.get("users") or [])

    def list_outbounds(self) -> list[dict[str, Any]]:
        body = self.get("/api/outbounds/list")
        return list(body.get("outbounds") or body.get("items") or [])

    def add_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self.post("/api/outbounds/add", {"outbounds": outbounds})

    def edit_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self.post("/api/outbounds/edit", {"outbounds": outbounds})

    def remove_outbounds(self, tags: list[str]) -> dict[str, Any]:
        return self.post("/api/outbounds/remove", {"tags": tags})

    def list_rules(self) -> list[dict[str, Any]]:
        body = self.get("/api/rules/list")
        return list(body.get("rules") or body.get("items") or [])

    def add_rules(self, rules: list[dict[str, Any]], *, should_append: bool = True) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/rules/add",
            params={"should_append": "true" if should_append else "false"},
            json_body={"routing": {"rules": rules}},
        )

    def edit_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/rules/edit", {"routing": {"rules": [rule]}})

    def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        return self.post("/api/rules/remove", {"tags": tags})

    def replace_rules(self, rules: list[dict[str, Any]], **routing_extras: Any) -> dict[str, Any]:
        """Prefer native Xray replace when available; caller may fall back to config write."""
        body: dict[str, Any] = {"rules": rules}
        body.update({k: v for k, v in routing_extras.items() if v is not None})
        return self.post("/api/rules/replace", body)

    def block_source_ips(
        self,
        source_ips: list[str],
        *,
        outbound: str = "blocked",
        inbound: str | None = None,
        rule_tag: str = "sourceIpBlock",
        reset: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "outbound": outbound,
            "rule_tag": rule_tag,
            "reset": reset,
            "source_ips": source_ips,
        }
        if inbound:
            payload["inbound"] = inbound
        return self.post("/api/sourceip/block", payload)

    def import_config(self, config: dict[str, Any], path: str | None = None) -> dict[str, Any]:
        files = {
            "file": ("config.json", json.dumps(config).encode("utf-8"), "application/json"),
        }
        data = {"path": path} if path else None
        return self._request("POST", "/api/config/import", files=files, data=data)
