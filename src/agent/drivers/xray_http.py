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
        method_u = method.upper()
        route = f"{method_u} {path}"
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
            raise AgentError(
                "CONFIG_NOT_FOUND",
                f"Xray HTTP API unreachable [{route}]: {exc}",
                502,
            ) from exc

        # Prefer the concrete URL httpx resolved (includes query).
        try:
            resolved = f"{method_u} {response.request.url}"
        except Exception:
            resolved = route

        if response.status_code == 401:
            raise AgentError(
                "INVALID_CREDENTIALS",
                f"Xray HTTP API unauthorized [{resolved}]",
                401,
            )

        if response.status_code >= 400:
            code_hint = ""
            try:
                body = response.json()
                message = str(body.get("error") or body.get("message") or body)
                code_hint = str(body.get("code") or "").strip().lower()
            except Exception:
                message = response.text or "unknown"
            detail = f"Xray HTTP API error ({response.status_code}) [{resolved}]: {message}"
            # Bare Go mux 404s mean the custom HTTP API routes are missing (stock Xray).
            if response.status_code == 404 or "page not found" in message.lower():
                raise AgentError("CONFIG_NOT_FOUND", detail, 404)
            if response.status_code in {401, 403}:
                raise AgentError("INVALID_CREDENTIALS", detail, response.status_code)
            if response.status_code == 413 or code_hint == "payload_too_large":
                raise AgentError("PAYLOAD_TOO_LARGE", detail, 413)
            raise AgentError(
                "VALIDATION_ERROR",
                detail,
                response.status_code if response.status_code >= 400 else 422,
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

    @staticmethod
    def _is_http_route_missing(exc: AgentError) -> bool:
        if int(exc.status or 0) in {404, 405, 501}:
            return True
        message = str(exc.message or "").lower()
        return "404 page not found" in message or "xray http api error (404)" in message

    @staticmethod
    def _client_email(client: dict[str, Any]) -> str:
        return str(client.get("email") or "").strip()

    @staticmethod
    def _inbound_clients(inbound: dict[str, Any]) -> list[dict[str, Any]]:
        settings = inbound.get("settings") if isinstance(inbound.get("settings"), dict) else {}
        rows = settings.get("clients") or settings.get("users") or []
        return [dict(row) for row in rows if isinstance(row, dict)]

    @staticmethod
    def _strip_panel_inbound_fields(inbound: dict[str, Any]) -> dict[str, Any]:
        payload = dict(inbound)
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
        return payload

    def _find_inbound_by_tag(self, tag: str) -> dict[str, Any]:
        wanted = str(tag or "").strip()
        for row in self.list_inbounds():
            if not isinstance(row, dict):
                continue
            if str(row.get("tag") or "").strip() == wanted:
                return dict(row)
        raise AgentError("CONFIG_NOT_FOUND", f"Inbound [{tag}] not found", 404)

    def _mutate_users_via_inbound_edit(
        self,
        tag: str,
        clients: list[dict[str, Any]],
        *,
        mode: str,
        protocol: str | None = None,
        inbound_settings: dict[str, Any] | None = None,
        remove_emails: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Fallback when /api/inbounds/users/* is missing (older/partial Xray HTTP API).

        Merges clients into the live inbound and POSTs /api/inbounds/edit with
        preserve_clients=false so runtime + config pick up the user list.
        """
        from agent.support import xray_protocol_user

        current = self._find_inbound_by_tag(tag)
        proto = str(protocol or current.get("protocol") or "vless").strip().lower()
        existing = self._inbound_clients(current)
        by_email: dict[str, dict[str, Any]] = {}
        extras: list[dict[str, Any]] = []
        for row in existing:
            email = self._client_email(row)
            if email:
                by_email[email] = row
            else:
                extras.append(row)

        mode_key = str(mode or "upsert").strip().lower()
        applied = 0
        errors: list[dict[str, str]] = []

        if mode_key == "remove":
            drop = {str(email).strip() for email in (remove_emails or []) if str(email).strip()}
            before = len(by_email)
            by_email = {email: row for email, row in by_email.items() if email not in drop}
            applied = max(0, before - len(by_email))
        else:
            for raw in clients:
                if not isinstance(raw, dict):
                    errors.append({"email": "", "message": "client must be an object"})
                    continue
                email = self._client_email(raw)
                try:
                    native = xray_protocol_user(proto, raw)
                except Exception as exc:  # noqa: BLE001
                    errors.append({"email": email, "message": f"{type(exc).__name__}: {exc}"})
                    continue
                if mode_key == "add":
                    if email and email in by_email:
                        errors.append({"email": email, "message": "client already exists"})
                        continue
                    if email:
                        by_email[email] = native
                    else:
                        extras.append(native)
                    applied += 1
                elif mode_key == "edit":
                    if not email or email not in by_email:
                        errors.append({"email": email, "message": "client not found"})
                        continue
                    by_email[email] = {**by_email[email], **native}
                    applied += 1
                else:  # upsert
                    if email:
                        by_email[email] = {**by_email.get(email, {}), **native}
                    else:
                        extras.append(native)
                    applied += 1

        settings = dict(current.get("settings") or {})
        if isinstance(inbound_settings, dict):
            for key, value in inbound_settings.items():
                if key not in {"clients", "users"}:
                    settings[key] = value
        merged = extras + list(by_email.values())
        settings["clients"] = merged
        settings["users"] = merged
        if proto == "vless":
            settings.setdefault("decryption", "none")

        payload = self._strip_panel_inbound_fields(current)
        payload["tag"] = tag
        payload["protocol"] = proto
        payload["settings"] = settings
        self.edit_inbounds([payload], preserve_clients=False)

        failed = len(errors)
        return {
            "succeeded": applied,
            "failed": failed,
            "errors": errors,
            "added_users": applied if mode_key in {"add", "upsert"} else 0,
            "updated_users": applied if mode_key == "edit" else 0,
            "removed_users": applied if mode_key == "remove" else 0,
            "fallback": "inbounds/edit",
        }

    def _users_request(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        tag: str,
        clients: list[dict[str, Any]],
        mode: str,
        protocol: str | None = None,
        inbound_settings: dict[str, Any] | None = None,
        remove_emails: list[str] | None = None,
    ) -> dict[str, Any]:
        try:
            result = self.post(path, payload)
            return result if isinstance(result, dict) else {"status": "ok", "result": result}
        except AgentError as exc:
            if not self._is_http_route_missing(exc):
                raise
            return self._mutate_users_via_inbound_edit(
                tag,
                clients,
                mode=mode,
                protocol=protocol,
                inbound_settings=inbound_settings,
                remove_emails=remove_emails,
            )

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
        return self._users_request(
            "/api/inbounds/users/add",
            payload,
            tag=tag,
            clients=clients,
            mode="add",
            protocol=protocol,
            inbound_settings=inbound_settings,
        )

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
        return self._users_request(
            "/api/inbounds/users/edit",
            payload,
            tag=tag,
            clients=clients,
            mode="edit",
            protocol=protocol,
            inbound_settings=inbound_settings,
        )

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
        return self._users_request(
            "/api/inbounds/users/upsert",
            payload,
            tag=tag,
            clients=clients,
            mode="upsert",
            protocol=protocol,
            inbound_settings=inbound_settings,
        )

    def remove_users(self, tag: str, emails: list[str], *, atomic: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"tag": tag, "emails": emails}
        if atomic:
            payload["atomic"] = True
        try:
            result = self.post("/api/inbounds/users/remove", payload)
            return result if isinstance(result, dict) else {"status": "ok", "result": result}
        except AgentError as exc:
            if not self._is_http_route_missing(exc):
                raise
            return self._mutate_users_via_inbound_edit(
                tag,
                [],
                mode="remove",
                remove_emails=list(emails),
            )

    def list_users(self, tag: str, email: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"tag": tag}
        if email:
            params["email"] = email
        try:
            body = self.get("/api/inbounds/users", params=params)
            return list(body.get("users") or [])
        except AgentError as exc:
            if not self._is_http_route_missing(exc):
                raise
            users = self._inbound_clients(self._find_inbound_by_tag(tag))
            if email:
                wanted = str(email).strip()
                users = [row for row in users if self._client_email(row) == wanted]
            return users

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

    def add_rules(self, rules: list[dict[str, Any]], *, should_append: bool = False) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/rules/add",
            params={"should_append": "true" if should_append else "false"},
            json_body={"routing": {"rules": rules}},
        )

    def edit_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        rule_tag = str(rule.get("ruleTag") or rule.get("tag") or "").strip()
        payload: dict[str, Any] = {"rule": rule}
        if rule_tag:
            payload["rule_tag"] = rule_tag
        return self.post("/api/rules/edit", payload)

    def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        # HTTPAPI accepts rule_tags / ruleTags / tags.
        return self.post("/api/rules/remove", {"rule_tags": tags, "ruleTags": tags, "tags": tags})

    def replace_rules(self, rules: list[dict[str, Any]], **routing_extras: Any) -> dict[str, Any]:
        """Atomically replace routing.rules. Omit balancers to keep existing ones."""
        body: dict[str, Any] = {"rules": rules}
        body.update({k: v for k, v in routing_extras.items() if v is not None})
        # Never wipe balancers accidentally — only send when caller provides them.
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
