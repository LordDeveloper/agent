"""In-memory stand-in for customized Xray-core HTTP API (tests only)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


class FakeXrayHttpClient:
    def __init__(self, settings=None, transport=None):
        self.settings = settings
        self._inbounds: list[dict[str, Any]] = []
        self._outbounds: list[dict[str, Any]] = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ]
        self._rules: list[dict[str, Any]] = []
        self._online: list[str] = []
        self._ips: dict[str, list[str]] = {}
        self._user_traffic: dict[str, dict[str, int]] = {}
        self._inbound_traffic: dict[str, dict[str, int]] = {}

    def close(self) -> None:
        return None

    def system(self) -> dict[str, Any]:
        return {"num_goroutine": 1}

    def online_users(self) -> list[str]:
        return list(self._online)

    def online_ips(self, email: str) -> list[str]:
        return list(self._ips.get(email, []))

    def stats_query_grouped(self, pattern: str, group: str | None = None) -> dict[str, Any]:
        if group == "user" or pattern.startswith("user"):
            return {"user": deepcopy(self._user_traffic)}
        if group == "inbound" or pattern.startswith("inbound"):
            return {"inbound": deepcopy(self._inbound_traffic)}
        return {}

    def reset_user_traffic(self, email: str) -> None:
        self._user_traffic[email] = {"uplink": 0, "downlink": 0}

    def restart_logger(self) -> dict[str, Any]:
        return {"status": "ok"}

    def list_inbounds(self) -> list[dict[str, Any]]:
        return deepcopy(self._inbounds)

    def add_inbounds(self, inbounds: list[dict[str, Any]]) -> dict[str, Any]:
        for inbound in inbounds:
            tag = inbound.get("tag")
            self._inbounds = [i for i in self._inbounds if i.get("tag") != tag]
            self._inbounds.append(deepcopy(inbound))
        return {"status": "ok"}

    def edit_inbounds(self, inbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self.add_inbounds(inbounds)

    def remove_inbounds(self, tags: list[str]) -> dict[str, Any]:
        tagset = set(tags)
        self._inbounds = [i for i in self._inbounds if i.get("tag") not in tagset]
        return {"status": "ok"}

    def add_users(self, tag: str, clients: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        for inbound in self._inbounds:
            if inbound.get("tag") == tag:
                inbound.setdefault("settings", {}).setdefault("clients", []).extend(deepcopy(clients))
                return {"added_users": len(clients)}
        raise RuntimeError(f"inbound {tag} missing")

    def edit_users(self, tag: str, clients: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        for inbound in self._inbounds:
            if inbound.get("tag") != tag:
                continue
            existing = inbound.setdefault("settings", {}).setdefault("clients", [])
            by_email = {str(c.get("email")): i for i, c in enumerate(existing)}
            for client in clients:
                email = str(client.get("email"))
                if email in by_email:
                    existing[by_email[email]] = deepcopy(client)
                else:
                    existing.append(deepcopy(client))
            return {"updated_users": len(clients)}
        raise RuntimeError(f"inbound {tag} missing")

    def remove_users(self, tag: str, emails: list[str]) -> dict[str, Any]:
        email_set = set(emails)
        for inbound in self._inbounds:
            if inbound.get("tag") != tag:
                continue
            clients = inbound.setdefault("settings", {}).setdefault("clients", [])
            inbound["settings"]["clients"] = [c for c in clients if str(c.get("email")) not in email_set]
            return {"removed_users": len(emails)}
        raise RuntimeError(f"inbound {tag} missing")

    def list_users(self, tag: str, email: str | None = None) -> list[dict[str, Any]]:
        for inbound in self._inbounds:
            if inbound.get("tag") != tag:
                continue
            users = inbound.get("settings", {}).get("clients", [])
            if email:
                return [u for u in users if str(u.get("email")) == email]
            return deepcopy(users)
        return []

    def list_outbounds(self) -> list[dict[str, Any]]:
        return deepcopy(self._outbounds)

    def add_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        for outbound in outbounds:
            tag = outbound.get("tag")
            self._outbounds = [row for row in self._outbounds if row.get("tag") != tag]
            self._outbounds.append(deepcopy(outbound))
        return {"added": len(outbounds)}

    def edit_outbounds(self, outbounds: list[dict[str, Any]]) -> dict[str, Any]:
        return self.add_outbounds(outbounds)

    def remove_outbounds(self, tags: list[str]) -> dict[str, Any]:
        tagset = set(tags)
        self._outbounds = [row for row in self._outbounds if row.get("tag") not in tagset]
        return {"removed": len(tags)}

    def list_rules(self) -> list[dict[str, Any]]:
        return deepcopy(self._rules)

    def add_rules(self, rules: list[dict[str, Any]], *, should_append: bool = True) -> dict[str, Any]:
        if not should_append:
            self._rules = []
        self._rules.extend(deepcopy(rules))
        return {"added": len(rules)}

    def edit_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        tag = rule.get("tag")
        for idx, current in enumerate(self._rules):
            if current.get("tag") == tag:
                self._rules[idx] = deepcopy(rule)
                return {"updated": 1}
        self._rules.append(deepcopy(rule))
        return {"updated": 1}

    def remove_rules(self, tags: list[str]) -> dict[str, Any]:
        tagset = set(tags)
        self._rules = [row for row in self._rules if row.get("tag") not in tagset]
        return {"removed": len(tags)}

    def block_source_ips(self, source_ips: list[str], **kwargs) -> dict[str, Any]:
        return {"blocked": source_ips}

    def import_config(self, config: dict[str, Any], path: str | None = None) -> dict[str, Any]:
        return {"imported": True, "path": path}

    def online_all(self, emails: list[str] | None = None) -> dict[str, Any]:
        return {"users": [{"email": e, "ips": self._ips.get(e, [])} for e in (emails or self._online)]}
