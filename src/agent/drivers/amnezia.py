from copy import deepcopy
from typing import Any

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.wireguard import WireGuardDriver
from agent.support.amnezia_obf import (
    fill_amnezia_obfuscation,
    obfuscation_conf_lines,
    obfuscation_is_complete,
)


class AmneziaDriver(WireGuardDriver):
    key = "amnezia"
    label = "AmneziaWG"
    _protocol = "amnezia"

    def __init__(self, settings: AgentSettings, audit: AuditLog, store: Store):
        super().__init__(settings, audit, store)

    def capabilities(self) -> list[str]:
        return super().capabilities() + ["amnezia_obfuscation"]

    def create_interface(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = deepcopy(payload)
        body["obfuscation"] = fill_amnezia_obfuscation(body.get("obfuscation"))
        return super().create_interface(body)

    def update_interface(self, interface_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        body = deepcopy(payload)
        current = super().get_interface(interface_id)
        incoming = body.get("obfuscation") if isinstance(body.get("obfuscation"), dict) else None
        if incoming:
            merged = {**(current.get("obfuscation") or {}), **incoming}
        else:
            merged = current.get("obfuscation")
        body["obfuscation"] = fill_amnezia_obfuscation(merged)
        return super().update_interface(interface_id, body)

    def add_peer(self, interface_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        peer = super().add_peer(interface_id, payload)
        if payload.get("obfuscation"):
            # Never re-push the full peer (would risk key churn); only attach obfuscation.
            peer["obfuscation"] = deepcopy(payload["obfuscation"])
            self.update_peer(
                interface_id,
                str(peer["id"]),
                {"obfuscation": deepcopy(payload["obfuscation"])},
            )
        return peer

    def _ensure_obfuscation(self, iface: dict[str, Any], *, apply: bool) -> dict[str, Any]:
        current = iface.get("obfuscation") if isinstance(iface.get("obfuscation"), dict) else {}
        if obfuscation_is_complete(current):
            iface["obfuscation"] = fill_amnezia_obfuscation(current)
            return iface

        iface["obfuscation"] = fill_amnezia_obfuscation(current)
        iface_id = iface.get("id")
        if iface_id is not None:
            self.store.put_doc(self.key, self._kind, str(iface_id), iface)
        if apply:
            self._bring_up(iface)
        return iface

    def _render_conf(self, iface: dict[str, Any]) -> str:
        self._ensure_obfuscation(iface, apply=False)
        return super()._render_conf(iface)

    def peer_config(self, interface_id: int | str, peer_id: str, endpoint_host: str = "127.0.0.1") -> str:
        iface = self.get_interface(interface_id)
        incomplete = not obfuscation_is_complete(iface.get("obfuscation"))
        self._ensure_obfuscation(iface, apply=incomplete)
        base = super().peer_config(interface_id, peer_id, endpoint_host)
        peer = next(
            (p for p in iface.get("peers", []) if str(p.get("id")) == peer_id or str(p.get("email")) == peer_id),
            {},
        )
        obf = {**(iface.get("obfuscation") or {}), **(peer.get("obfuscation") or {})}
        extra = obfuscation_conf_lines(obf)
        needle = "DNS = 1.1.1.1\n"
        if extra and needle in base:
            return base.replace(needle, needle + "\n".join(extra) + "\n", 1)
        if extra and "[Interface]" in base:
            head, tail = base.split("[Interface]", 1)
            iface_block, rest = tail.split("\n\n", 1) if "\n\n" in tail else (tail, "")
            iface_block = iface_block.rstrip() + "\n" + "\n".join(extra) + "\n"
            return head + "[Interface]" + iface_block + ("\n" + rest if rest else "")
        return base
