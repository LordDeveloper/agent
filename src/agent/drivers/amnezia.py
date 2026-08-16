from copy import deepcopy
from typing import Any

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.wireguard import WireGuardDriver


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
        body.setdefault("obfuscation", {})
        return super().create_interface(body)

    def add_peer(self, interface_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        peer = super().add_peer(interface_id, payload)
        if payload.get("obfuscation"):
            peer["obfuscation"] = deepcopy(payload["obfuscation"])
            self.update_peer(interface_id, str(peer["id"]), peer)
        return peer

    def peer_config(self, interface_id: int | str, peer_id: str, endpoint_host: str = "127.0.0.1") -> str:
        base = super().peer_config(interface_id, peer_id, endpoint_host)
        iface = self.get_interface(interface_id)
        peer = next(
            (p for p in iface.get("peers", []) if str(p.get("id")) == peer_id or str(p.get("email")) == peer_id),
            {},
        )
        obf = {**iface.get("obfuscation", {}), **(peer.get("obfuscation") or {})}
        if not obf:
            return base
        extra = [f"{k} = {v}" for k, v in obf.items() if v is not None]
        if "[Interface]" in base:
            head, tail = base.split("[Interface]", 1)
            iface_block, rest = tail.split("\n\n", 1) if "\n\n" in tail else (tail, "")
            iface_block = iface_block.rstrip() + "\n" + "\n".join(extra) + "\n"
            return head + "[Interface]" + iface_block + ("\n" + rest if rest else "")
        return base + "\n# Amnezia obfuscation\n" + "\n".join(extra) + "\n"
