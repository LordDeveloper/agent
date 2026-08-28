from __future__ import annotations

import ipaddress
import shutil
import subprocess
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.base import CoreDriver
from agent.errors import AgentError
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support import normalize_peer, record_is_enabled
from agent.support.config_validate import validate_wg_conf_stripped, validate_wg_iface
from agent.support.process import run

_ONLINE_HANDSHAKE_SECONDS = 180
_IP_WINDOW_SECONDS = 600
_IP_LOG_LIMIT = 50


def endpoint_host(endpoint: str | None) -> str | None:
    if not endpoint or endpoint in ("(none)", ""):
        return None
    raw = str(endpoint).strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end > 0:
            return raw[1:end] or None
    if raw.count(":") == 1:
        return raw.rsplit(":", 1)[0].strip() or None
    return raw or None


def _parse_ip_log(item: Any) -> tuple[str | None, int]:
    if isinstance(item, str) and item.strip():
        return item.strip(), 0
    if isinstance(item, dict):
        ip = str(item.get("ip") or item.get("host") or "").strip()
        try:
            seen = int(item.get("seen_at") or 0)
        except (TypeError, ValueError):
            seen = 0
        return (ip or None), seen
    return None, 0


def remember_peer_ip(peer: dict[str, Any], host: str | None, *, now: int | None = None, limit: int = _IP_LOG_LIMIT) -> None:
    ip = endpoint_host(host)
    if not ip:
        return

    stamp = int(now or time.time())
    logs: list[dict[str, Any]] = []
    found = False
    for item in list(peer.get("ip_logs") or []):
        current, seen = _parse_ip_log(item)
        if not current:
            continue
        if current == ip:
            logs.append({"ip": current, "seen_at": stamp})
            found = True
            continue
        logs.append({"ip": current, "seen_at": seen or stamp})
    if not found:
        logs.append({"ip": ip, "seen_at": stamp})
    peer["ip_logs"] = logs[-limit:]


def recent_peer_ips(
    peer: dict[str, Any],
    *,
    window: int = _IP_WINDOW_SECONDS,
    now: int | None = None,
) -> list[str]:
    stamp = int(now or time.time())
    ips: list[str] = []
    for item in peer.get("ip_logs") or []:
        ip, seen = _parse_ip_log(item)
        if not ip:
            continue
        if seen == 0 or (stamp - seen) <= window:
            if ip not in ips:
                ips.append(ip)
    live = endpoint_host(peer.get("endpoint")) if peer.get("online") else None
    if live and live not in ips:
        ips.insert(0, live)
    return ips


def _wg_keypair(cli: str = "wg") -> tuple[str, str]:
    try:
        priv = subprocess.run([cli, "genkey"], capture_output=True, text=True, timeout=5, check=True)
        private = priv.stdout.strip()
        pub = subprocess.run([cli, "pubkey"], input=private, capture_output=True, text=True, timeout=5, check=True)
        return private, pub.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        token = uuid.uuid4().hex
        return token, uuid.uuid4().hex


def _next_ip(subnet: str, used: set[str]) -> str:
    network = ipaddress.ip_network(subnet, strict=False)
    for host in network.hosts():
        ip = str(host)
        if ip not in used:
            return ip
    raise AgentError("VALIDATION_ERROR", "No free IPs in subnet")


def _peer_change_needs_wg_apply(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """True when live WireGuard peer config must change (not just egress metadata)."""
    wg_keys = (
        "public_key",
        "allowed_ips",
        "persistent_keepalive",
        "address",
        "private_key",
        "preshared_key",
    )
    for key in wg_keys:
        if before.get(key) != after.get(key):
            return True
    if record_is_enabled(before) != record_is_enabled(after):
        return True
    return False


def accumulate_transfer(
    peer: dict[str, Any],
    incoming: int,
    outgoing: int,
    handshake_at: int = 0,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """
    WireGuard keeps rx/tx in kernel memory; after reboot counters restart at 0.
    Persist cumulative totals and last-seen raw counters.
    """
    prev_in = int(peer.get("_incoming", 0) or 0)
    prev_out = int(peer.get("_outgoing", 0) or 0)
    total_in = int(peer.get("incoming", 0) or 0)
    total_out = int(peer.get("outgoing", 0) or 0)

    delta_in = incoming if incoming < prev_in else incoming - prev_in
    delta_out = outgoing if outgoing < prev_out else outgoing - prev_out

    peer["incoming"] = total_in + delta_in
    peer["outgoing"] = total_out + delta_out
    peer["_incoming"] = int(incoming)
    peer["_outgoing"] = int(outgoing)

    if endpoint and endpoint not in ("(none)", ""):
        peer["endpoint"] = endpoint
        remember_peer_ip(peer, endpoint)

    if handshake_at > 0:
        peer["handshake_at"] = datetime.fromtimestamp(handshake_at, tz=timezone.utc).isoformat()
        peer["online"] = (time.time() - handshake_at) < _ONLINE_HANDSHAKE_SECONDS
    else:
        peer["online"] = False

    return peer


class WireGuardDriver(CoreDriver):
    key = "wireguard"
    label = "WireGuard"
    _kind = "interface"
    _protocol = "wireguard"

    def __init__(self, settings: AgentSettings, audit: AuditLog, store: Store):
        self.settings = settings
        self.audit = audit
        self.store = store

    def capabilities(self) -> list[str]:
        return [
            "peers",
            "online_clients",
            "client_traffic",
            "ip_logs",
            "backup_restore",
            "peer_egress_routing",
        ]

    def installed(self) -> bool:
        return self._cli_bin() is not None

    def running(self) -> bool:
        return self.installed()

    def version(self) -> str | None:
        cli = self._cli_bin()
        if not cli:
            return None
        try:
            result = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=5, check=False)
            return (result.stdout or result.stderr).strip() or None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def install(self) -> dict[str, Any]:
        from agent.ops import install_amnezia, install_wireguard

        return install_amnezia() if self.key == "amnezia" else install_wireguard()

    def enable(self) -> dict[str, Any]:
        results = []
        for iface in self.list_interfaces():
            results.append(self._bring_up(iface))
        return {"enabled": True, "interfaces": results}

    def disable(self) -> dict[str, Any]:
        results = []
        for iface in self.list_interfaces():
            results.append(self._bring_down(iface))
        return {"enabled": False, "interfaces": results}

    def restart(self) -> dict[str, Any]:
        self.disable()
        return self.enable()

    def peer_ips(self, email: str) -> list[str]:
        self.sync_peer_stats()
        for iface in self.list_interfaces():
            for peer in iface.get("peers", []):
                if str(peer.get("email")) == email or str(peer.get("id")) == email:
                    return recent_peer_ips(peer)
        return []

    def diagnose_address(self, address: str) -> dict[str, Any]:
        """Full interface/peer/routing diagnostic for a peer AllowedIP address."""
        from agent.support.peer_diagnose import diagnose_peer_address

        self.sync_peer_stats()
        return diagnose_peer_address(
            self.store,
            self.key,
            address,
            peer_dump_fn=self._peer_dump,
            interface_is_up_fn=self._interface_is_up,
        )

    def clear_peer_ips(self, email: str) -> bool:
        changed = False
        for iface in self.list_interfaces():
            for peer in iface.get("peers", []):
                if str(peer.get("email")) == email or str(peer.get("id")) == email:
                    peer["ip_logs"] = []
                    changed = True
            if changed:
                self.store.put_doc(self.key, self._kind, str(iface.get("id")), iface)
        return True

    def reset_peer_traffic(self, interface_id: int | str, peer_id: str) -> dict[str, Any]:
        """Zero billing totals and re-baseline kernel counters so the next sync delta is 0."""
        self.sync_peer_stats()
        iface = self.get_interface(interface_id)
        for peer in iface.get("peers", []):
            if str(peer.get("id")) != str(peer_id) and str(peer.get("email")) != str(peer_id):
                continue
            live = self._peer_dump(str(iface.get("name") or "")).get(str(peer.get("public_key") or ""), {})
            return self.update_peer(
                interface_id,
                peer_id,
                {
                    "incoming": 0,
                    "outgoing": 0,
                    "_incoming": int(live.get("incoming", peer.get("_incoming", 0)) or 0),
                    "_outgoing": int(live.get("outgoing", peer.get("_outgoing", 0)) or 0),
                },
            )
        raise AgentError("CLIENT_NOT_FOUND", f"Peer [{peer_id}] not found", 404)

    def backup(self) -> dict[str, Any]:
        return {"interfaces": self.list_interfaces(), "core": self.key}

    def restore(self, payload: dict[str, Any]) -> bool:
        interfaces = list(payload.get("interfaces") or [])
        for existing in list(self.list_interfaces()):
            self.delete_interface(existing.get("id"))
        for row in interfaces:
            peers = list(row.get("peers") or [])
            body = {k: v for k, v in row.items() if k != "peers"}
            iface = self.create_interface(body)
            for peer in peers:
                self.add_peer(iface["id"], peer)
        self.audit.record("restore", self.key)
        return True

    # --- interface / peer CRUD ---
    def list_interfaces(self) -> list[dict[str, Any]]:
        return self.store.list_docs(self.key, self._kind)

    def get_interface(self, interface_id: int | str) -> dict[str, Any]:
        by_id = self.store.get_doc(self.key, self._kind, str(interface_id))
        if by_id:
            return by_id
        for iface in self.list_interfaces():
            if iface.get("name") == interface_id or str(iface.get("id")) == str(interface_id):
                return iface
        raise AgentError("CONFIG_NOT_FOUND", f"Interface [{interface_id}] not found", 404)

    def create_interface(self, payload: dict[str, Any]) -> dict[str, Any]:
        iface_id = payload.get("id")
        if iface_id is None:
            existing_ids = []
            for row in self.list_interfaces():
                try:
                    existing_ids.append(int(row.get("id", 0)))
                except (TypeError, ValueError):
                    continue
            iface_id = max(existing_ids + [0]) + 1

        name = payload.get("name") or f"{'awg' if self.key == 'amnezia' else 'wg'}{iface_id}"
        private_key = payload.get("private_key")
        cli = self._cli_bin() or "wg"
        if not private_key:
            private_key, public_key = _wg_keypair(cli)
        else:
            public_key = payload.get("public_key") or ""
            if not public_key:
                try:
                    pub = subprocess.run(
                        [cli, "pubkey"],
                        input=private_key,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=True,
                    )
                    public_key = pub.stdout.strip()
                except Exception:
                    public_key = ""

        iface = {
            "id": iface_id,
            "name": name,
            "listen_port": int(payload.get("listen_port", 51820)),
            "subnet": self._unique_subnet(payload.get("subnet"), exclude_id=iface_id),
            "private_key": private_key,
            "public_key": public_key,
            "peers": list(payload.get("peers") or []),
        }
        if payload.get("obfuscation") is not None:
            iface["obfuscation"] = payload["obfuscation"]

        self.store.put_doc(self.key, self._kind, str(iface_id), iface)
        self.audit.record("create", f"{self.key}/interface/{iface_id}")
        up = self._bring_up(iface)
        if not up.get("ok"):
            self.store.delete_doc(self.key, self._kind, str(iface_id))
            self._conf_file(iface["name"]).unlink(missing_ok=True)
            detail = up.get("stderr") or up.get("message") or "wg-quick up failed"
            raise AgentError("VALIDATION_ERROR", f"WireGuard interface failed to start: {detail}")
        return iface

    def _unique_subnet(self, requested: Any, *, exclude_id: int | str | None = None) -> str:
        used = {
            str(row.get("subnet") or "")
            for row in self.list_interfaces()
            if exclude_id is None or str(row.get("id")) != str(exclude_id)
        }
        wanted = str(requested or "").strip()
        if wanted and wanted not in used:
            return wanted
        base = 112 if self.key == "amnezia" else 80
        for second in range(base, base + 16):
            for third in range(256):
                cidr = f"10.{second}.{third}.0/24"
                if cidr not in used:
                    return cidr
        raise AgentError("VALIDATION_ERROR", "No free subnet for WireGuard/Amnezia interface")

    def update_interface(self, interface_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        iface = self.get_interface(interface_id)
        previous = deepcopy(iface)
        iface.update({k: v for k, v in payload.items() if k not in ("id",)})
        self._validate_before_apply(iface)
        self.store.put_doc(self.key, self._kind, str(iface.get("id")), iface)
        try:
            self._apply_live(iface)
        except AgentError:
            self.store.put_doc(self.key, self._kind, str(previous.get("id")), previous)
            raise
        return iface

    def delete_interface(self, interface_id: int | str) -> bool:
        iface = self.get_interface(interface_id)
        self._bring_down(iface)
        self._conf_file(iface["name"]).unlink(missing_ok=True)
        if not self.store.delete_doc(self.key, self._kind, str(iface.get("id"))):
            raise AgentError("CONFIG_NOT_FOUND", f"Interface [{interface_id}] not found", 404)
        self.audit.record("delete", f"{self.key}/interface/{interface_id}")
        return True

    def add_peer(self, interface_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        iface = self.get_interface(interface_id)
        peer = normalize_peer(payload)
        peer.setdefault("id", str(uuid.uuid4()))
        peer.setdefault("email", peer.get("name") or str(peer["id"])[:8])
        used_ips = {p.get("address") for p in iface.get("peers", [])}
        peer.setdefault("address", _next_ip(iface["subnet"], used_ips))
        cli = self._cli_bin() or "wg"
        priv, pub = _wg_keypair(cli)
        peer.setdefault("private_key", priv)
        peer.setdefault("public_key", payload.get("public_key") or pub)
        peer.setdefault("allowed_ips", f"{peer['address']}/32")
        peer.setdefault("incoming", 0)
        peer.setdefault("outgoing", 0)
        peer.setdefault("_incoming", 0)
        peer.setdefault("_outgoing", 0)
        peer.setdefault("handshake_at", None)
        peer.setdefault("online", False)
        peer.setdefault("ip_logs", [])
        peer.setdefault("max_connection", 0)
        peer.setdefault("persistent_keepalive", 25)

        if not record_is_enabled(peer):
            # Keep record disabled without applying to live interface.
            pass

        for existing in iface.get("peers", []):
            if str(existing.get("id")) == str(peer["id"]) or str(existing.get("email")) == str(peer.get("email")):
                return self.update_peer(interface_id, str(existing.get("id") or peer["id"]), peer)

        iface.setdefault("peers", []).append(peer)
        self.update_interface(interface_id, iface)
        self.audit.record("create", f"{self.key}/peer/{peer['id']}")
        return peer

    def update_peer(self, interface_id: int | str, peer_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        iface = self.get_interface(interface_id)
        for idx, peer in enumerate(iface.get("peers", [])):
            if str(peer.get("id")) == peer_id or str(peer.get("email")) == peer_id:
                before = deepcopy(peer)
                merged = deepcopy(peer)
                normalized = normalize_peer(payload)
                # Preserve traffic counters unless explicitly reset in payload.
                for key, value in normalized.items():
                    merged[key] = value
                if "exit_interface" in payload:
                    if "exit_interface" in normalized:
                        merged["exit_interface"] = normalized["exit_interface"]
                    else:
                        merged.pop("exit_interface", None)
                iface["peers"][idx] = merged

                # exit_interface / metadata-only updates must not wg syncconf + nft flush.
                if _peer_change_needs_wg_apply(before, merged):
                    self.update_interface(interface_id, iface)
                else:
                    self.store.put_doc(self.key, self._kind, str(iface.get("id")), iface)
                    self._sync_peer_egress()
                return merged
        raise AgentError("CLIENT_NOT_FOUND", f"Peer [{peer_id}] not found", 404)

    def delete_peer(self, interface_id: int | str, peer_id: str) -> bool:
        iface = self.get_interface(interface_id)
        peers = iface.get("peers", [])
        filtered = [p for p in peers if str(p.get("id")) != peer_id and str(p.get("email")) != peer_id]
        if len(filtered) == len(peers):
            raise AgentError("CLIENT_NOT_FOUND", f"Peer [{peer_id}] not found", 404)
        iface["peers"] = filtered
        self.update_interface(interface_id, iface)
        self.audit.record("delete", f"{self.key}/peer/{peer_id}")
        return True

    def peer_config(self, interface_id: int | str, peer_id: str, endpoint_host: str = "127.0.0.1") -> str:
        iface = self.get_interface(interface_id)
        peer = None
        for row in iface.get("peers", []):
            if str(row.get("id")) == peer_id or str(row.get("email")) == peer_id:
                peer = row
                break
        if peer is None:
            raise AgentError("CLIENT_NOT_FOUND", f"Peer [{peer_id}] not found", 404)

        lines = [
            "[Interface]",
            f"PrivateKey = {peer.get('private_key')}",
            f"Address = {peer.get('address')}/32",
            "DNS = 1.1.1.1",
            "",
            "[Peer]",
            f"PublicKey = {iface.get('public_key')}",
            f"Endpoint = {endpoint_host}:{iface.get('listen_port')}",
            "AllowedIPs = 0.0.0.0/0",
            f"PersistentKeepalive = {peer.get('persistent_keepalive', 25)}",
            "",
        ]
        return "\n".join(lines)

    def usage_snapshot(self) -> UsageSnapshotModel:
        self.sync_peer_stats()
        rows: list[InboundUsageModel] = []
        for iface in self.list_interfaces():
            clients = []
            for peer in iface.get("peers", []):
                if not record_is_enabled(peer):
                    continue
                clients.append(
                    ClientUsageModel(
                        id=str(peer.get("id")),
                        email=peer.get("email"),
                        # Billing must use cumulative totals, never raw kernel counters.
                        incoming=int(peer.get("incoming", 0) or 0),
                        outgoing=int(peer.get("outgoing", 0) or 0),
                        inbound_id=iface.get("id"),
                    )
                )
            rows.append(
                InboundUsageModel(
                    id=iface.get("id"),
                    tag=str(iface.get("name") or f"wg{iface.get('id')}"),
                    incoming=sum(c.incoming for c in clients),
                    outgoing=sum(c.outgoing for c in clients),
                    clients=clients,
                )
            )
        return UsageSnapshotModel(inbounds=rows)

    def online_users(self) -> list[str]:
        self.sync_peer_stats()
        online: list[str] = []
        for iface in self.list_interfaces():
            for peer in iface.get("peers", []):
                if peer.get("online") and record_is_enabled(peer):
                    online.append(str(peer.get("email") or peer.get("id")))
        return online

    def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import online_traffic_from_snapshot

        return online_traffic_from_snapshot(self)

    def sync_peer_stats(self) -> None:
        for iface in self.list_interfaces():
            live = self._peer_dump(str(iface.get("name") or ""))
            if not live and not iface.get("peers"):
                continue

            changed = False
            for peer in iface.get("peers", []):
                pub = str(peer.get("public_key") or "")
                stats = live.get(pub)
                if stats is None:
                    if peer.get("online"):
                        peer["online"] = False
                        changed = True
                    continue

                before = (
                    peer.get("incoming"),
                    peer.get("outgoing"),
                    peer.get("_incoming"),
                    peer.get("_outgoing"),
                    peer.get("handshake_at"),
                    peer.get("online"),
                    peer.get("endpoint"),
                    str(peer.get("ip_logs") or []),
                )
                accumulate_transfer(
                    peer,
                    incoming=stats["incoming"],
                    outgoing=stats["outgoing"],
                    handshake_at=stats["handshake_at"],
                    endpoint=stats.get("endpoint"),
                )
                after = (
                    peer.get("incoming"),
                    peer.get("outgoing"),
                    peer.get("_incoming"),
                    peer.get("_outgoing"),
                    peer.get("handshake_at"),
                    peer.get("online"),
                    peer.get("endpoint"),
                    str(peer.get("ip_logs") or []),
                )
                if before != after:
                    changed = True

            if changed:
                self.store.put_doc(self.key, self._kind, str(iface.get("id")), iface)

    def _cli_bin(self) -> str | None:
        if self.key == "amnezia":
            return shutil.which("awg") or shutil.which("wg")
        return shutil.which("wg")

    def _quick_bin(self) -> str | None:
        if self.key == "amnezia":
            return shutil.which("awg-quick") or shutil.which("wg-quick")
        return shutil.which("wg-quick")

    def _conf_file(self, name: str) -> Path:
        return self._config_dir() / f"{name}.conf"

    def _peer_dump(self, iface_name: str) -> dict[str, dict[str, Any]]:
        if not iface_name:
            return {}
        cli = self._cli_bin()
        if not cli:
            return {}
        try:
            result = subprocess.run(
                [cli, "show", iface_name, "dump"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}
        if result.returncode != 0 or not result.stdout.strip():
            return {}

        peers: dict[str, dict[str, Any]] = {}
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            public_key = parts[0]
            endpoint = parts[2] if len(parts) > 2 else ""
            allowed_ips = parts[3] if len(parts) > 3 else ""
            try:
                handshake_at = int(parts[4] or 0)
                transfer_rx = int(parts[5] or 0)
                transfer_tx = int(parts[6] or 0)
            except ValueError:
                continue
            peers[public_key] = {
                "incoming": transfer_tx,
                "outgoing": transfer_rx,
                "handshake_at": handshake_at,
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
                "public_key": public_key,
            }
        return peers

    def _config_dir(self) -> Path:
        if self.key == "amnezia":
            return Path(self.settings.amnezia.config_dir)
        return Path(self.settings.wireguard.config_dir)

    def _interface_lines(self, iface: dict[str, Any]) -> list[str]:
        address = iface["subnet"]
        if "/" not in str(address):
            address = f"{address}/16"
        # Prefer host .1 in subnet for server address.
        try:
            network = ipaddress.ip_network(address, strict=False)
            host = str(next(network.hosts()))
            address = f"{host}/{network.prefixlen}"
        except ValueError:
            pass

        lines = [
            "[Interface]",
            f"Address = {address}",
            f"ListenPort = {iface['listen_port']}",
            f"PrivateKey = {iface['private_key']}",
        ]
        obf = iface.get("obfuscation") or {}
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            if obf.get(key) is not None:
                lines.append(f"{key} = {obf[key]}")

        # Re-apply policy routing whenever wg-quick brings the interface up (survives reboot).
        from agent.support.peer_egress import apply_script_path

        script = apply_script_path(self.settings.data_dir)
        lines.append(f"PostUp = {script.as_posix()} >/dev/null 2>&1 || true")
        lines.append("")
        return lines

    def _render_conf(self, iface: dict[str, Any]) -> str:
        lines = self._interface_lines(iface)
        for peer in iface.get("peers", []):
            if not record_is_enabled(peer):
                continue
            lines.extend(
                [
                    "[Peer]",
                    f"PublicKey = {peer.get('public_key')}",
                    f"AllowedIPs = {peer.get('allowed_ips')}",
                    f"PersistentKeepalive = {peer.get('persistent_keepalive', 25)}",
                    "",
                ]
            )
        return "\n".join(lines)

    def _validate_before_apply(self, iface: dict[str, Any]) -> None:
        validate_wg_iface(iface)
        quick = self._quick_bin()
        if not quick:
            return
        conf_text = self._render_conf(iface)
        validate_wg_conf_stripped(
            conf_text,
            quick_bin=quick,
            config_dir=self._config_dir(),
        )

    def _interface_is_up(self, name: str) -> bool:
        cli = self._cli_bin()
        if not cli or not name:
            return False
        result = run([cli, "show", name], check=False, timeout=5)
        return result.returncode == 0

    def _sync_conf(self, iface: dict[str, Any]) -> None:
        self._config_dir().mkdir(parents=True, exist_ok=True)
        self._conf_file(iface["name"]).write_text(self._render_conf(iface), encoding="utf-8")

    def _bring_up(self, iface: dict[str, Any]) -> dict[str, Any]:
        self._validate_before_apply(iface)
        self._sync_conf(iface)
        quick = self._quick_bin()
        name = iface["name"]
        conf = str(self._conf_file(name))
        if not quick:
            return {"name": name, "ok": False, "message": "wg-quick not found"}
        down = run([quick, "down", conf], check=False)
        up = run([quick, "up", conf], check=False)
        result = {
            "name": name,
            "ok": up.returncode == 0,
            "stderr": (up.stderr or down.stderr or "").strip(),
        }
        if result["ok"]:
            self._sync_peer_egress()
        return result

    def _bring_down(self, iface: dict[str, Any]) -> dict[str, Any]:
        remaining = [
            row
            for row in self.list_interfaces()
            if str(row.get("id")) != str(iface.get("id"))
        ]
        self._sync_peer_egress(remaining)
        quick = self._quick_bin()
        name = iface["name"]
        if not quick:
            return {"name": name, "ok": False, "message": "wg-quick not found"}
        result = run([quick, "down", str(self._conf_file(name))], check=False)
        return {"name": name, "ok": result.returncode == 0, "stderr": (result.stderr or "").strip()}

    def _apply_live(self, iface: dict[str, Any]) -> None:
        self._validate_before_apply(iface)

        cli = self._cli_bin()
        quick = self._quick_bin()
        name = iface["name"]
        conf_path = self._conf_file(name)
        backup = conf_path.read_text(encoding="utf-8") if conf_path.exists() else None

        if not cli or not quick:
            self._sync_conf(iface)
            self._sync_peer_egress()
            return

        if not self._interface_is_up(name):
            self._sync_conf(iface)
            self._sync_peer_egress()
            return

        try:
            self._sync_conf(iface)
            strip = run([quick, "strip", str(conf_path)], check=False)
            if strip.returncode != 0 or not strip.stdout:
                detail = (strip.stderr or strip.stdout or "wg-quick strip failed").strip()
                raise AgentError("VALIDATION_ERROR", f"WireGuard live apply rejected: {detail}")
            sync = run([cli, "syncconf", name, "/dev/stdin"], check=False, input_text=strip.stdout)
            if sync.returncode != 0:
                detail = (sync.stderr or sync.stdout or "wg syncconf failed").strip()
                raise AgentError("VALIDATION_ERROR", f"WireGuard live apply rejected: {detail}")
            self._sync_peer_egress()
        except AgentError:
            if backup is not None:
                conf_path.write_text(backup, encoding="utf-8")
            else:
                conf_path.unlink(missing_ok=True)
            raise

    def _sync_peer_egress(self, interfaces: list[dict[str, Any]] | None = None) -> None:
        try:
            from agent.support.peer_egress import reconcile_core_egress

            rows = interfaces if interfaces is not None else self.list_interfaces()
            reconcile_core_egress(
                self.store,
                self.key,
                rows,
                data_dir=self.settings.data_dir,
            )
        except Exception:
            from agent.logutil import get_logger

            get_logger("wireguard").exception("peer egress reconcile failed core=%s", self.key)