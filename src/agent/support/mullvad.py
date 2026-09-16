from __future__ import annotations

"""Mullvad WireGuard exit tunnels for region nodes.

Existing host interfaces (de, usa, sw, …) are adopted when their live peer
matches a Mullvad relay. Fallback only rewrites Endpoint/PublicKey so the
iface name — and panel exit_interface — stay unchanged.
"""

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

import httpx

from agent.db import Store
from agent.errors import AgentError
from agent.logutil import get_logger
from agent.support.node_probe import _curl_probe
from agent.support.peer_egress import normalize_exit_interface
from agent.support.process import run

log = get_logger("mullvad")

Runner = Callable[..., Any]
FetchRelays = Callable[[], list[dict[str, Any]]]
TcpProbe = Callable[[str, int], tuple[bool, int | None]]

RELAYS_URL = "https://api.mullvad.net/www/relays/wireguard"
WG_PORT = 51820
HANDSHAKE_MAX_AGE = 180
TCP_TIMEOUT = 1.5
CACHE_TTL = 3600.0
KIND_SETTINGS = "settings"
KIND_LOCATION = "location"
CORE = "mullvad"
SETTINGS_ID = "account"
_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")

# Host iface names already in use on this deployment (not always ISO).
IFACE_FOR_COUNTRY: dict[str, str] = {
    "us": "usa",
    "gb": "uk",
    "se": "sw",
    "mx": "mx",
}
COUNTRY_FOR_IFACE: dict[str, str] = {iface: code for code, iface in IFACE_FOR_COUNTRY.items()}


def preferred_iface(country_code: str) -> str:
    code = str(country_code or "").strip().lower()
    return IFACE_FOR_COUNTRY.get(code, code)


def country_for_iface_name(iface: str) -> str | None:
    name = str(iface or "").strip().lower()
    if not name:
        return None
    if name in COUNTRY_FOR_IFACE:
        return COUNTRY_FOR_IFACE[name]
    if re.fullmatch(r"[a-z]{2}", name):
        return name
    return None


def mask_key(value: str) -> str:
    text = str(value or "").strip()
    if len(text) < 12:
        return "********" if text else ""
    return f"{text[:4]}…{text[-4:]}"


def parse_wg_conf(text: str) -> dict[str, Any]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section = ""
    current: dict[str, str] | None = None
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current = {}
                peers.append(current)
            else:
                current = None
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if section == "interface":
            interface[key] = value
        elif section == "peer" and current is not None:
            current[key] = value
    return {"interface": interface, "peers": peers}


def dump_wg_conf(parsed: dict[str, Any]) -> str:
    interface = dict(parsed.get("interface") or {})
    peers = [dict(peer) for peer in (parsed.get("peers") or []) if isinstance(peer, dict)]
    iface_order = ("PrivateKey", "Address", "DNS", "Table", "ListenPort", "FwMark", "MTU")
    peer_order = ("PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive")

    lines = ["[Interface]"]
    seen: set[str] = set()
    for key in iface_order:
        if key in interface:
            lines.append(f"{key} = {interface[key]}")
            seen.add(key)
    for key, value in interface.items():
        if key not in seen:
            lines.append(f"{key} = {value}")
    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        seen_peer: set[str] = set()
        for key in peer_order:
            if key in peer:
                lines.append(f"{key} = {peer[key]}")
                seen_peer.add(key)
        for key, value in peer.items():
            if key not in seen_peer:
                lines.append(f"{key} = {value}")
    lines.append("")
    return "\n".join(lines)


def _relays_cache() -> dict[str, Any]:
    return {"at": 0.0, "rows": []}


_CACHE = _relays_cache()


def fetch_relays(*, timeout: float = 20.0, force: bool = False) -> list[dict[str, Any]]:
    now = time.time()
    if not force and _CACHE["rows"] and (now - float(_CACHE["at"])) < CACHE_TTL:
        return list(_CACHE["rows"])

    try:
        response = httpx.get(RELAYS_URL, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        if _CACHE["rows"]:
            log.warning("mullvad catalog refresh failed; using cache: %s", exc)
            return list(_CACHE["rows"])
        raise AgentError("UPSTREAM_ERROR", f"Failed to fetch Mullvad relays: {exc}", 502) from exc

    if not isinstance(payload, list):
        raise AgentError("UPSTREAM_ERROR", "Mullvad relays response is not a list", 502)

    rows = [row for row in payload if isinstance(row, dict)]
    _CACHE["at"] = now
    _CACHE["rows"] = rows
    return list(rows)


def active_relays(relays: list[dict[str, Any]], country_code: str) -> list[dict[str, Any]]:
    code = str(country_code or "").strip().lower()
    out: list[dict[str, Any]] = []
    for row in relays:
        if str(row.get("country_code") or "").strip().lower() != code:
            continue
        if row.get("active") is False:
            continue
        if str(row.get("type") or "wireguard").strip().lower() not in {"", "wireguard"}:
            continue
        pubkey = str(row.get("pubkey") or "").strip()
        ipv4 = str(row.get("ipv4_addr_in") or "").strip()
        if not pubkey or not ipv4:
            continue
        out.append(row)
    return out


def group_locations(relays: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in relays:
        if row.get("active") is False:
            continue
        code = str(row.get("country_code") or "").strip().lower()
        if not code:
            continue
        bucket = grouped.setdefault(
            code,
            {
                "country_code": code,
                "country_name": str(row.get("country_name") or code).strip(),
                "iface": preferred_iface(code),
                "relay_count": 0,
                "cities": [],
            },
        )
        if not bucket.get("country_name"):
            bucket["country_name"] = str(row.get("country_name") or code).strip()
        bucket["relay_count"] = int(bucket["relay_count"]) + 1
        city_code = str(row.get("city_code") or "").strip().lower()
        city_name = str(row.get("city_name") or "").strip()
        cities: list[dict[str, str]] = bucket["cities"]
        if city_code and not any(item.get("code") == city_code for item in cities):
            cities.append({"code": city_code, "name": city_name or city_code})
    return sorted(grouped.values(), key=lambda item: str(item.get("country_name") or ""))


def match_relay(
    relays: list[dict[str, Any]],
    *,
    pubkey: str = "",
    endpoint_host: str = "",
) -> dict[str, Any] | None:
    pub = str(pubkey or "").strip()
    host = str(endpoint_host or "").strip()
    if host and ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    for row in relays:
        if pub and str(row.get("pubkey") or "").strip() == pub:
            return row
        ipv4 = str(row.get("ipv4_addr_in") or "").strip()
        if host and ipv4 and host == ipv4:
            return row
    return None


def tcp_probe(host: str, port: int = WG_PORT, *, timeout: float = TCP_TIMEOUT) -> tuple[bool, int | None]:
    host = str(host or "").strip()
    if not host or port <= 0:
        return False, None
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = max(1, int(round((time.perf_counter() - started) * 1000)))
            return True, latency_ms
    except OSError:
        return False, None


def pick_best_relay(
    relays: list[dict[str, Any]],
    *,
    exclude_hostname: str = "",
    probe: TcpProbe | None = None,
) -> dict[str, Any] | None:
    checker = probe or (lambda host, port: tcp_probe(host, port))
    scored: list[tuple[int, dict[str, Any]]] = []
    skip = str(exclude_hostname or "").strip().lower()

    def _one(row: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
        hostname = str(row.get("hostname") or "").strip().lower()
        if skip and hostname == skip:
            return None
        ipv4 = str(row.get("ipv4_addr_in") or "").strip()
        ok, latency = checker(ipv4, WG_PORT)
        if not ok or latency is None:
            return None
        return latency, row

    workers = min(16, max(1, len(relays)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, row) for row in relays]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                scored.append(result)
    if not scored:
        return None
    scored.sort(key=lambda item: item[0])
    return scored[0][1]


def conf_path(config_dir: str | Path, iface: str) -> Path:
    return Path(config_dir) / f"{iface}.conf"


def read_conf(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return parse_wg_conf(path.read_text(encoding="utf-8"))
    except OSError:
        return None


class MullvadService:
    def __init__(
        self,
        store: Store,
        *,
        config_dir: str | Path = "/etc/wireguard",
        runner: Runner | None = None,
        fetch: FetchRelays | None = None,
        probe: TcpProbe | None = None,
        egress_probe: Callable[..., tuple[bool, str, int | None]] | None = None,
    ) -> None:
        self.store = store
        self.config_dir = Path(config_dir)
        self.runner = runner or run
        self.fetch = fetch or fetch_relays
        self.probe = probe or (lambda host, port: tcp_probe(host, port))
        self.egress_probe = egress_probe or _curl_probe

    def settings(self) -> dict[str, Any]:
        row = self.store.get_doc(CORE, KIND_SETTINGS, SETTINGS_ID) or {}
        private_key = str(row.get("private_key") or "").strip()
        address = str(row.get("address") or "").strip()
        return {
            "private_key": private_key,
            "address": address,
            "has_private_key": bool(private_key),
            "key_preview": mask_key(private_key),
        }

    def save_settings(self, *, private_key: str, address: str | None = None) -> dict[str, Any]:
        key = str(private_key or "").strip()
        if not _WG_KEY_RE.match(key):
            raise AgentError("VALIDATION_ERROR", "Invalid WireGuard private key", 422)
        current = self.store.get_doc(CORE, KIND_SETTINGS, SETTINGS_ID) or {}
        addr = str(address if address is not None else current.get("address") or "").strip()
        if not addr:
            addr = self._discover_address()
        if addr:
            try:
                ipaddress.ip_interface(addr if "/" in addr else f"{addr}/32")
            except ValueError as exc:
                raise AgentError("VALIDATION_ERROR", "Invalid Mullvad tunnel address", 422) from exc
            if "/" not in addr:
                addr = f"{addr}/32"
        payload = {"private_key": key, "address": addr}
        self.store.put_doc(CORE, KIND_SETTINGS, SETTINGS_ID, payload)
        return self.settings()

    def bindings(self) -> list[dict[str, Any]]:
        rows = []
        for row in self.store.list_docs(CORE, KIND_LOCATION):
            if isinstance(row, dict) and str(row.get("country_code") or "").strip():
                rows.append(row)
        return rows

    def binding_for(self, country_code: str) -> dict[str, Any] | None:
        code = str(country_code or "").strip().lower()
        if not code:
            return None
        row = self.store.get_doc(CORE, KIND_LOCATION, code)
        return row if isinstance(row, dict) else None

    def locations(self, *, force: bool = False) -> dict[str, Any]:
        relays = fetch_relays(force=True) if force and self.fetch is fetch_relays else self.fetch()
        self.refresh_bindings(relays)
        bound = {str(row.get("country_code") or "").lower(): row for row in self.bindings()}
        locations = []
        for item in group_locations(relays):
            code = item["country_code"]
            bind = bound.get(code)
            locations.append(
                {
                    **item,
                    "iface": str((bind or {}).get("iface") or item["iface"]),
                    "bound": bind is not None,
                    "adopted": bool((bind or {}).get("adopted")),
                    "hostname": str((bind or {}).get("hostname") or "") or None,
                    "endpoint": str((bind or {}).get("endpoint") or "") or None,
                }
            )
        return {
            "settings": {k: v for k, v in self.settings().items() if k != "private_key"},
            "locations": locations,
        }

    def refresh_bindings(self, relays: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        catalog = relays if relays is not None else self.fetch()
        claimed_ifaces = {
            str(row.get("iface") or "").strip()
            for row in self.bindings()
            if str(row.get("iface") or "").strip()
        }
        claimed_countries = {
            str(row.get("country_code") or "").strip().lower()
            for row in self.bindings()
            if str(row.get("country_code") or "").strip()
        }

        for iface, parsed, live in self._scan_interfaces():
            if iface in claimed_ifaces:
                self._seed_settings_from_conf(parsed)
                continue
            pubkey = ""
            endpoint = ""
            if live:
                pubkey = str(live.get("public_key") or "").strip()
                endpoint = str(live.get("endpoint") or "").strip()
            if not pubkey:
                peers = parsed.get("peers") or []
                if peers:
                    pubkey = str(peers[0].get("PublicKey") or "").strip()
                    endpoint = str(peers[0].get("Endpoint") or "").strip()
            relay = match_relay(catalog, pubkey=pubkey, endpoint_host=endpoint)
            if relay is None:
                continue
            code = str(relay.get("country_code") or "").strip().lower()
            if not code or code in claimed_countries:
                continue
            self._put_binding(
                country_code=code,
                iface=iface,
                relay=relay,
                adopted=True,
            )
            claimed_ifaces.add(iface)
            claimed_countries.add(code)
            self._seed_settings_from_conf(parsed)

        return self.bindings()

    def ensure(self, country_code: str) -> dict[str, Any]:
        code = str(country_code or "").strip().lower()
        if not re.fullmatch(r"[a-z]{2}", code or ""):
            raise AgentError("VALIDATION_ERROR", "country_code must be ISO 3166-1 alpha-2", 422)

        relays = self.fetch()
        self.refresh_bindings(relays)
        candidates = active_relays(relays, code)
        if not candidates:
            raise AgentError("NOT_FOUND", f"No active Mullvad relays for {code}", 404)

        bind = self.binding_for(code)
        iface = str((bind or {}).get("iface") or "").strip() or self._allocate_iface(code)
        normalized = normalize_exit_interface(iface)
        if not normalized:
            raise AgentError("VALIDATION_ERROR", f"Invalid interface name [{iface}]", 422)
        iface = normalized

        current_host = str((bind or {}).get("hostname") or "")
        healthy = False
        if bind and self._iface_up(iface):
            healthy = self._iface_healthy(iface)

        relay = None
        if healthy and bind:
            relay = next((row for row in candidates if str(row.get("hostname") or "") == current_host), None)
        if relay is None:
            exclude = current_host if not healthy else ""
            relay = pick_best_relay(candidates, exclude_hostname=exclude, probe=self.probe)
        if relay is None:
            relay = candidates[0]

        self._apply_relay(iface, relay)
        self._put_binding(country_code=code, iface=iface, relay=relay, adopted=bool((bind or {}).get("adopted")))
        return self._present_binding(self.binding_for(code) or {})

    def fallback(self, country_code: str | None = None) -> dict[str, Any]:
        relays = self.fetch()
        self.refresh_bindings(relays)
        targets = self.bindings()
        if country_code:
            code = str(country_code).strip().lower()
            targets = [row for row in targets if str(row.get("country_code") or "").lower() == code]
            if not targets:
                raise AgentError("NOT_FOUND", f"No Mullvad binding for {code}", 404)

        changed: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        for bind in targets:
            result = self._fallback_one(bind, relays)
            status = result.get("status")
            if status == "changed":
                changed.append(result)
            elif status == "failed":
                failed.append(result)
            else:
                skipped.append(result)
        return {"changed": changed, "skipped": skipped, "failed": failed}

    def status(self) -> dict[str, Any]:
        self.refresh_bindings()
        rows = []
        for bind in self.bindings():
            iface = str(bind.get("iface") or "")
            ok = False
            message = "interface down"
            latency = None
            if iface and self._iface_up(iface):
                ok, message, latency = self.egress_probe(interface=iface, runner=self.runner)
            rows.append(
                {
                    **self._present_binding(bind),
                    "up": self._iface_up(iface) if iface else False,
                    "healthy": ok,
                    "message": message,
                    "latency_ms": latency,
                }
            )
        settings = self.settings()
        settings.pop("private_key", None)
        return {"settings": settings, "tunnels": rows}

    def _fallback_one(self, bind: dict[str, Any], relays: list[dict[str, Any]]) -> dict[str, Any]:
        code = str(bind.get("country_code") or "").strip().lower()
        iface = str(bind.get("iface") or "").strip()
        hostname = str(bind.get("hostname") or "")
        presented = self._present_binding(bind)
        if not iface:
            return {**presented, "status": "failed", "message": "missing iface"}
        if self._iface_up(iface) and self._iface_healthy(iface):
            return {**presented, "status": "ok", "message": "healthy"}

        candidates = active_relays(relays, code)
        relay = pick_best_relay(candidates, exclude_hostname=hostname, probe=self.probe)
        if relay is None:
            message = "no healthy Mullvad relay in country"
            self._put_binding(country_code=code, iface=iface, relay=None, adopted=bool(bind.get("adopted")), extra={"last_error": message})
            return {**presented, "status": "failed", "message": message}
        try:
            self._apply_relay(iface, relay)
            self._put_binding(
                country_code=code,
                iface=iface,
                relay=relay,
                adopted=bool(bind.get("adopted")),
                extra={"last_fallback_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "last_error": ""},
            )
            log.info("mullvad fallback country=%s iface=%s hostname=%s", code, iface, relay.get("hostname"))
            return {
                **self._present_binding(self.binding_for(code) or bind),
                "status": "changed",
                "message": f"switched to {relay.get('hostname')}",
            }
        except AgentError as exc:
            return {**presented, "status": "failed", "message": exc.message}

    def _allocate_iface(self, country_code: str) -> str:
        preferred = preferred_iface(country_code)
        used = {str(row.get("iface") or "").strip() for row in self.bindings()}
        if preferred not in used:
            parsed = read_conf(conf_path(self.config_dir, preferred))
            if parsed is None or self._conf_looks_mullvad(parsed):
                return preferred
            raise AgentError(
                "CONFLICT",
                f"Interface {preferred} exists and is not a Mullvad tunnel",
                409,
            )
        raise AgentError("CONFLICT", f"Country {country_code} already has an interface", 409)

    def _conf_looks_mullvad(self, parsed: dict[str, Any]) -> bool:
        try:
            catalog = self.fetch()
        except AgentError:
            return False
        peers = parsed.get("peers") or []
        if not peers:
            return False
        return match_relay(catalog, pubkey=str(peers[0].get("PublicKey") or ""), endpoint_host=str(peers[0].get("Endpoint") or "")) is not None

    def _apply_relay(self, iface: str, relay: dict[str, Any]) -> None:
        settings = self.settings()
        path = conf_path(self.config_dir, iface)
        parsed = read_conf(path) or {"interface": {}, "peers": []}
        interface = dict(parsed.get("interface") or {})
        private_key = str(interface.get("PrivateKey") or settings.get("private_key") or "").strip()
        address = str(interface.get("Address") or settings.get("address") or "").strip()
        if not private_key:
            raise AgentError("VALIDATION_ERROR", "Mullvad private key is not set", 422)
        if not address:
            raise AgentError(
                "VALIDATION_ERROR",
                "Mullvad tunnel Address is missing; set PrivateKey after an existing Mullvad interface is present",
                422,
            )
        interface["PrivateKey"] = private_key
        interface["Address"] = address if "/" in address else f"{address}/32"
        if "Table" not in interface:
            interface["Table"] = "off"

        pubkey = str(relay.get("pubkey") or "").strip()
        ipv4 = str(relay.get("ipv4_addr_in") or "").strip()
        endpoint = f"{ipv4}:{WG_PORT}"
        peers = [dict(peer) for peer in (parsed.get("peers") or []) if isinstance(peer, dict)]
        peer = peers[0] if peers else {}
        peer["PublicKey"] = pubkey
        peer["Endpoint"] = endpoint
        if "AllowedIPs" not in peer:
            peer["AllowedIPs"] = "0.0.0.0/0"
        if "PersistentKeepalive" not in peer:
            peer["PersistentKeepalive"] = "25"
        parsed = {"interface": interface, "peers": [peer]}
        self.config_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(dump_wg_conf(parsed), encoding="utf-8")
        self._sync_iface(iface, path)
        if not settings.get("private_key") or not settings.get("address"):
            self.store.put_doc(
                CORE,
                KIND_SETTINGS,
                SETTINGS_ID,
                {"private_key": private_key, "address": interface["Address"]},
            )

    def _sync_iface(self, iface: str, path: Path) -> None:
        if self._iface_up(iface):
            strip = self.runner(["wg-quick", "strip", str(path)], check=False, timeout=15)
            if getattr(strip, "returncode", 1) != 0:
                strip = self.runner(["wg-quick", "strip", iface], check=False, timeout=15)
            stripped = (getattr(strip, "stdout", "") or "").strip()
            if getattr(strip, "returncode", 1) != 0 or not stripped:
                raise AgentError("EXEC_ERROR", f"wg-quick strip failed for {iface}", 500)
            tmp = path.with_suffix(".sync")
            tmp.write_text(stripped + "\n", encoding="utf-8")
            try:
                sync = self.runner(["wg", "syncconf", iface, str(tmp)], check=False, timeout=15)
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
            if getattr(sync, "returncode", 1) != 0:
                err = (getattr(sync, "stderr", "") or getattr(sync, "stdout", "") or "wg syncconf failed").strip()
                raise AgentError("EXEC_ERROR", err, 500)
            return

        up = self.runner(["wg-quick", "up", iface], check=False, timeout=30)
        if getattr(up, "returncode", 1) != 0:
            err = (getattr(up, "stderr", "") or getattr(up, "stdout", "") or "wg-quick up failed").strip()
            raise AgentError("EXEC_ERROR", err, 500)

    def _iface_up(self, iface: str) -> bool:
        return Path(f"/sys/class/net/{iface}").is_dir()

    def _iface_healthy(self, iface: str) -> bool:
        ok, _message, _latency = self.egress_probe(interface=iface, runner=self.runner)
        if ok:
            return True
        handshake = self._latest_handshake(iface)
        if handshake and (time.time() - handshake) <= HANDSHAKE_MAX_AGE:
            return True
        return False

    def _latest_handshake(self, iface: str) -> int | None:
        result = self.runner(["wg", "show", iface, "latest-handshakes"], check=False, timeout=5)
        if getattr(result, "returncode", 1) != 0:
            return None
        newest = 0
        for line in (getattr(result, "stdout", "") or "").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                ts = int(parts[-1])
            except ValueError:
                continue
            newest = max(newest, ts)
        return newest or None

    def _scan_interfaces(self) -> list[tuple[str, dict[str, Any], dict[str, str] | None]]:
        names: set[str] = set()
        if self.config_dir.is_dir():
            for path in self.config_dir.glob("*.conf"):
                names.add(path.stem)
        listed = self.runner(["wg", "show", "interfaces"], check=False, timeout=5)
        if getattr(listed, "returncode", 0) == 0:
            for name in (getattr(listed, "stdout", "") or "").split():
                if name.strip():
                    names.add(name.strip())
        rows: list[tuple[str, dict[str, Any], dict[str, str] | None]] = []
        for name in sorted(names):
            if not normalize_exit_interface(name):
                continue
            parsed = read_conf(conf_path(self.config_dir, name)) or {"interface": {}, "peers": []}
            rows.append((name, parsed, self._live_peer(name)))
        return rows

    def _live_peer(self, iface: str) -> dict[str, str] | None:
        dump = self.runner(["wg", "show", iface, "dump"], check=False, timeout=5)
        if getattr(dump, "returncode", 1) != 0:
            return None
        lines = [line for line in (getattr(dump, "stdout", "") or "").splitlines() if line.strip()]
        if len(lines) < 2:
            return None
        parts = lines[1].split("\t")
        if len(parts) < 4:
            return None
        return {"public_key": parts[0], "endpoint": parts[2] if parts[2] != "(none)" else ""}

    def _seed_settings_from_conf(self, parsed: dict[str, Any]) -> None:
        interface = parsed.get("interface") or {}
        private_key = str(interface.get("PrivateKey") or "").strip()
        address = str(interface.get("Address") or "").strip()
        current = self.store.get_doc(CORE, KIND_SETTINGS, SETTINGS_ID) or {}
        if current.get("private_key") and current.get("address"):
            return
        if not private_key and not address:
            return
        self.store.put_doc(
            CORE,
            KIND_SETTINGS,
            SETTINGS_ID,
            {
                "private_key": str(current.get("private_key") or private_key),
                "address": str(current.get("address") or address),
            },
        )

    def _put_binding(
        self,
        *,
        country_code: str,
        iface: str,
        relay: dict[str, Any] | None,
        adopted: bool,
        extra: dict[str, Any] | None = None,
    ) -> None:
        current = self.binding_for(country_code) or {}
        payload = {
            "country_code": country_code,
            "country_name": str((relay or {}).get("country_name") or current.get("country_name") or country_code),
            "iface": iface,
            "hostname": str((relay or {}).get("hostname") or current.get("hostname") or ""),
            "pubkey": str((relay or {}).get("pubkey") or current.get("pubkey") or ""),
            "endpoint": (
                f"{relay.get('ipv4_addr_in')}:{WG_PORT}"
                if relay and relay.get("ipv4_addr_in")
                else str(current.get("endpoint") or "")
            ),
            "adopted": adopted,
            "last_fallback_at": current.get("last_fallback_at"),
            "last_error": current.get("last_error") or "",
        }
        if extra:
            payload.update(extra)
        self.store.put_doc(CORE, KIND_LOCATION, country_code, payload)

    def _present_binding(self, bind: dict[str, Any]) -> dict[str, Any]:
        return {
            "country_code": str(bind.get("country_code") or ""),
            "country_name": str(bind.get("country_name") or ""),
            "iface": str(bind.get("iface") or ""),
            "hostname": str(bind.get("hostname") or "") or None,
            "endpoint": str(bind.get("endpoint") or "") or None,
            "adopted": bool(bind.get("adopted")),
            "last_fallback_at": bind.get("last_fallback_at"),
            "last_error": str(bind.get("last_error") or "") or None,
        }

    def _discover_address(self) -> str:
        for _iface, parsed, _live in self._scan_interfaces():
            address = str((parsed.get("interface") or {}).get("Address") or "").strip()
            if address:
                return address
        return ""


def service_from_app(request) -> MullvadService:
    settings = request.app.state.settings
    return MullvadService(
        request.app.state.store,
        config_dir=settings.wireguard_config_dir,
    )
