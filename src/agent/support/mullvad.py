from __future__ import annotations

"""Mullvad WireGuard exit tunnels for region nodes.

Existing host interfaces (de, usa, sw, …) are adopted when their live peer
matches a Mullvad relay. Fallback only rewrites Endpoint/PublicKey so the
iface name — and panel exit_interface — stay unchanged.
"""

import ipaddress
import re
import shutil
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

import httpx

from agent.db import Store
from agent.errors import AgentError
from agent.logutil import get_logger
from agent.support.node_probe import _curl_probe, curl_speed_mbps
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
_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)
KIND_SETTINGS = "settings"
KIND_LOCATION = "location"
CORE = "mullvad"
SETTINGS_ID = "account"
RELAY_METRIC_PING = "ping"
RELAY_METRIC_SPEED = "speed"
RELAY_METRICS = {RELAY_METRIC_PING, RELAY_METRIC_SPEED}
PERSIST_UNIT_TEMPLATE = "agent-mullvad-wg@.service"
PERSIST_HOLD_SCRIPT = Path("/var/lib/agent/mullvad-wg-hold.sh")
PERSIST_UNIT_PATH = Path("/etc/systemd/system") / PERSIST_UNIT_TEMPLATE
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


def parse_ping_ms(output: str) -> int | None:
    match = _PING_TIME_RE.search(str(output or ""))
    if not match:
        return None
    try:
        return max(1, int(round(float(match.group(1)))))
    except ValueError:
        return None


def icmp_ping(host: str, *, runner: Runner | None = None, timeout: float = 2.5) -> tuple[bool, int | None]:
    ip = str(host or "").strip()
    if not ip:
        return False, None
    execute = runner or run
    result = execute(
        ["ping", "-4", "-n", "-c", "1", "-W", "1", ip],
        check=False,
        timeout=timeout,
    )
    body = f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    latency = parse_ping_ms(body)
    if getattr(result, "returncode", 1) == 0 and latency:
        return True, latency
    if latency:
        return True, latency
    return False, None


def ping_relay_ip(
    host: str,
    *,
    runner: Runner | None = None,
    tcp: TcpProbe | None = None,
) -> tuple[bool, int | None]:
    ok, latency = icmp_ping(host, runner=runner)
    if ok:
        return True, latency
    checker = tcp or tcp_probe
    return checker(host, WG_PORT)


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


def sample_relays(relays: list[dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    owned = [row for row in relays if row.get("owned")]
    rest = [row for row in relays if not row.get("owned")]
    return (owned + rest)[: max(1, limit)]


def normalize_tunnel_address(value: Any) -> str:
    """Validate and normalize Address (supports comma-separated IPv4+IPv6)."""
    text = str(value or "").strip()
    if not text:
        return ""
    parts: list[str] = []
    for raw in text.split(","):
        cidr = raw.strip()
        if not cidr:
            continue
        try:
            iface = ipaddress.ip_interface(cidr if "/" in cidr else f"{cidr}/32")
        except ValueError as exc:
            raise AgentError("VALIDATION_ERROR", "Invalid Mullvad tunnel address", 422) from exc
        parts.append(str(iface))
    return ",".join(parts)


def normalize_relay_metric(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"speed", "bandwidth", "port_speed", "network_port_speed", "throughput"}:
        return RELAY_METRIC_SPEED
    return RELAY_METRIC_PING


def relay_network_speed_mbps(row: dict[str, Any]) -> int:
    for key in ("network_port_speed", "network_port_speed_mbps", "speed"):
        raw = row.get(key)
        if raw is None or raw == "":
            continue
        try:
            return max(0, int(round(float(raw))))
        except (TypeError, ValueError):
            continue
    return 0


def score_relays(
    relays: list[dict[str, Any]],
    *,
    exclude_hostname: str = "",
    exclude_hostnames: list[str] | set[str] | None = None,
    probe: TcpProbe | None = None,
    workers: int = 16,
    require_reachable: bool = False,
    prefer_measured: bool = True,
    metric: str = RELAY_METRIC_PING,
) -> list[tuple[int, dict[str, Any]]]:
    """Rank relays for fallback/ensure.

    metric=ping  → lower measured latency wins
    metric=speed → same ping shortlist (real Mbps is measured later via curl --interface)
    """
    # Catalog port Mbps is not used for ranking; throughput is measured per-iface with curl.
    _ = normalize_relay_metric(metric)
    checker = probe or (lambda host, port: tcp_probe(host, port))
    scored: list[tuple[int, dict[str, Any], bool]] = []
    skip = {str(exclude_hostname or "").strip().lower()}
    skip.update(str(name or "").strip().lower() for name in (exclude_hostnames or []))
    skip.discard("")

    def _one(row: dict[str, Any]) -> tuple[int, dict[str, Any], bool] | None:
        hostname = str(row.get("hostname") or "").strip().lower()
        if hostname and hostname in skip:
            return None
        ipv4 = str(row.get("ipv4_addr_in") or "").strip()
        ok, latency = checker(ipv4, WG_PORT) if ipv4 else (False, None)
        measured = bool(ok and latency is not None)
        if require_reachable and not measured:
            return None
        if measured:
            return int(latency or 0), row, True
        # WireGuard is UDP; TCP/ICMP to :51820 often fails even when the relay is usable.
        return (40_000 if row.get("owned") else 50_000), row, False

    if not relays:
        return []
    pool_size = min(max(1, workers), max(1, len(relays)))
    with ThreadPoolExecutor(max_workers=pool_size) as pool:
        futures = [pool.submit(_one, row) for row in relays]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                scored.append(result)

    measured = [item for item in scored if item[2]]
    pool = measured if (prefer_measured and measured) else scored

    ranked = [(score, row) for score, row, _measured in pool]
    ranked.sort(
        key=lambda item: (
            item[0],
            0 if item[1].get("owned") else 1,
            str(item[1].get("hostname") or ""),
        )
    )
    return ranked


def pick_best_relay(
    relays: list[dict[str, Any]],
    *,
    exclude_hostname: str = "",
    exclude_hostnames: list[str] | set[str] | None = None,
    probe: TcpProbe | None = None,
    require_reachable: bool = False,
    prefer_measured: bool = True,
    metric: str = RELAY_METRIC_PING,
) -> dict[str, Any] | None:
    scored = score_relays(
        relays,
        exclude_hostname=exclude_hostname,
        exclude_hostnames=exclude_hostnames,
        probe=probe,
        require_reachable=require_reachable,
        prefer_measured=prefer_measured,
        metric=metric,
    )
    return scored[0][1] if scored else None


def present_relay_row(
    row: dict[str, Any],
    *,
    ping_ms: int | None = None,
    measured: bool = False,
    current: bool = False,
    speed_mbps: float | int | None = None,
) -> dict[str, Any]:
    port_speed = relay_network_speed_mbps(row)
    measured_speed = None
    if speed_mbps is not None:
        try:
            measured_speed = round(float(speed_mbps), 2)
        except (TypeError, ValueError):
            measured_speed = None
    return {
        "hostname": str(row.get("hostname") or "").strip(),
        "country_code": str(row.get("country_code") or "").strip().lower(),
        "country_name": str(row.get("country_name") or "").strip(),
        "city_code": str(row.get("city_code") or "").strip().lower(),
        "city_name": str(row.get("city_name") or "").strip(),
        "ipv4": str(row.get("ipv4_addr_in") or "").strip(),
        "pubkey": str(row.get("pubkey") or "").strip(),
        "owned": bool(row.get("owned")),
        "port_mbps": port_speed if port_speed > 0 else None,
        "speed_mbps": measured_speed if measured_speed is not None else (port_speed if port_speed > 0 else None),
        "ping_ms": ping_ms,
        "measured": bool(measured and ping_ms is not None),
        "current": bool(current),
    }


def conf_path(config_dir: str | Path, iface: str) -> Path:
    return Path(config_dir) / f"{iface}.conf"


def render_persist_hold_script(config_dir: str | Path) -> str:
    root = str(Path(config_dir)).replace("'", "'\"'\"'")
    return f"""#!/bin/sh
set -eu
IFACE=${{1:-}}
CONF='{root}'/"$IFACE".conf
case "$IFACE" in
  ''|*[!A-Za-z0-9_.-]*) echo "invalid iface" >&2; exit 1 ;;
esac
if [ ! -f "$CONF" ]; then
  echo "missing $CONF" >&2
  exit 1
fi

bring_up() {{
  ip link add name "$IFACE" type wireguard 2>/dev/null || true
  tmp=$(mktemp)
  if ! wg-quick strip "$CONF" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  if ! wg setconf "$IFACE" "$tmp" 2>/dev/null; then
    wg syncconf "$IFACE" "$tmp" || {{ rm -f "$tmp"; return 1; }}
  fi
  rm -f "$tmp"
  ip link set dev "$IFACE" up
  addrs=$(awk -F= 'BEGIN {{ IGNORECASE=1 }} $1 ~ /^[[:space:]]*Address[[:space:]]*$/ {{ print $2 }}' "$CONF" | tr -d ' ')
  old_ifs=$IFS
  IFS=,
  for cidr in $addrs; do
    [ -n "$cidr" ] || continue
    case "$cidr" in
      *:*) ip -6 addr add "$cidr" dev "$IFACE" 2>/dev/null || true ;;
      *) ip -4 addr add "$cidr" dev "$IFACE" 2>/dev/null || true ;;
    esac
  done
  IFS=$old_ifs
}}

while true; do
  if [ ! -d "/sys/class/net/$IFACE" ]; then
    bring_up || true
  else
    ip link set dev "$IFACE" up 2>/dev/null || true
  fi
  sleep 8
done
"""


def render_persist_unit(script_path: str | Path) -> str:
    script = str(script_path)
    return "\n".join(
        [
            "[Unit]",
            "Description=Netinja Mullvad WireGuard exit %i",
            "After=network-online.target",
            "Wants=network-online.target",
            "Conflicts=wg-quick@%i.service",
            "",
            "[Service]",
            "Type=simple",
            "Restart=always",
            "RestartSec=5",
            f"ExecStart={script} %i",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


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
        persist_script: str | Path | None = None,
        persist_unit_path: str | Path | None = None,
    ) -> None:
        self.store = store
        self.config_dir = Path(config_dir)
        self.runner = runner or run
        self.fetch = fetch or fetch_relays
        self.probe = probe or (lambda host, _port: ping_relay_ip(host, runner=self.runner))
        self.egress_probe = egress_probe or _curl_probe
        self.handshake_wait = 2.0
        self.persist_script = Path(persist_script) if persist_script else PERSIST_HOLD_SCRIPT
        self.persist_unit_path = Path(persist_unit_path) if persist_unit_path else PERSIST_UNIT_PATH

    def settings(self) -> dict[str, Any]:
        row = self.store.get_doc(CORE, KIND_SETTINGS, SETTINGS_ID) or {}
        private_key = str(row.get("private_key") or "").strip()
        address = str(row.get("address") or "").strip()
        metric = normalize_relay_metric(row.get("relay_metric"))
        return {
            "private_key": private_key,
            "address": address,
            "has_private_key": bool(private_key),
            "key_preview": mask_key(private_key),
            "relay_metric": metric,
            "relay_metric_label": "سرعت واقعی (curl)" if metric == RELAY_METRIC_SPEED else "پینگ",
        }

    def relay_metric(self) -> str:
        return normalize_relay_metric(self.settings().get("relay_metric"))

    def save_settings(
        self,
        *,
        private_key: str | None = None,
        address: str | None = None,
        relay_metric: str | None = None,
    ) -> dict[str, Any]:
        current = self.store.get_doc(CORE, KIND_SETTINGS, SETTINGS_ID) or {}
        key = str(private_key if private_key is not None else current.get("private_key") or "").strip()
        if private_key is not None and not _WG_KEY_RE.match(key):
            raise AgentError("VALIDATION_ERROR", "Invalid WireGuard private key", 422)
        if private_key is None and not key and relay_metric is None:
            raise AgentError("VALIDATION_ERROR", "Mullvad private key is not set", 422)

        metric = normalize_relay_metric(
            relay_metric if relay_metric is not None else current.get("relay_metric")
        )

        # Metric-only updates must not re-validate Address: exits share one key/IP and
        # configs often store dual-stack Address (IPv4,IPv6) that older code rejected.
        if relay_metric is not None and private_key is None and address is None:
            payload = {
                "private_key": key,
                "address": str(current.get("address") or "").strip(),
                "relay_metric": metric,
            }
            self.store.put_doc(CORE, KIND_SETTINGS, SETTINGS_ID, payload)
            return self.settings()

        addr = str(address if address is not None else current.get("address") or "").strip()
        if address is not None or (private_key is not None and not addr):
            if not addr:
                addr = self._discover_address()
        if addr:
            addr = normalize_tunnel_address(addr)

        payload = {
            "private_key": key,
            "address": addr,
            "relay_metric": metric,
        }
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

    def locations(self, *, force: bool = False, ping: bool = False) -> dict[str, Any]:
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
                    "ping_ms": None,
                    "ping_ip": None,
                    "reachable": None,
                    "ping_via": None,
                }
            )
        if ping:
            locations = self._attach_pings(locations, relays)
        return {
            "settings": {k: v for k, v in self.settings().items() if k != "private_key"},
            "locations": locations,
        }

    def _attach_pings(self, locations: list[dict[str, Any]], relays: list[dict[str, Any]]) -> list[dict[str, Any]]:
        jobs: list[tuple[str, str]] = []
        for item in locations:
            iface = str(item.get("iface") or "")
            has_tunnel = bool(item.get("bound") and iface and self._iface_up(iface))
            if has_tunnel:
                continue
            code = str(item.get("country_code") or "")
            candidates = active_relays(relays, code)
            for row in sample_relays(candidates, 12):
                ipv4 = str(row.get("ipv4_addr_in") or "").strip()
                if ipv4:
                    jobs.append((code, ipv4))

        best: dict[str, tuple[int, str]] = {}
        if jobs:
            with ThreadPoolExecutor(max_workers=min(32, max(1, len(jobs)))) as pool:
                futures = {
                    pool.submit(ping_relay_ip, ip, runner=self.runner, tcp=self.probe): (code, ip)
                    for code, ip in jobs
                }
                for future in as_completed(futures):
                    code, ip = futures[future]
                    ok, latency = future.result()
                    if not ok or latency is None:
                        continue
                    previous = best.get(code)
                    if previous is None or latency < previous[0]:
                        best[code] = (latency, ip)

        for item in locations:
            code = str(item.get("country_code") or "")
            iface = str(item.get("iface") or "")
            has_tunnel = bool(item.get("bound") and iface and self._iface_up(iface))
            if has_tunnel:
                tunnel_ok, _message, tunnel_ms = self.egress_probe(interface=iface, runner=self.runner)
                if tunnel_ok and tunnel_ms:
                    item["ping_ms"] = tunnel_ms
                    item["ping_ip"] = None
                    item["reachable"] = True
                    item["ping_via"] = "tunnel"
                    continue
            catalog = best.get(code)
            if catalog:
                item["ping_ms"] = catalog[0]
                item["ping_ip"] = catalog[1]
                item["reachable"] = True
                item["ping_via"] = "relay"
            else:
                item["ping_ms"] = None
                item["ping_ip"] = None
                item["reachable"] = False
                item["ping_via"] = None
        return locations

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
            relay = pick_best_relay(
                candidates,
                exclude_hostname=exclude,
                probe=self.probe,
                metric=RELAY_METRIC_PING,
            )
        if relay is None:
            relay = candidates[0]

        self._apply_relay(iface, relay)
        self._put_binding(country_code=code, iface=iface, relay=relay, adopted=bool((bind or {}).get("adopted")))
        return self._present_binding(self.binding_for(code) or {})

    def fallback_iface(self, iface: str) -> dict[str, Any] | None:
        name = str(iface or "").strip()
        if not name:
            return None
        relays = self.fetch()
        self.refresh_bindings(relays)
        for bind in self.bindings():
            if str(bind.get("iface") or "").strip() == name:
                return self._fallback_one(bind, relays)
        code = country_for_iface_name(name)
        if not code:
            log.warning("mullvad fallback skipped iface=%s: no country binding", name)
            return None
        bind = self.binding_for(code) or {}
        live = self._live_peer(name) or {}
        hostname = str(bind.get("hostname") or "")
        if not hostname:
            match = match_relay(
                relays,
                pubkey=str(live.get("public_key") or ""),
                endpoint_host=str(live.get("endpoint") or ""),
            )
            if match:
                hostname = str(match.get("hostname") or "")
        synthesized = {
            **bind,
            "country_code": code,
            "iface": name,
            "hostname": hostname,
            "adopted": bool(bind.get("adopted", True)),
        }
        log.info("mullvad fallback iface=%s country=%s hostname=%s", name, code, hostname or "-")
        return self._fallback_one(synthesized, relays)

    def fallback(self, country_code: str | None = None, *, optimize: bool = False) -> dict[str, Any]:
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
            result = self._fallback_one(bind, relays, optimize=optimize)
            status = result.get("status")
            if status == "changed":
                changed.append(result)
            elif status == "failed":
                failed.append(result)
            else:
                skipped.append(result)
        return {"changed": changed, "skipped": skipped, "failed": failed, "optimize": bool(optimize)}

    def country_relays(self, country_code: str, *, ping: bool = True) -> dict[str, Any]:
        code = str(country_code or "").strip().lower()
        if not re.fullmatch(r"[a-z]{2}", code or ""):
            raise AgentError("VALIDATION_ERROR", "country_code must be ISO 3166-1 alpha-2", 422)

        relays = self.fetch()
        self.refresh_bindings(relays)
        candidates = active_relays(relays, code)
        if not candidates:
            raise AgentError("NOT_FOUND", f"No active Mullvad relays for {code}", 404)

        bind = self.binding_for(code) or {}
        current_host = str(bind.get("hostname") or "").strip().lower()
        metric = self.relay_metric()
        rows: list[dict[str, Any]] = []

        ping_by_host: dict[str, int | None] = {}
        if ping:
            for score, row in score_relays(
                candidates,
                probe=self.probe,
                prefer_measured=False,
                metric=RELAY_METRIC_PING,
            ):
                host = str(row.get("hostname") or "").strip().lower()
                ping_by_host[host] = score if score < 40_000 else None

        scored = score_relays(
            candidates,
            probe=self.probe,
            prefer_measured=False,
            metric=metric,
        )
        for _score, row in scored:
            host = str(row.get("hostname") or "").strip().lower()
            ping_ms = ping_by_host.get(host)
            rows.append(
                present_relay_row(
                    row,
                    ping_ms=ping_ms,
                    measured=ping_ms is not None,
                    current=host == current_host,
                )
            )

        return {
            "country_code": code,
            "iface": str(bind.get("iface") or preferred_iface(code) or ""),
            "bound": bool(bind),
            "current_hostname": str(bind.get("hostname") or "") or None,
            "relay_metric": metric,
            "relays": rows,
        }

    def switch_relay(self, country_code: str, hostname: str) -> dict[str, Any]:
        code = str(country_code or "").strip().lower()
        host = str(hostname or "").strip()
        if not re.fullmatch(r"[a-z]{2}", code or ""):
            raise AgentError("VALIDATION_ERROR", "country_code must be ISO 3166-1 alpha-2", 422)
        if not host:
            raise AgentError("VALIDATION_ERROR", "hostname is required", 422)

        relays = self.fetch()
        self.refresh_bindings(relays)
        candidates = active_relays(relays, code)
        relay = next(
            (row for row in candidates if str(row.get("hostname") or "").strip().lower() == host.lower()),
            None,
        )
        if relay is None:
            raise AgentError("NOT_FOUND", f"Relay [{host}] not found for {code}", 404)

        bind = self.binding_for(code)
        if not bind:
            raise AgentError("NOT_FOUND", f"No Mullvad binding for {code}; ensure the location first", 404)

        iface = str(bind.get("iface") or "").strip()
        if not iface:
            raise AgentError("VALIDATION_ERROR", f"Missing interface for {code}", 422)

        previous = str(bind.get("hostname") or "").strip()
        self._apply_relay(iface, relay)
        self._put_binding(
            country_code=code,
            iface=iface,
            relay=relay,
            adopted=bool(bind.get("adopted")),
            extra={
                "last_fallback_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "last_error": "",
                "manual_switch": True,
            },
        )
        presented = self._present_binding(self.binding_for(code) or bind)
        return {
            **presented,
            "status": "changed" if previous.lower() != host.lower() else "ok",
            "previous_hostname": previous or None,
            "message": f"switched to {host}" if previous.lower() != host.lower() else f"already on {host}",
        }

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

    def _fallback_one(
        self,
        bind: dict[str, Any],
        relays: list[dict[str, Any]],
        *,
        optimize: bool = False,
    ) -> dict[str, Any]:
        code = str(bind.get("country_code") or "").strip().lower()
        iface = str(bind.get("iface") or "").strip()
        hostname = str(bind.get("hostname") or "")
        presented = self._present_binding(bind)
        if not iface:
            return {**presented, "status": "failed", "message": "missing iface"}

        healthy = self._iface_up(iface) and self._iface_healthy(iface)
        if healthy and not optimize:
            return {**presented, "status": "ok", "message": "healthy"}

        candidates = active_relays(relays, code)
        tried = {hostname.strip().lower()} if hostname.strip() and not optimize else set()
        last_error = "no Mullvad relay left in country"
        last_changed: dict[str, Any] | None = None
        if not candidates:
            log.warning("mullvad fallback no catalog relays country=%s iface=%s", code, iface)
            return {**presented, "status": "failed", "message": last_error}

        metric = self.relay_metric()
        if metric == RELAY_METRIC_SPEED:
            return self._fallback_one_by_speed(
                bind,
                candidates,
                optimize=optimize,
                healthy=healthy,
                tried=tried,
            )

        if optimize and healthy:
            scored = score_relays(candidates, probe=self.probe, prefer_measured=True, metric=RELAY_METRIC_PING)
            if not scored:
                return {**presented, "status": "ok", "message": "healthy"}
            best_score, best = scored[0]
            best_host = str(best.get("hostname") or "").strip()
            if best_host.lower() == hostname.strip().lower():
                return {**presented, "status": "ok", "message": "already best by ping"}
            current_score = next(
                (
                    score
                    for score, row in scored
                    if str(row.get("hostname") or "").strip().lower() == hostname.strip().lower()
                ),
                None,
            )
            if (
                current_score is not None
                and best_score < 40_000
                and current_score < 40_000
                and (current_score - best_score) < max(20, int(current_score * 0.2))
            ):
                return {
                    **presented,
                    "status": "ok",
                    "message": f"current relay within ping margin ({current_score}ms vs {best_score}ms)",
                }
            tried = {hostname.strip().lower()} if hostname.strip() else set()

        attempts = min(4, max(1, len(candidates)))
        log.info(
            "mullvad fallback start country=%s iface=%s candidates=%s exclude=%s optimize=%s metric=%s",
            code,
            iface,
            len(candidates),
            ",".join(sorted(tried)) or "-",
            optimize,
            metric,
        )
        for _ in range(attempts):
            relay = pick_best_relay(
                candidates,
                exclude_hostnames=tried,
                probe=self.probe,
                prefer_measured=True,
                metric=RELAY_METRIC_PING,
            )
            if relay is None:
                log.warning(
                    "mullvad fallback no candidate left country=%s iface=%s tried=%s catalog=%s",
                    code,
                    iface,
                    ",".join(sorted(tried)) or "-",
                    len(candidates),
                )
                break
            relay_host = str(relay.get("hostname") or "").strip()
            try:
                self._apply_relay(iface, relay)
                self._put_binding(
                    country_code=code,
                    iface=iface,
                    relay=relay,
                    adopted=bool(bind.get("adopted")),
                    extra={
                        "last_fallback_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "last_error": "",
                        "manual_switch": False,
                    },
                )
                log.info("mullvad fallback country=%s iface=%s hostname=%s", code, iface, relay_host)
                last_changed = {
                    **self._present_binding(self.binding_for(code) or bind),
                    "status": "changed",
                    "message": f"switched to {relay_host}",
                }
                wait = float(getattr(self, "handshake_wait", 0) or 0)
                if wait > 0:
                    time.sleep(wait)
                if self._iface_healthy(iface):
                    return last_changed
                log.warning(
                    "mullvad fallback still unhealthy country=%s iface=%s hostname=%s",
                    code,
                    iface,
                    relay_host,
                )
                last_error = f"egress still down after {relay_host}"
            except AgentError as exc:
                last_error = exc.message
                log.warning(
                    "mullvad fallback apply failed country=%s iface=%s hostname=%s: %s",
                    code,
                    iface,
                    relay_host,
                    exc.message,
                )
            if relay_host:
                tried.add(relay_host.lower())

        if last_changed is not None:
            last_changed["message"] = f"{last_changed['message']} (egress still down)"
            return last_changed
        return {**presented, "status": "failed", "message": last_error}

    def _measure_iface_speed(self, iface: str) -> float | None:
        ok, _message, mbps = curl_speed_mbps(interface=iface, runner=self.runner)
        if not ok or mbps is None:
            return None
        return float(mbps)

    def _fallback_one_by_speed(
        self,
        bind: dict[str, Any],
        candidates: list[dict[str, Any]],
        *,
        optimize: bool,
        healthy: bool,
        tried: set[str],
    ) -> dict[str, Any]:
        """Pick relay by real curl download Mbps bound to the WireGuard iface name."""
        code = str(bind.get("country_code") or "").strip().lower()
        iface = str(bind.get("iface") or "").strip()
        hostname = str(bind.get("hostname") or "").strip()
        presented = self._present_binding(bind)
        if not iface:
            return {**presented, "status": "failed", "message": "missing iface"}

        if healthy and not optimize:
            return {**presented, "status": "ok", "message": "healthy"}

        shortlist_n = 5 if optimize else 4
        ranked = score_relays(
            candidates,
            exclude_hostnames=tried,
            probe=self.probe,
            prefer_measured=True,
            metric=RELAY_METRIC_PING,
        )
        shortlist = [row for _score, row in ranked[:shortlist_n]]
        if not shortlist:
            return {**presented, "status": "failed", "message": "no Mullvad relay left in country"}

        log.info(
            "mullvad speed-rank start country=%s iface=%s shortlist=%s optimize=%s",
            code,
            iface,
            ",".join(str(r.get("hostname") or "") for r in shortlist),
            optimize,
        )

        best_relay: dict[str, Any] | None = None
        best_mbps = -1.0
        current_mbps: float | None = None
        last_error = "speed probe failed"
        applied_host = hostname

        # Measure current first without switching when already healthy.
        if healthy and hostname:
            current_mbps = self._measure_iface_speed(iface)
            if current_mbps is not None:
                best_mbps = current_mbps
                best_relay = next(
                    (
                        row
                        for row in candidates
                        if str(row.get("hostname") or "").strip().lower() == hostname.lower()
                    ),
                    None,
                )
                log.info(
                    "mullvad speed current iface=%s hostname=%s mbps=%s",
                    iface,
                    hostname,
                    current_mbps,
                )

        for relay in shortlist:
            relay_host = str(relay.get("hostname") or "").strip()
            if not relay_host:
                continue
            if relay_host.lower() in tried and relay_host.lower() != hostname.lower():
                continue
            if healthy and relay_host.lower() == hostname.lower():
                continue
            try:
                self._apply_relay(iface, relay)
                applied_host = relay_host
                self._put_binding(
                    country_code=code,
                    iface=iface,
                    relay=relay,
                    adopted=bool(bind.get("adopted")),
                    extra={
                        "last_fallback_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "last_error": "",
                        "manual_switch": False,
                    },
                )
                wait = float(getattr(self, "handshake_wait", 0) or 0)
                if wait > 0:
                    time.sleep(wait)
                if not self._iface_healthy(iface):
                    last_error = f"egress still down after {relay_host}"
                    tried.add(relay_host.lower())
                    continue
                mbps = self._measure_iface_speed(iface)
                if mbps is None:
                    last_error = f"curl speed failed on {relay_host}"
                    tried.add(relay_host.lower())
                    continue
                log.info(
                    "mullvad speed measured iface=%s hostname=%s mbps=%s",
                    iface,
                    relay_host,
                    mbps,
                )
                if mbps > best_mbps:
                    best_mbps = mbps
                    best_relay = relay
            except AgentError as exc:
                last_error = exc.message
                log.warning(
                    "mullvad speed apply failed country=%s iface=%s hostname=%s: %s",
                    code,
                    iface,
                    relay_host,
                    exc.message,
                )
                tried.add(relay_host.lower())

        if best_relay is None:
            return {**presented, "status": "failed", "message": last_error}

        best_host = str(best_relay.get("hostname") or "").strip()
        # Within ~10% of current measured speed, keep current.
        if (
            optimize
            and healthy
            and current_mbps is not None
            and best_host.lower() == hostname.lower()
        ):
            return {
                **presented,
                "status": "ok",
                "message": f"already best by curl speed ({current_mbps} Mbps)",
            }
        if (
            optimize
            and healthy
            and current_mbps is not None
            and best_mbps > 0
            and (best_mbps - current_mbps) < max(0.5, current_mbps * 0.1)
            and hostname
        ):
            current_relay = next(
                (
                    row
                    for row in candidates
                    if str(row.get("hostname") or "").strip().lower() == hostname.lower()
                ),
                None,
            )
            if current_relay is not None and applied_host.lower() != hostname.lower():
                try:
                    self._apply_relay(iface, current_relay)
                    self._put_binding(
                        country_code=code,
                        iface=iface,
                        relay=current_relay,
                        adopted=bool(bind.get("adopted")),
                        extra={"last_error": "", "manual_switch": False},
                    )
                except AgentError:
                    pass
            return {
                **presented,
                "status": "ok",
                "message": (
                    f"current relay within speed margin ({current_mbps}Mbps vs {best_mbps}Mbps)"
                ),
            }

        if applied_host.lower() != best_host.lower():
            try:
                self._apply_relay(iface, best_relay)
                self._put_binding(
                    country_code=code,
                    iface=iface,
                    relay=best_relay,
                    adopted=bool(bind.get("adopted")),
                    extra={
                        "last_fallback_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "last_error": "",
                        "manual_switch": False,
                    },
                )
            except AgentError as exc:
                return {**presented, "status": "failed", "message": exc.message}

        if best_host.lower() == hostname.lower():
            return {
                **self._present_binding(self.binding_for(code) or bind),
                "status": "ok",
                "message": f"already best by curl speed ({best_mbps} Mbps)",
            }
        return {
            **self._present_binding(self.binding_for(code) or bind),
            "status": "changed",
            "message": f"switched to {best_host} ({best_mbps} Mbps via curl --interface {iface})",
        }

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
        interface["Address"] = normalize_tunnel_address(
            address if "/" in address or "," in address else f"{address}/32"
        ) or (address if "/" in address else f"{address}/32")
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
        try:
            self._ensure_persist_unit(iface)
        except Exception as exc:
            log.warning("mullvad persist unit failed iface=%s: %s", iface, exc)
        if not settings.get("private_key") or not settings.get("address"):
            self.store.put_doc(
                CORE,
                KIND_SETTINGS,
                SETTINGS_ID,
                {"private_key": private_key, "address": interface["Address"]},
            )

    def restore_interfaces(self) -> dict[str, Any]:
        restored: list[str] = []
        persisted: list[str] = []
        failed: list[str] = []
        for bind in self.bindings():
            iface = normalize_exit_interface(str(bind.get("iface") or ""))
            if not iface:
                continue
            path = conf_path(self.config_dir, iface)
            try:
                if path.is_file() and not self._iface_up(iface):
                    self._sync_iface(iface, path)
                    restored.append(iface)
                if self._ensure_persist_unit(iface).get("ok"):
                    persisted.append(iface)
            except Exception as exc:
                log.warning("mullvad restore failed iface=%s: %s", iface, exc)
                failed.append(iface)
        return {"restored": restored, "persisted": persisted, "failed": failed}

    def _ensure_persist_unit(self, iface: str) -> dict[str, Any]:
        name = normalize_exit_interface(iface)
        if not name:
            return {"ok": False, "skipped": True, "reason": "invalid iface"}
        if shutil.which("systemctl") is None:
            return {"ok": False, "skipped": True, "reason": "systemctl not found"}

        script_text = render_persist_hold_script(self.config_dir)
        unit_text = render_persist_unit(self.persist_script)
        try:
            self.persist_script.parent.mkdir(parents=True, exist_ok=True)
            self.persist_unit_path.parent.mkdir(parents=True, exist_ok=True)
            previous_script = self.persist_script.read_text(encoding="utf-8") if self.persist_script.is_file() else ""
            previous_unit = self.persist_unit_path.read_text(encoding="utf-8") if self.persist_unit_path.is_file() else ""
            changed = previous_script != script_text or previous_unit != unit_text
            if previous_script != script_text:
                self.persist_script.write_text(script_text, encoding="utf-8")
                try:
                    self.persist_script.chmod(0o755)
                except OSError:
                    pass
            if previous_unit != unit_text:
                self.persist_unit_path.write_text(unit_text, encoding="utf-8")
            if changed:
                self.runner(["systemctl", "daemon-reload"], check=False, timeout=30)
        except OSError as exc:
            log.warning("mullvad persist unit write failed: %s", exc)
            return {"ok": False, "skipped": False, "reason": str(exc)}

        instance = f"agent-mullvad-wg@{name}.service"
        self.runner(["systemctl", "disable", f"wg-quick@{name}.service"], check=False, timeout=30)
        enabled = self.runner(["systemctl", "is-enabled", instance], check=False, timeout=10)
        if getattr(enabled, "returncode", 1) != 0:
            self.runner(["systemctl", "enable", instance], check=False, timeout=30)
        active = self.runner(["systemctl", "is-active", instance], check=False, timeout=10)
        started = getattr(active, "returncode", 1) == 0
        if not started:
            start = self.runner(["systemctl", "start", instance], check=False, timeout=30)
            started = getattr(start, "returncode", 1) == 0
        return {"ok": True, "unit": instance, "started": started}

    def _sync_iface(self, iface: str, path: Path) -> None:
        stripped = self._stripped_conf(iface, path)
        existed = self._iface_up(iface)
        if not existed:
            self._create_wg_link(iface)
        self._wg_apply_conf(iface, stripped)
        self._link_up(iface)
        self._assign_tunnel_address(iface, path)

    def _stripped_conf(self, iface: str, path: Path) -> str:
        strip = self.runner(["wg-quick", "strip", str(path)], check=False, timeout=15)
        if getattr(strip, "returncode", 1) != 0:
            strip = self.runner(["wg-quick", "strip", iface], check=False, timeout=15)
        stripped = (getattr(strip, "stdout", "") or "").strip()
        if getattr(strip, "returncode", 1) != 0 or not stripped:
            raise AgentError("EXEC_ERROR", f"wg-quick strip failed for {iface}", 500)
        return stripped

    def _proc_err(self, proc: Any, fallback: str) -> str:
        return (getattr(proc, "stderr", "") or getattr(proc, "stdout", "") or fallback).strip() or fallback

    def _is_exists_err(self, err: str) -> bool:
        text = err.lower()
        return (
            "file exists" in text
            or "already exists" in text
            or "already assigned" in text
        )

    def _create_wg_link(self, iface: str) -> None:
        add = self.runner(["ip", "link", "add", "name", iface, "type", "wireguard"], check=False, timeout=10)
        if getattr(add, "returncode", 1) == 0 or self._iface_up(iface):
            return
        err = self._proc_err(add, f"ip link add {iface} failed")
        if self._is_exists_err(err):
            return
        raise AgentError("EXEC_ERROR", err, 500)

    def _wg_apply_conf(self, iface: str, stripped: str) -> None:
        tmp = Path(str(self.config_dir / iface) + ".sync")
        tmp.write_text(stripped + "\n", encoding="utf-8")
        try:
            applied = self.runner(["wg", "setconf", iface, str(tmp)], check=False, timeout=15)
            if getattr(applied, "returncode", 1) != 0:
                applied = self.runner(["wg", "syncconf", iface, str(tmp)], check=False, timeout=15)
            if getattr(applied, "returncode", 1) != 0:
                raise AgentError("EXEC_ERROR", self._proc_err(applied, f"wg setconf {iface} failed"), 500)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass

    def _link_up(self, iface: str) -> None:
        result = self.runner(["ip", "link", "set", "dev", iface, "up"], check=False, timeout=10)
        if getattr(result, "returncode", 1) == 0:
            return
        raise AgentError("EXEC_ERROR", self._proc_err(result, f"ip link set {iface} up failed"), 500)

    def _assign_tunnel_address(self, iface: str, path: Path) -> None:
        parsed = read_conf(path) or {}
        address = str((parsed.get("interface") or {}).get("Address") or "").strip()
        if not address:
            return
        for raw in address.split(","):
            cidr = raw.strip()
            if not cidr:
                continue
            if "/" not in cidr:
                cidr = f"{cidr}/32"
            family = "-6" if ":" in cidr.split("/", 1)[0] else "-4"
            result = self.runner(
                ["ip", family, "addr", "add", cidr, "dev", iface],
                check=False,
                timeout=10,
            )
            if getattr(result, "returncode", 1) == 0:
                continue
            err = self._proc_err(result, f"ip addr add {cidr} dev {iface} failed")
            if self._is_exists_err(err):
                continue
            raise AgentError("EXEC_ERROR", err, 500)

    def _iface_up(self, iface: str) -> bool:
        return Path(f"/sys/class/net/{iface}").is_dir()

    def _iface_healthy(self, iface: str) -> bool:
        ok, message, _latency = self.egress_probe(interface=iface, runner=self.runner)
        if ok:
            return True
        log.info("mullvad egress down iface=%s: %s", iface, message)
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
                "relay_metric": normalize_relay_metric(current.get("relay_metric")),
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
