from __future__ import annotations

"""
Peer egress policy routing (WireGuard / Amnezia region exits).

Server-change scenario (per user, dynamic exits)
----------------------------------------------
Inbound WG/Amnezia peers stay on a fixed listen interface. Selecting a region
node only rewrites host policy routing — never the client peer keys:

  from <peer_ip>/32  →  lookup table(N)  →  default dev <exit_iface>

Exit interface names are dynamic (poland, ukrine, deutch, …): each name maps
to a stable table id. No country whitelist.

Firewall ownership
------------------
All forwarding/NAT/sysctl for peer egress is applied by the agent
(nft preferred, else iptables / iptables-legacy) for both exit NICs and
tunnel ifaces (wg*/awg*). Do not rely on manual ``iptables -P FORWARD ACCEPT``.

Repair scenario (handshake OK, RX≈0)
------------------------------------
POST /api/v1/network/egress/repair  →  repair_peer_egress()
force-reconciles routing + firewall and restarts the oneshot apply unit.

Missing exit interface (boot race / Mullvad down / server transfer)
-------------------------------------------------------------------
Never delete a peer's lookup rule just because an explicit ``exit_interface``
is briefly absent. Retain the previous lookup (and the apply script must not
``ip rule del`` on failure); reinstall once that exit iface is warm again.

Peers that have no exit interface at all (standalone / non-region servers)
are different: they are meant to use the main routing table. WireGuard still
decrypts their packets, but the source is a tunnel address, so the agent must
resolve the live default IPv4 device and install FORWARD plus SNAT for traffic
that arrives on a tunnel and leaves through that device, and accept the
ESTABLISHED replies back toward the tunnel. Route lookup alone does not do that.

The apply script must not sleep. A transferred node often has peers aimed at
exit interfaces (nl, tr, de, …) that do not exist on the new host. Sleeping
once per peer inside ExecStartPost and inside every ``wg-quick`` PostUp keeps
``agent.service`` in ``activating (start-post)`` and blocks the API. Defer the
rule and exit. A later reconcile installs it when the interface appears.

Live apply must be idempotent:
  • ip rules: add/switch only when needed (stable pref per peer IP)
  • NAT/MSS: rebuild only when the exit set changes (never flush on no-op)
  • systemd oneshot: rewrite/start only when the apply script content changes

Blind nft flush + systemctl start on every peer update caused multi-second
packet loss every time the panel/API touched a peer.
"""

import asyncio
import ipaddress
import json
import os
import re
import shlex
import shutil
import zlib
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.logutil import get_logger
from agent.support import record_is_enabled
from agent.support import aiofs
from agent.support.process import execute, run as process_run

log = get_logger("peer_egress")

Runner = Callable[..., Any]


async def _default_runner(*args: Any, **kwargs: Any) -> Any:
    return await process_run(*args, **kwargs)

_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
_STATE_KIND = "egress_state"
_STATE_ID = "applied"
_IFACE_KIND = "interface"
_NFT_CHAIN = "postrouting"
_MASQ_COMMENT_PREFIX = "netinja-egress-"
_UNIT_NAME = "agent-peer-egress.service"
_UNIT_PATH = Path("/etc/systemd/system") / _UNIT_NAME
_SYSCTL_DROPIN = Path("/etc/sysctl.d/99-netinja-peer-egress.conf")
_EGRESS_CORES = ("wireguard", "amnezia", "l2tp", "openvpn")
_PPP_TUNNEL = "ppp+"
_OPENVPN_TUNNEL = "tun+"
_L2TP_KIND = "server"
_OPENVPN_KIND = "server"


def _peer_egress_wants_link(unit_path: Path) -> Path:
    return unit_path.parent / "multi-user.target.wants" / unit_path.name


def _wants_target_is_unit(link: Path, raw_target: str, unit_path: Path) -> bool:
    """True when a wants-link target names this unit file.

    ``systemctl enable`` stores either an absolute path or a relative one
    such as ``../agent-peer-egress.service``. A missing link, a regular file,
    or a link to another path means the unit is not enabled.
    """
    raw = str(raw_target or "").strip()
    if raw == "":
        return False
    target = Path(raw)
    if not target.is_absolute():
        target = link.parent / target
    try:
        return os.path.normcase(os.path.abspath(target)) == os.path.normcase(os.path.abspath(unit_path))
    except OSError:
        return False


def _peer_egress_unit_enabled(unit_path: Path) -> bool:
    """True when the WantedBy symlink already points at this unit.

    Checking the symlink avoids ``systemctl enable`` and ``systemctl is-enabled``
    on every reconcile. A changed unit file still daemon-reloads; the existing
    symlink keeps the unit enabled.
    """
    link = _peer_egress_wants_link(unit_path)
    try:
        if not link.is_symlink():
            return False
        raw = os.readlink(link)
    except OSError:
        return False
    return _wants_target_is_unit(link, raw, unit_path)


def _egress_comment_label(iface: str) -> str:
    """Make iface names safe for nft/iptables comment tokens (no '+' / '*')."""
    return str(iface or "").strip().replace("+", "x").replace("*", "x")


def _tunnel_egress_comment(tunnel: str) -> str:
    return f"{_MASQ_COMMENT_PREFIX}tunnel-{_egress_comment_label(tunnel)}"


def rule_pref_for_addr(addr: str) -> int:
    """Stable ip-rule preference per peer address (lower = higher priority)."""
    host = str(addr or "").split("/", 1)[0].strip()
    digest = zlib.crc32(host.encode("utf-8")) & 0xFFFF
    return 15000 + (digest % 5000)


def table_id_for_interface(name: str) -> int:
    digest = zlib.crc32(name.encode("utf-8")) & 0xFFFF
    return 10000 + (digest % 20000)


def normalize_exit_interface(value: Any) -> str | None:
    name = str(value or "").strip()
    if not name:
        return None
    if not _IFACE_RE.match(name):
        return None
    return name


def tunnel_interface_names(interfaces: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(row.get("name") or "").strip()
            for row in interfaces
            if str(row.get("name") or "").strip()
        }
    )


async def all_tunnel_interface_names(store: Store) -> list[str]:
    names: set[str] = set()
    for core in _EGRESS_CORES:
        if core == "l2tp":
            if await _l2tp_has_egress_users(store):
                names.add(_PPP_TUNNEL)
                names.update(live_ppp_interface_names())
            continue
        if core == "openvpn":
            if await _openvpn_has_egress_users(store):
                names.update(await _openvpn_tunnel_names(store))
                names.add(_OPENVPN_TUNNEL)
            continue
        for row in await store.list_docs(core, _IFACE_KIND):
            name = str(row.get("name") or "").strip()
            if name:
                names.add(name)
    return sorted(names)


def live_ppp_interface_names() -> list[str]:
    net = Path("/sys/class/net")
    if not net.is_dir():
        return []
    return sorted(p.name for p in net.iterdir() if p.name.startswith("ppp") and p.is_dir())


def _forwarded_user_needs_tunnel(user: dict[str, Any]) -> bool:
    """True when this user's packets are forwarded out an exit or the main table.

    A linked companion with no exit is prohibited and does not need a tunnel
    match. Everyone else who is enabled and has an address does, including
    standalone users whose ``exit_interface`` is empty.
    """
    if not record_is_enabled(user) or not peer_source_cidr(user.get("address")):
        return False
    linked = str(user.get("linked_peer_id") or "").strip()
    if linked and normalize_exit_interface(user.get("exit_interface")) is None:
        return False
    return True


async def _l2tp_has_egress_users(store: Store) -> bool:
    for server in await store.list_docs("l2tp", _L2TP_KIND):
        for user in server.get("users") or []:
            if isinstance(user, dict) and _forwarded_user_needs_tunnel(user):
                return True
    return False


async def _openvpn_has_egress_users(store: Store) -> bool:
    for server in await store.list_docs("openvpn", _OPENVPN_KIND):
        for user in server.get("users") or []:
            if isinstance(user, dict) and _forwarded_user_needs_tunnel(user):
                return True
    return False


async def _openvpn_tunnel_names(store: Store) -> list[str]:
    names: set[str] = set()
    for server in await store.list_docs("openvpn", _OPENVPN_KIND):
        if not isinstance(server, dict):
            continue
        tun = str(server.get("tun_dev") or "").strip()
        if tun:
            names.add(tun)
            continue
        sid = server.get("id")
        if sid is not None:
            names.add(f"ovpn{sid}")
    return sorted(names)


def l2tp_servers_as_interfaces(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map L2TP server users into the interface/peers shape used by reconcile_core_egress."""
    peers: list[dict[str, Any]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        for user in server.get("users") or []:
            if not isinstance(user, dict):
                continue
            peers.append(dict(user))
    return [{"name": _PPP_TUNNEL, "peers": peers}]


def openvpn_servers_as_interfaces(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map OpenVPN server users into the interface/peers shape used by reconcile_core_egress."""
    rows: list[dict[str, Any]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        peers: list[dict[str, Any]] = []
        for user in server.get("users") or []:
            if not isinstance(user, dict):
                continue
            peers.append(dict(user))
        tun = str(server.get("tun_dev") or "").strip() or f"ovpn{server.get('id') or 0}"
        rows.append({"name": tun, "peers": peers})
    if not rows:
        return [{"name": _OPENVPN_TUNNEL, "peers": []}]
    return rows


def desired_rules_from_l2tp_servers(servers: list[dict[str, Any]]) -> list[dict[str, str | int]]:
    return desired_rules_from_interfaces(l2tp_servers_as_interfaces(servers))


def desired_rules_from_openvpn_servers(servers: list[dict[str, Any]]) -> list[dict[str, str | int]]:
    return desired_rules_from_interfaces(openvpn_servers_as_interfaces(servers))


def peer_source_cidr(address: Any) -> str | None:
    text = str(address or "").strip()
    if not text:
        return None
    host = text.split("/", 1)[0].strip()
    if not host:
        return None
    return f"{host}/32"


def peer_uses_main_table(peer: dict[str, Any]) -> bool:
    """Enabled peer with no explicit exit and no companion prohibit.

    Standalone (non-region) WireGuard peers are stored this way: the panel
    omits ``exit_interface`` unless the server is a region host. They must
    leave through the main-table default device, not a policy table.
    """
    if not isinstance(peer, dict):
        return False
    if not peer_source_cidr(peer.get("address")):
        return False
    if str(peer.get("linked_peer_id") or "").strip():
        return False
    if not record_is_enabled(peer):
        return False
    return normalize_exit_interface(peer.get("exit_interface")) is None


def peers_use_main_table(interfaces: list[dict[str, Any]]) -> bool:
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        for peer in iface.get("peers") or []:
            if peer_uses_main_table(peer):
                return True
    return False


def _interfaces_for_core(core: str, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if core == "l2tp":
        return l2tp_servers_as_interfaces(docs)
    if core == "openvpn":
        return openvpn_servers_as_interfaces(docs)
    return [row for row in docs if isinstance(row, dict)]


async def _core_interface_docs(store: Store, core: str) -> list[dict[str, Any]]:
    if core == "l2tp":
        return await store.list_docs(core, _L2TP_KIND)
    if core == "openvpn":
        return await store.list_docs(core, _OPENVPN_KIND)
    return await store.list_docs(core, _IFACE_KIND)


async def store_has_main_table_peers(store: Store) -> bool:
    for core in _EGRESS_CORES:
        docs = await _core_interface_docs(store, core)
        if peers_use_main_table(_interfaces_for_core(core, docs)):
            return True
    return False


async def _other_cores_use_main_table(store: Store, core: str) -> bool:
    for other in _EGRESS_CORES:
        if other == core:
            continue
        docs = await _core_interface_docs(store, other)
        if peers_use_main_table(_interfaces_for_core(other, docs)):
            return True
    return False


def device_from_route_text(text: str) -> str | None:
    """First ``dev`` token in an ``ip route`` line. Empty when the lookup failed."""
    devices = devices_from_route_text(text)
    return devices[0] if devices else None


def devices_from_route_text(text: str) -> list[str]:
    found: list[str] = []
    for line in str(text or "").splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        try:
            dev = parts[parts.index("dev") + 1]
        except IndexError:
            continue
        if dev and dev not in found:
            found.append(dev)
    return found


def _acceptable_egress_device(name: str, skip: set[str]) -> str | None:
    iface = normalize_exit_interface(name)
    if not iface or iface in skip or iface in {"lo", "lo0"}:
        return None
    return iface


def _stored_main_egress(state: dict[str, Any] | None) -> list[str]:
    raw = (state or {}).get("main_egress")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    found: list[str] = []
    for item in raw:
        name = str(item or "").strip()
        if name and name not in found:
            found.append(name)
    return found


def apply_script_path(data_dir: str | Path | None = None) -> Path:
    base = Path(data_dir or os.environ.get("DATA_DIR") or "/var/lib/agent")
    return base / "peer-egress-apply.sh"


def public_exit_ipv4(value: Any) -> str:
    """Public IPv4 a peer should SNAT to. Empty when missing or not public."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if (
        ip.version != 4
        or ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_link_local
        or ip.is_reserved
    ):
        return ""
    return str(ip)


async def preserve_public_sources(addresses: list[str], *, runner: Runner | None = None) -> None:
    """Keep an already-chosen public source. MASQUERADE would put the primary back."""
    ips: list[str] = []
    for raw in addresses:
        ip = public_exit_ipv4(raw)
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        return
    run = runner or process_run
    if shutil.which("nft"):
        await _nft(run, ["add", "table", "inet", "netinja_egress"])
        await _nft(
            run,
            [
                "add",
                "chain",
                "inet",
                "netinja_egress",
                "postrouting",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ],
        )
        try:
            listed = await execute(
                run,
                ["nft", "-a", "list", "chain", "inet", "netinja_egress", "postrouting"],
                check=False,
                timeout=10,
            )
            text = str(getattr(listed, "stdout", "") or "")
        except Exception:
            text = ""
        for ip in ips:
            comment = f"netinja-keep-{ip}"
            if comment in text:
                continue
            await _nft(
                run,
                [
                    "insert",
                    "rule",
                    "inet",
                    "netinja_egress",
                    "postrouting",
                    "ip",
                    "saddr",
                    ip,
                    "return",
                    "comment",
                    comment,
                ],
            )
        return
    binary = "iptables" if shutil.which("iptables") else ""
    if not binary:
        return
    for ip in ips:
        comment = f"netinja-keep-{ip}"
        exists = await _iptables(
            run,
            ["-t", "nat", "-C", "POSTROUTING", "-s", ip, "-m", "comment", "--comment", comment, "-j", "RETURN"],
            quiet=True,
            binary=binary,
        )
        if exists:
            continue
        await _iptables(
            run,
            ["-t", "nat", "-I", "POSTROUTING", "1", "-s", ip, "-m", "comment", "--comment", comment, "-j", "RETURN"],
            binary=binary,
        )


def egress_mark(ip: str) -> int:
    """Stable fwmark for one public source. Matches the panel's sockopt.mark."""
    address = public_exit_ipv4(ip)
    if not address:
        return 0
    last = int(ipaddress.ip_address(address)) & 0xFFFF
    return 0x51000000 | last


async def pin_public_egress(ip: str, mark: int = 0, *, runner: Runner | None = None) -> None:
    """Stop MASQUERADE from rewriting a node address back to the server primary.

    Runs before the normal srcnat hook. Packets already using the node IP are
    left alone. Packets marked by that node's Xray outbound are rewritten to it.
    """
    address = public_exit_ipv4(ip)
    if not address:
        return
    run = runner or process_run
    wanted = mark if mark > 0 else egress_mark(address)
    if shutil.which("nft"):
        await _nft(run, ["add", "table", "inet", "netinja_egress"])
        await _nft(
            run,
            [
                "add",
                "chain",
                "inet",
                "netinja_egress",
                "srcpin",
                "{ type nat hook postrouting priority -10; policy accept; }",
            ],
        )
        try:
            listed = await execute(
                run,
                ["nft", "-a", "list", "chain", "inet", "netinja_egress", "srcpin"],
                check=False,
                timeout=10,
            )
            text = str(getattr(listed, "stdout", "") or "")
        except Exception:
            text = ""
        keep = f"netinja-pin-{address}"
        if keep not in text:
            await _nft(
                run,
                [
                    "add", "rule", "inet", "netinja_egress", "srcpin",
                    "ip", "saddr", address, "accept", "comment", keep,
                ],
            )
        stamped = f"netinja-mark-{wanted}"
        if wanted > 0 and stamped not in text:
            await _nft(
                run,
                [
                    "add", "rule", "inet", "netinja_egress", "srcpin",
                    "meta", "mark", hex(wanted),
                    "snat", "to", address,
                    "accept",
                    "comment", stamped,
                ],
            )
        return
    binary = "iptables" if shutil.which("iptables") else ""
    if not binary:
        return
    keep = f"netinja-pin-{address}"
    if not await _iptables(
        run,
        ["-t", "nat", "-C", "POSTROUTING", "-s", address, "-m", "comment", "--comment", keep, "-j", "ACCEPT"],
        quiet=True,
        binary=binary,
    ):
        await _iptables(
            run,
            ["-t", "nat", "-I", "POSTROUTING", "1", "-s", address, "-m", "comment", "--comment", keep, "-j", "ACCEPT"],
            binary=binary,
        )
    if wanted <= 0:
        return
    stamped = f"netinja-mark-{wanted}"
    if await _iptables(
        run,
        [
            "-t", "nat", "-C", "POSTROUTING", "-m", "mark", "--mark", hex(wanted),
            "-m", "comment", "--comment", stamped, "-j", "SNAT", "--to-source", address,
        ],
        quiet=True,
        binary=binary,
    ):
        return
    await _iptables(
        run,
        [
            "-t", "nat", "-I", "POSTROUTING", "1", "-m", "mark", "--mark", hex(wanted),
            "-m", "comment", "--comment", stamped, "-j", "SNAT", "--to-source", address,
        ],
        binary=binary,
    )


_PIN_GENERATION = 1
_PIN_CHAIN = "peersrc"


def _pin_rows(rules: list[dict[str, str | int]]) -> list[dict[str, str]]:
    """Tunnel sources that must leave as a node IP, before any MASQUERADE."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rules:
        if str(row.get("action") or "lookup") == "prohibit":
            continue
        snat = public_exit_ipv4(row.get("snat"))
        addr = str(row.get("addr") or "").strip()
        cidr = str(row.get("cidr") or "").strip() or (f"{addr}/32" if addr else "")
        if not snat or not cidr:
            continue
        key = (cidr, snat)
        if key in seen:
            continue
        seen.add(key)
        found.append({"cidr": cidr, "snat": snat, "addr": addr or cidr.split("/", 1)[0]})
    return found


async def ensure_peer_source_pins(
    store: Store,
    *,
    runner: Runner | None = None,
    rules: list[dict[str, str | int]] | None = None,
) -> None:
    """SNAT WireGuard/Amnezia/L2TP/OpenVPN sources before the host MASQUERADE.

    Xray pins itself with a packet mark. These cores keep the tunnel address
    until postrouting, and a later MASQUERADE puts the server primary back.
    """
    source = rules if rules is not None else await all_desired_rules_from_store(store)
    rows = _pin_rows(source)
    run = runner or process_run
    await _install_peer_source_pins(rows, runner=run)
    marker = await store.get_doc("network", _STATE_KIND, "pin") or {}
    if int(marker.get("generation") or 0) == _PIN_GENERATION:
        return
    for row in rows:
        await _flush_conntrack(run, str(row.get("addr") or ""))
    await store.put_doc("network", _STATE_KIND, "pin", {"generation": _PIN_GENERATION})


async def _install_peer_source_pins(rows: list[dict[str, str]], *, runner: Runner) -> None:
    if shutil.which("nft"):
        await _nft(runner, ["add", "table", "inet", "netinja_egress"])
        await _nft(
            runner,
            [
                "add", "chain", "inet", "netinja_egress", _PIN_CHAIN,
                "{ type nat hook postrouting priority -10; policy accept; }",
            ],
        )
        try:
            listed = await execute(
                runner,
                ["nft", "list", "chain", "inet", "netinja_egress", _PIN_CHAIN],
                check=False,
                timeout=10,
            )
            text = str(getattr(listed, "stdout", "") or "")
        except Exception:
            text = ""
        if text.count("snat to") == len(rows) and all(
            f"saddr {row['cidr']}" in text and f"snat to {row['snat']}" in text for row in rows
        ):
            return
        await _nft(runner, ["flush", "chain", "inet", "netinja_egress", _PIN_CHAIN])
        for row in rows:
            host = str(row.get("addr") or row["cidr"].split("/", 1)[0])
            await _nft(
                runner,
                [
                    "add", "rule", "inet", "netinja_egress", _PIN_CHAIN,
                    "ip", "saddr", row["cidr"],
                    "snat", "to", row["snat"],
                    "accept",
                    "comment", f"netinja-peer-{host}",
                ],
            )
        return
    binary = "iptables" if shutil.which("iptables") else ""
    if not binary:
        return
    for row in rows:
        comment = f"netinja-peer-{row.get('addr') or row['cidr'].split('/', 1)[0]}"
        if await _iptables(
            runner,
            [
                "-t", "nat", "-C", "POSTROUTING", "-s", row["cidr"],
                "-m", "comment", "--comment", comment, "-j", "SNAT", "--to-source", row["snat"],
            ],
            quiet=True,
            binary=binary,
        ):
            continue
        await _iptables(
            runner,
            [
                "-t", "nat", "-I", "POSTROUTING", "1", "-s", row["cidr"],
                "-m", "comment", "--comment", comment, "-j", "SNAT", "--to-source", row["snat"],
            ],
            binary=binary,
        )


def _with_snat(row: dict[str, str | int], snat: str) -> dict[str, str | int]:
    if snat:
        row["snat"] = snat
    return row


def desired_rules_from_interfaces(interfaces: list[dict[str, Any]]) -> list[dict[str, str | int]]:
    rules: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for iface in interfaces:
        for peer in iface.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            cidr = peer_source_cidr(peer.get("address"))
            if not cidr:
                continue
            addr = cidr.split("/", 1)[0]
            if addr in seen:
                continue
            linked = str(peer.get("linked_peer_id") or "").strip()
            exit_iface = normalize_exit_interface(peer.get("exit_interface"))
            if linked and (not record_is_enabled(peer) or not exit_iface):
                seen.add(addr)
                rules.append(
                    {
                        "addr": addr,
                        "cidr": cidr,
                        "iface": "",
                        "table": 0,
                        "action": "prohibit",
                    }
                )
                continue
            if not record_is_enabled(peer) or not exit_iface:
                continue
            seen.add(addr)
            rules.append(
                _with_snat(
                    {
                        "addr": addr,
                        "cidr": cidr,
                        "iface": exit_iface,
                        "table": table_id_for_interface(exit_iface),
                        "action": "lookup",
                    },
                    public_exit_ipv4(peer.get("exit_ipv4")),
                )
            )
    return rules


async def all_desired_rules_from_store(store: Store) -> list[dict[str, str | int]]:
    """Prefer live interface docs; fall back to last applied egress_state."""
    merged: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for core in _EGRESS_CORES:
        if core in {"l2tp", "openvpn"}:
            kind = _L2TP_KIND if core == "l2tp" else _OPENVPN_KIND
            servers = await store.list_docs(core, kind)
            if servers:
                source = (
                    desired_rules_from_l2tp_servers(servers)
                    if core == "l2tp"
                    else desired_rules_from_openvpn_servers(servers)
                )
            else:
                state = await store.get_doc(core, _STATE_KIND, _STATE_ID) or {}
                source = []
                for row in state.get("rules") or []:
                    if not isinstance(row, dict):
                        continue
                    addr = str(row.get("addr") or "").strip()
                    action = str(row.get("action") or "lookup")
                    iface = str(row.get("iface") or "").strip()
                    table = int(row.get("table") or 0)
                    if not addr:
                        continue
                    if action == "prohibit":
                        source.append(
                            {
                                "addr": addr,
                                "cidr": f"{addr}/32",
                                "iface": "",
                                "table": 0,
                                "action": "prohibit",
                            }
                        )
                        continue
                    if not iface or table <= 0:
                        continue
                    source.append(
                        _with_snat(
                            {
                                "addr": addr,
                                "cidr": f"{addr}/32",
                                "iface": iface,
                                "table": table,
                                "action": "lookup",
                            },
                            public_exit_ipv4(row.get("snat")),
                        )
                    )
        else:
            ifaces = await store.list_docs(core, _IFACE_KIND)
            if ifaces:
                source = desired_rules_from_interfaces(ifaces)
            else:
                state = await store.get_doc(core, _STATE_KIND, _STATE_ID) or {}
                source = []
                for row in state.get("rules") or []:
                    if not isinstance(row, dict):
                        continue
                    addr = str(row.get("addr") or "").strip()
                    action = str(row.get("action") or "lookup")
                    iface = str(row.get("iface") or "").strip()
                    table = int(row.get("table") or 0)
                    if not addr:
                        continue
                    if action == "prohibit":
                        source.append(
                            {
                                "addr": addr,
                                "cidr": f"{addr}/32",
                                "iface": "",
                                "table": 0,
                                "action": "prohibit",
                            }
                        )
                        continue
                    if not iface or table <= 0:
                        continue
                    source.append(
                        _with_snat(
                            {
                                "addr": addr,
                                "cidr": f"{addr}/32",
                                "iface": iface,
                                "table": table,
                                "action": "lookup",
                            },
                            public_exit_ipv4(row.get("snat")),
                        )
                    )
        for row in source:
            addr = str(row["addr"])
            if addr in seen:
                continue
            seen.add(addr)
            merged.append(row)
    return merged


def render_apply_script(
    rules: list[dict[str, str | int]],
    tunnel_ifaces: list[str] | None = None,
    bind_ifaces: list[str] | None = None,
    *,
    masquerade_main_table: bool = False,
    public_pins: list[dict[str, Any]] | None = None,
) -> str:
    """Self-contained shell script so egress survives reboot (wg-quick PostUp / systemd)."""
    lines = [
        "#!/bin/sh",
        "# Generated by Netinja agent — peer egress policy routing. Do not edit.",
        "set +e",
        "# One apply at a time. wg-quick PostUp and agent start can invoke this",
        "# together; extra copies must return immediately so boot is not stacked.",
        "if command -v flock >/dev/null 2>&1; then",
        '  exec 9>"$0.lock"',
        "  if ! flock -n 9; then",
        '    echo "peer-egress: another apply is running; skipping" >&2',
        "    exit 0",
        "  fi",
        "fi",
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true",
        "",
    ]
    if masquerade_main_table:
        lines.extend(
            [
                "# Peers with no exit_interface follow the main table. Resolve the",
                "# egress device at apply time so a renamed uplink is picked up",
                "# without baking a host-specific interface name into this script.",
                "_main_egress_dev() {",
                "  dev=\"$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}')\"",
                "  if [ -z \"$dev\" ]; then",
                "    dev=\"$(ip -4 route show default 2>/dev/null | awk '$1==\"default\"{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}')\"",
                "  fi",
                "  printf '%s\\n' \"$dev\"",
                "}",
                "",
            ]
        )
    lines.extend(
        [
        '_iface_ready() {',
        '  ip link show "$1" >/dev/null 2>&1',
        '}',
        "",
        '_soften_rp_filter() {',
        '  iface="$1"',
        '  sysctl -w "net.ipv4.conf.${iface}.rp_filter=0" >/dev/null 2>&1 || true',
        '}',
        "",
        '_default_for_iface() {',
        '  iface="$1"',
        '  table="$2"',
        '  if ! _iface_ready "$iface"; then',
        '    echo "peer-egress: exit interface missing: $iface (table $table)" >&2',
        '    return 1',
        '  fi',
        '  _soften_rp_filter "$iface"',
        '  via="$(ip -4 route show default 2>/dev/null | awk -v d="$iface" \'{for(i=1;i<=NF;i++) if($i=="dev" && $(i+1)==d){for(j=1;j<=NF;j++) if($j=="via"){print $(j+1); exit}}}\')"',
        '  if [ -n "$via" ]; then',
        '    ip route replace default via "$via" dev "$iface" table "$table" 2>/dev/null || return 1',
        '  else',
        '    ip route replace default dev "$iface" table "$table" 2>/dev/null || return 1',
        '  fi',
        '}',
        "",
        ]
    )

    masq: set[str] = set()
    lookup_rows: list[tuple[str, str, int, str, int]] = []
    for row in rules:
        addr = str(row["addr"])
        cidr = str(row.get("cidr") or f"{addr}/32")
        pref = rule_pref_for_addr(addr)
        if str(row.get("action") or "lookup") == "prohibit":
            lines.append(f'ip rule del from "{cidr}" prohibit 2>/dev/null || true')
            lines.append(
                f'ip rule add from "{cidr}" pref {pref} prohibit 2>/dev/null || true'
            )
            continue
        table = int(row["table"])
        iface = str(row["iface"])
        if iface:
            masq.add(iface)
        lookup_rows.append((addr, cidr, pref, iface, table))

    # Probe each exit once. PostUp runs this script while awg-quick/wg-quick is
    # still in the foreground. A transferred host can point hundreds of peers at
    # the same missing NIC (nl, tr, de); probing inside every peer blows the
    # bring-up timeout and the agent kills the userspace daemon.
    probed: set[tuple[str, int]] = set()
    for _addr, _cidr, _pref, iface, table in lookup_rows:
        key = (iface, table)
        if key in probed:
            continue
        probed.add(key)
        lines.append(f'if _default_for_iface "{iface}" {table}; then')
        lines.append(f"  _ready_{table}=1")
        lines.append("else")
        lines.append(f"  _ready_{table}=0")
        lines.append("fi")
    if lookup_rows:
        lines.append("")

    for _addr, cidr, pref, iface, table in lookup_rows:
        # Install the table, then the rule, at a stable preference.
        # Do not sleep when the exit interface is missing.
        # NEVER delete the lookup rule on failure — that dumps traffic onto the
        # region primary IP via the main routing table.
        lines.append(f'if [ "${{_ready_{table}:-0}}" = 1 ]; then')
        lines.append(f'  ip rule del from "{cidr}" lookup {table} 2>/dev/null || true')
        lines.append(f'  ip rule del from "{cidr}" prohibit 2>/dev/null || true')
        lines.append(
            f'  ip rule add from "{cidr}" lookup {table} pref {pref} 2>/dev/null || true'
        )
        lines.append("else")
        lines.append(
            f'  echo "peer-egress: deferred {cidr} -> {iface} '
            f'(interface missing or route failed; keeping existing rule)" >&2'
        )
        lines.append("fi")

    lines.append("")
    tunnels = sorted({str(name).strip() for name in (tunnel_ifaces or []) if str(name).strip()})
    for tunnel in tunnels:
        lines.append(f'_soften_rp_filter "{tunnel}"')
    if tunnels:
        lines.append("")

    if masquerade_main_table:
        lines.extend(
            [
                '_main_dev="$(_main_egress_dev)"',
                'case "$_main_dev" in',
                '  ""|lo|lo0) _main_dev="" ;;',
            ]
        )
        skip_names = sorted(set(tunnels) | set(masq))
        for name in skip_names:
            lines.append(f'  {name}) _main_dev="" ;;')
        lines.extend(
            [
                "esac",
                'if [ -n "$_main_dev" ]; then',
                '  _soften_rp_filter "$_main_dev"',
                "fi",
                "",
            ]
        )

    # Prefer a SINGLE NAT backend to avoid double MASQUERADE (causes packet loss).
    lines.extend(
        [
            "if command -v nft >/dev/null 2>&1; then",
            "  nft add table inet netinja_egress 2>/dev/null || true",
            "  nft add chain inet netinja_egress postrouting "
            '"{ type nat hook postrouting priority srcnat; policy accept; }" 2>/dev/null || true',
            "  nft add chain inet netinja_egress peersrc "
            '"{ type nat hook postrouting priority -10; policy accept; }" 2>/dev/null || true',
            "  nft flush chain inet netinja_egress peersrc 2>/dev/null || true",
            "  nft add chain inet netinja_egress forward "
            '"{ type filter hook forward priority filter; policy accept; }" 2>/dev/null || true',
            "  nft flush chain inet netinja_egress postrouting 2>/dev/null || true",
            "  nft flush chain inet netinja_egress forward 2>/dev/null || true",
        ]
    )
    _append_nft_snat_shell(lines, _snat_rows(rules))
    for iface in sorted(masq):
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        lines.append(
            f'  nft add rule inet netinja_egress postrouting oifname "{iface}" '
            f'masquerade comment "{comment}" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward oifname "{iface}" '
            f'tcp flags syn / syn,rst tcp option maxseg size set rt mtu '
            f'comment "{comment}-mss" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward oifname "{iface}" '
            f'accept comment "{comment}-fwd-out" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward iifname "{iface}" '
            f'ct state related,established accept comment "{comment}-fwd-in" 2>/dev/null || true'
        )
    if masquerade_main_table:
        _append_main_table_nft_shell(lines, tunnels)
    for tunnel in tunnels:
        tunnel_comment = _tunnel_egress_comment(tunnel)
        match = _nft_iface_match(tunnel)
        lines.append(
            f'  nft add rule inet netinja_egress forward iifname "{match}" '
            f'tcp flags syn / syn,rst tcp option maxseg size set rt mtu '
            f'comment "{tunnel_comment}-mss" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward iifname "{match}" '
            f'accept comment "{tunnel_comment}-in" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward oifname "{match}" '
            f'accept comment "{tunnel_comment}-out" 2>/dev/null || true'
        )
    # When nft owns NAT, strip duplicate iptables MASQUERADE (double SNAT = packet loss).
    lines.append("  if command -v iptables >/dev/null 2>&1; then")
    for iface in sorted(masq):
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        lines.append(
            f'    while iptables -t nat -D POSTROUTING -o "{iface}" -j MASQUERADE 2>/dev/null; do :; done'
        )
        lines.append(
            f'    while iptables -t nat -D POSTROUTING -o "{iface}" -m comment --comment "{comment}" '
            f"-j MASQUERADE 2>/dev/null; do :; done"
        )
    lines.append("  fi")
    lines.append("  if command -v iptables-legacy >/dev/null 2>&1; then")
    for iface in sorted(masq):
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        lines.append(
            f'    while iptables-legacy -t nat -D POSTROUTING -o "{iface}" -j MASQUERADE 2>/dev/null; do :; done'
        )
        lines.append(
            f'    while iptables-legacy -t nat -D POSTROUTING -o "{iface}" -m comment --comment "{comment}" '
            f"-j MASQUERADE 2>/dev/null; do :; done"
        )
    lines.append("  fi")
    lines.append("elif command -v iptables >/dev/null 2>&1; then")
    _append_iptables_snat_shell(lines, _snat_rows(rules), binary="iptables", indent="  ")
    _append_iptables_firewall_shell(lines, binary="iptables", masq=masq, tunnels=tunnels, indent="  ")
    if masquerade_main_table:
        _append_main_table_iptables_shell(lines, binary="iptables", tunnels=tunnels, indent="  ")
    lines.append("elif command -v iptables-legacy >/dev/null 2>&1; then")
    _append_iptables_snat_shell(lines, _snat_rows(rules), binary="iptables-legacy", indent="  ")
    _append_iptables_firewall_shell(lines, binary="iptables-legacy", masq=masq, tunnels=tunnels, indent="  ")
    if masquerade_main_table:
        _append_main_table_iptables_shell(lines, binary="iptables-legacy", tunnels=tunnels, indent="  ")
    lines.append("fi")
    lines.append("")

    if bind_ifaces:
        from agent.support.xray_exit_bind import script_lines

        lines.extend(script_lines(bind_ifaces))
    from agent.support.xray_exit_bind import load_public_pins, public_pin_script_lines

    lines.extend(public_pin_script_lines(load_public_pins() if public_pins is None else public_pins))
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


def _snat_rows(rules: list[dict[str, str | int]]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rules:
        if str(row.get("action") or "lookup") == "prohibit":
            continue
        snat = public_exit_ipv4(row.get("snat"))
        iface = normalize_exit_interface(row.get("iface"))
        addr = str(row.get("addr") or "").strip()
        cidr = str(row.get("cidr") or "").strip() or (f"{addr}/32" if addr else "")
        if not snat or not iface or not cidr:
            continue
        key = (cidr, iface, snat)
        if key in seen:
            continue
        seen.add(key)
        found.append({"cidr": cidr, "iface": iface, "snat": snat})
    return found


def _append_nft_snat_shell(lines: list[str], rows: list[dict[str, str]]) -> None:
    """SNAT each peer to its node IP before the interface MASQUERADE.

    peersrc runs before the normal srcnat hook, so a host MASQUERADE cannot
    put the server primary back on WireGuard, Amnezia, L2TP, or OpenVPN.
    """
    kept: set[str] = set()
    for row in rows:
        host = row["cidr"].split("/", 1)[0]
        lines.append(
            f'  nft add rule inet netinja_egress peersrc ip saddr {row["cidr"]} '
            f'snat to {row["snat"]} accept comment "netinja-peer-{host}" 2>/dev/null || true'
        )
    for row in rows:
        comment = f"netinja-src-{row['snat']}"
        lines.append(
            f'  nft add rule inet netinja_egress postrouting ip saddr {row["cidr"]} '
            f'oifname "{row["iface"]}" snat to {row["snat"]} accept comment "{comment}" 2>/dev/null || true'
        )
        kept.add(row["snat"])
    for ip in sorted(kept):
        lines.append(
            f'  nft add rule inet netinja_egress postrouting ip saddr {ip} '
            f'accept comment "netinja-keep-{ip}" 2>/dev/null || true'
        )


def _append_iptables_snat_shell(
    lines: list[str],
    rows: list[dict[str, str]],
    *,
    binary: str,
    indent: str,
) -> None:
    kept: set[str] = set()
    for row in rows:
        comment = f"netinja-src-{row['snat']}"
        lines.append(
            f'{indent}{binary} -t nat -C POSTROUTING -s {row["cidr"]} -o "{row["iface"]}" '
            f'-m comment --comment "{comment}" -j SNAT --to-source {row["snat"]} 2>/dev/null || '
            f'{binary} -t nat -I POSTROUTING 1 -s {row["cidr"]} -o "{row["iface"]}" '
            f'-m comment --comment "{comment}" -j SNAT --to-source {row["snat"]}'
        )
        kept.add(row["snat"])
    for ip in sorted(kept):
        comment = f"netinja-keep-{ip}"
        lines.append(
            f'{indent}{binary} -t nat -C POSTROUTING -s {ip} -m comment --comment "{comment}" '
            f'-j RETURN 2>/dev/null || '
            f'{binary} -t nat -I POSTROUTING 1 -s {ip} -m comment --comment "{comment}" -j RETURN'
        )


def _append_main_table_nft_shell(lines: list[str], tunnels: list[str]) -> None:
    """SNAT only tunnel-sourced traffic out the live main-table device.

    The device name is ``$_main_dev`` in the generated script. Explicit exit
    NICs keep their own oifname rules and are not repeated here.
    """
    lines.extend(
        [
            '  if [ -n "$_main_dev" ]; then',
            '    _main_comment="' + _MASQ_COMMENT_PREFIX + '${_main_dev}"',
        ]
    )
    if tunnels:
        for tunnel in tunnels:
            match = _nft_iface_match(tunnel)
            lines.append(
                f'    nft add rule inet netinja_egress postrouting iifname "{match}" '
                'oifname "$_main_dev" masquerade comment "$_main_comment" 2>/dev/null || true'
            )
    else:
        lines.append(
            '    nft add rule inet netinja_egress postrouting oifname "$_main_dev" '
            'masquerade comment "$_main_comment" 2>/dev/null || true'
        )
    lines.extend(
        [
            '    nft add rule inet netinja_egress forward oifname "$_main_dev" '
            'tcp flags syn / syn,rst tcp option maxseg size set rt mtu '
            'comment "${_main_comment}-mss" 2>/dev/null || true',
            '    nft add rule inet netinja_egress forward oifname "$_main_dev" '
            'accept comment "${_main_comment}-fwd-out" 2>/dev/null || true',
            '    nft add rule inet netinja_egress forward iifname "$_main_dev" '
            'ct state related,established accept comment "${_main_comment}-fwd-in" '
            '2>/dev/null || true',
            "  fi",
        ]
    )


def _append_main_table_iptables_shell(
    lines: list[str],
    *,
    binary: str,
    tunnels: list[str],
    indent: str,
) -> None:
    """Same main-table NAT as nft, for hosts whose iptables is not nft-backed."""
    pad = indent
    lines.append(f'{pad}if [ -n "$_main_dev" ]; then')
    lines.append(f'{pad}  _main_comment="{_MASQ_COMMENT_PREFIX}${{_main_dev}}"')
    sources = tunnels or [""]
    for tunnel in sources:
        incoming = f'-i "{tunnel}" ' if tunnel else ""
        lines.append(
            f'{pad}  {binary} -t nat -C POSTROUTING {incoming}-o "$_main_dev" '
            f'-m comment --comment "$_main_comment" -j MASQUERADE 2>/dev/null || '
            f'{binary} -t nat -A POSTROUTING {incoming}-o "$_main_dev" '
            f'-m comment --comment "$_main_comment" -j MASQUERADE'
        )
    lines.append(
        f'{pad}  {binary} -C FORWARD -o "$_main_dev" -p tcp --tcp-flags SYN,RST SYN '
        f'-m comment --comment "$_main_comment-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || '
        f'{binary} -I FORWARD 1 -o "$_main_dev" -p tcp --tcp-flags SYN,RST SYN '
        f'-m comment --comment "$_main_comment-mss" -j TCPMSS --clamp-mss-to-pmtu'
    )
    lines.append(
        f'{pad}  {binary} -C FORWARD -o "$_main_dev" -m comment --comment "$_main_comment-fwd-out" '
        f'-j ACCEPT 2>/dev/null || '
        f'{binary} -I FORWARD 1 -o "$_main_dev" -m comment --comment "$_main_comment-fwd-out" -j ACCEPT'
    )
    lines.append(
        f'{pad}  {binary} -C FORWARD -i "$_main_dev" -m state --state RELATED,ESTABLISHED '
        f'-m comment --comment "$_main_comment-fwd-in" -j ACCEPT 2>/dev/null || '
        f'{binary} -I FORWARD 1 -i "$_main_dev" -m state --state RELATED,ESTABLISHED '
        f'-m comment --comment "$_main_comment-fwd-in" -j ACCEPT'
    )
    lines.append(f"{pad}fi")


def _append_iptables_firewall_shell(
    lines: list[str],
    *,
    binary: str,
    masq: set[str],
    tunnels: list[str],
    indent: str = "  ",
) -> None:
    """Idempotent MASQUERADE + FORWARD (+ MSS) for exit NICs and WG/Amnezia tunnels."""
    for iface in sorted(masq):
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        lines.append(
            f'{indent}{binary} -t nat -C POSTROUTING -o "{iface}" -m comment --comment "{comment}" '
            f"-j MASQUERADE 2>/dev/null || "
            f'{binary} -t nat -A POSTROUTING -o "{iface}" -m comment --comment "{comment}" -j MASQUERADE'
        )
        lines.append(
            f'{indent}{binary} -C FORWARD -o "{iface}" -p tcp --tcp-flags SYN,RST SYN '
            f'-m comment --comment "{comment}-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || '
            f'{binary} -I FORWARD 1 -o "{iface}" -p tcp --tcp-flags SYN,RST SYN '
            f'-m comment --comment "{comment}-mss" -j TCPMSS --clamp-mss-to-pmtu'
        )
        lines.append(
            f'{indent}{binary} -C FORWARD -o "{iface}" -m comment --comment "{comment}-fwd-out" '
            f"-j ACCEPT 2>/dev/null || "
            f'{binary} -I FORWARD 1 -o "{iface}" -m comment --comment "{comment}-fwd-out" -j ACCEPT'
        )
        lines.append(
            f'{indent}{binary} -C FORWARD -i "{iface}" -m state --state RELATED,ESTABLISHED '
            f'-m comment --comment "{comment}-fwd-in" -j ACCEPT 2>/dev/null || '
            f'{binary} -I FORWARD 1 -i "{iface}" -m state --state RELATED,ESTABLISHED '
            f'-m comment --comment "{comment}-fwd-in" -j ACCEPT'
        )
    for tunnel in tunnels:
        tunnel_comment = _tunnel_egress_comment(tunnel)
        lines.append(
            f'{indent}{binary} -C FORWARD -i "{tunnel}" -p tcp --tcp-flags SYN,RST SYN '
            f'-m comment --comment "{tunnel_comment}-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || '
            f'{binary} -I FORWARD 1 -i "{tunnel}" -p tcp --tcp-flags SYN,RST SYN '
            f'-m comment --comment "{tunnel_comment}-mss" -j TCPMSS --clamp-mss-to-pmtu'
        )
        lines.append(
            f'{indent}{binary} -C FORWARD -i "{tunnel}" -m comment --comment "{tunnel_comment}-in" '
            f"-j ACCEPT 2>/dev/null || "
            f'{binary} -I FORWARD 1 -i "{tunnel}" -m comment --comment "{tunnel_comment}-in" -j ACCEPT'
        )
        lines.append(
            f'{indent}{binary} -C FORWARD -o "{tunnel}" -m comment --comment "{tunnel_comment}-out" '
            f"-j ACCEPT 2>/dev/null || "
            f'{binary} -I FORWARD 1 -o "{tunnel}" -m comment --comment "{tunnel_comment}-out" -j ACCEPT'
        )


async def write_apply_script(
    rules: list[dict[str, str | int]],
    *,
    data_dir: str | Path | None = None,
    tunnel_ifaces: list[str] | None = None,
) -> Path:
    from agent.support.xray_exit_bind import load_bind_ifaces

    path = apply_script_path(data_dir)
    await aiofs.atomic_write(
        path,
        render_apply_script(
            rules,
            tunnel_ifaces,
            bind_ifaces=load_bind_ifaces(),
            masquerade_main_table=False,
        ),
        encoding="utf-8",
    )
    try:
        await aiofs.chmod(path, 0o755)
    except (OSError, AttributeError):
        pass
    return path


async def ensure_peer_egress_unit(
    script_path: Path,
    *,
    runner: Runner | None = None,
    start: bool = False,
) -> dict[str, Any]:
    """Install/enable a oneshot systemd unit that restores egress after reboot.

    ``start`` should be true only when the apply script content actually changed;
    starting on every reconcile flushed nft NAT and caused periodic packet loss.
    """
    if not shutil.which("systemctl"):
        return {"ok": False, "skipped": True, "reason": "systemctl not found"}

    unit = "\n".join(
        [
            "[Unit]",
            "Description=Netinja peer egress routing (WireGuard/Amnezia)",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={script_path}",
            "RemainAfterExit=yes",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )

    try:
        _UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        previous = (
            await aiofs.read_text(_UNIT_PATH, encoding="utf-8") if _UNIT_PATH.is_file() else ""
        )
        if previous != unit:
            await aiofs.atomic_write(_UNIT_PATH, unit, encoding="utf-8")
            await execute(runner, ["systemctl", "daemon-reload"], check=False, timeout=30)
    except OSError as exc:
        log.warning("peer egress unit write failed: %s", exc)
        return {"ok": False, "skipped": False, "reason": str(exc)}

    already_enabled = _peer_egress_unit_enabled(_UNIT_PATH)
    if already_enabled:
        enable_ok = True
    else:
        enable = await execute(runner, ["systemctl", "enable", _UNIT_NAME], check=False, timeout=30)
        enable_ok = getattr(enable, "returncode", 1) == 0
    started = False
    if start:
        start_result = await execute(runner, ["systemctl", "start", _UNIT_NAME], check=False, timeout=60)
        started = getattr(start_result, "returncode", 1) == 0
    return {
        "ok": enable_ok,
        "started": started,
        "already_enabled": already_enabled,
        "unit": str(_UNIT_PATH),
        "script": str(script_path),
    }


async def persist_peer_egress(
    store: Store,
    *,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
    force_start: bool = False,
    start_unit: bool | None = None,
) -> dict[str, Any]:
    from agent.support.xray_exit_bind import load_bind_ifaces

    rules = await all_desired_rules_from_store(store)
    tunnels = await all_tunnel_interface_names(store)
    path = apply_script_path(data_dir)
    new_text = render_apply_script(
        rules,
        tunnels,
        bind_ifaces=load_bind_ifaces(),
        masquerade_main_table=await store_has_main_table_peers(store),
    )
    previous = await aiofs.read_text(path, encoding="utf-8") if path.is_file() else None
    changed = previous != new_text
    if changed:
        await aiofs.atomic_write(path, new_text, encoding="utf-8")
        try:
            await aiofs.chmod(path, 0o755)
        except (OSError, AttributeError):
            pass
    should_start = (changed or force_start) if start_unit is None else bool(start_unit)
    unit = await ensure_peer_egress_unit(path, runner=runner, start=should_start)
    return {"script": str(path), "rules": len(rules), "changed": changed, "unit": unit}


_l2tp_egress_state_lock = asyncio.Lock()


async def write_egress_script_only(
    store: Store,
    *,
    data_dir: str | Path | None = None,
) -> bool:
    """Refresh the boot apply script without starting systemd or touching nft.

    Live rules are installed by the caller. Starting the oneshot re-runs every
    iptables/nft statement and is what made a single user create exceed 15s.
    """
    from agent.support.xray_exit_bind import load_bind_ifaces

    rules = await all_desired_rules_from_store(store)
    tunnels = await all_tunnel_interface_names(store)
    path = apply_script_path(data_dir)
    new_text = render_apply_script(
        rules,
        tunnels,
        bind_ifaces=load_bind_ifaces(),
        masquerade_main_table=await store_has_main_table_peers(store),
    )
    previous = await aiofs.read_text(path, encoding="utf-8") if path.is_file() else None
    if previous == new_text:
        return False
    await aiofs.atomic_write(path, new_text, encoding="utf-8")
    try:
        await aiofs.chmod(path, 0o755)
    except (OSError, AttributeError):
        pass
    return True


async def apply_l2tp_user_egress(
    store: Store,
    user: dict[str, Any],
    *,
    previous_address: str | None = None,
    remove: bool = False,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Install or remove policy routing for one L2TP address.

    Does not rebuild NAT, flush nft, or walk every other peer. Shared exit
    interfaces already have MASQUERADE from the server/WireGuard reconcile.
    """
    current = str(peer_source_cidr(user.get("address")) or "").split("/", 1)[0].strip()
    previous = str(previous_address or "").split("/", 1)[0].strip()
    desired = [] if remove else desired_rules_from_interfaces([{"name": _PPP_TUNNEL, "peers": [user]}])
    desired_addrs = {str(row["addr"]) for row in desired}

    if not shutil.which("ip"):
        async with _l2tp_egress_state_lock:
            await _merge_l2tp_egress_state(store, desired, drop_addrs=_drop_addrs(current, previous, desired_addrs, remove))
        return {"ok": True, "skipped": True, "reason": "ip not found"}

    cache = _EgressCache()
    drop = _drop_addrs(current, previous, desired_addrs, remove)
    deferred: list[str] = []
    applied: list[dict[str, str | int]] = []

    for addr in sorted(drop):
        await _delete_policy_for_host(runner, addr, cache)

    for row in desired:
        outcome = await _install_one_egress_rule(runner, row, cache)
        if outcome == "deferred":
            deferred.append(str(row["addr"]))
            continue
        if outcome == "applied":
            applied.append(row)

    async with _l2tp_egress_state_lock:
        await _merge_l2tp_egress_state(
            store,
            applied,
            drop_addrs=set(drop) | {str(row["addr"]) for row in applied},
            retain_addrs=set(deferred),
        )
    try:
        await ensure_peer_source_pins(store, runner=runner)
    except Exception:
        log.exception("peer source pin failed")
    return {
        "ok": True,
        "applied": len(applied),
        "deferred": deferred,
        "removed": sorted(drop),
    }


def _drop_addrs(current: str, previous: str, desired_addrs: set[str], remove: bool) -> set[str]:
    drop: set[str] = set()
    if previous and previous != current:
        drop.add(previous)
    if remove and current:
        drop.add(current)
    if current and current not in desired_addrs:
        drop.add(current)
    return drop


async def _delete_policy_for_host(runner: Runner | None, host: str, cache: _EgressCache) -> None:
    await cache.ensure_rules(runner)
    cidr = f"{host}/32"
    if cache.has_prohibit(cidr):
        await _mutate_rule(runner, ["rule", "del", "from", cidr, "prohibit"], cache)
    for known, table in list(cache.lookups):
        if known == host:
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "lookup", str(table)], cache)


async def _install_one_egress_rule(runner: Runner | None, row: dict[str, str | int], cache: _EgressCache) -> str:
    addr = str(row["addr"])
    cidr = str(row["cidr"])
    action = str(row.get("action") or "lookup")
    pref = rule_pref_for_addr(addr)
    await cache.ensure_rules(runner)
    if action == "prohibit":
        for known, known_table in list(cache.lookups):
            if known == addr:
                await _mutate_rule(runner, ["rule", "del", "from", cidr, "lookup", str(known_table)], cache)
        if not await _has_from_prohibit_rule(runner, cidr=cidr, cache=cache):
            if not await _mutate_rule(
                runner,
                ["rule", "add", "from", cidr, "pref", str(pref), "prohibit"],
                cache,
            ):
                return "failed"
        return "applied"

    iface = str(row["iface"])
    table = int(row["table"])
    if not iface or not await _iface_exists(runner, iface, cache):
        log.warning("l2tp egress deferred: exit interface [%s] missing for %s", iface, cidr)
        return "deferred"
    await _soften_rp_filter(runner, iface, cache)
    if not await _install_default_route(runner, iface=iface, table=table, cache=cache):
        log.warning("l2tp egress deferred: default route failed for %s via %s", cidr, iface)
        return "deferred"
    if not await _has_from_lookup_rule(runner, cidr=cidr, table=table, cache=cache):
        if not await _mutate_rule(
            runner,
            ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(pref)],
            cache,
        ):
            return "failed"
    if cache.has_prohibit(cidr):
        await _mutate_rule(runner, ["rule", "del", "from", cidr, "prohibit"], cache)
    for known, known_table in list(cache.lookups):
        if known == addr and known_table != table:
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "lookup", str(known_table)], cache)
    return "applied"


async def _merge_l2tp_egress_state(
    store: Store,
    applied: list[dict[str, str | int]],
    *,
    drop_addrs: set[str],
    retain_addrs: set[str] | None = None,
) -> None:
    """Patch the L2TP egress snapshot for the addresses this call touched."""
    retain = retain_addrs or set()
    previous = await store.get_doc("l2tp", _STATE_KIND, _STATE_ID) or {}
    rules = [row for row in (previous.get("rules") or []) if isinstance(row, dict)]
    kept: list[dict[str, Any]] = []
    for row in rules:
        addr = str(row.get("addr") or "").strip()
        if not addr:
            continue
        if addr in retain:
            kept.append(row)
            continue
        if addr in drop_addrs:
            continue
        kept.append(row)
    seen = {str(row.get("addr") or "") for row in kept}
    for row in applied:
        addr = str(row["addr"])
        if addr in seen:
            kept = [item for item in kept if str(item.get("addr") or "") != addr]
        kept.append(
            {
                "addr": addr,
                "table": int(row["table"]),
                "iface": str(row["iface"]),
                "action": str(row.get("action") or "lookup"),
            }
        )
        seen.add(addr)
    masq = [str(item).strip() for item in (previous.get("masq") or []) if str(item).strip()]
    for row in applied:
        iface = str(row.get("iface") or "").strip()
        if iface and iface not in masq and str(row.get("action") or "lookup") == "lookup":
            masq.append(iface)
    tables = sorted({int(row.get("table") or 0) for row in kept if int(row.get("table") or 0) > 0})
    await store.put_doc(
        "l2tp",
        _STATE_KIND,
        _STATE_ID,
        {"rules": kept, "tables": tables, "masq": masq},
    )


async def repair_peer_egress(
    store: Store,
    *,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
    force: bool = True,
) -> dict[str, Any]:
    """
    Full repair scenario owned by the agent:

      1) ip_forward + persist sysctl drop-in
      2) soften rp_filter on all / default
      3) reconcile policy routing + NAT/FORWARD for every WG/Amnezia core
      4) rewrite PostUp script and (re)start systemd oneshot when forced/changed

    Use after RX≈0 with healthy handshake, or after manual iptables experiments.
    ``force=False`` is a soft heal (idempotent reinstall of missing rules only).
    """
    await _ensure_ip_forward(runner)
    sysctl_ok = await _persist_sysctl_forward()

    cores: dict[str, Any] = {}
    for core in _EGRESS_CORES:
        if core == "l2tp":
            servers = await store.list_docs(core, _L2TP_KIND)
            ifaces = l2tp_servers_as_interfaces(servers) if servers else []
        elif core == "openvpn":
            servers = await store.list_docs(core, _OPENVPN_KIND)
            ifaces = openvpn_servers_as_interfaces(servers) if servers else []
        else:
            ifaces = await store.list_docs(core, _IFACE_KIND)
        state = await store.get_doc(core, _STATE_KIND, _STATE_ID)
        if not ifaces and not state:
            continue
        # Empty synthetic iface with no peers still needs force when state exists.
        cores[core] = await reconcile_core_egress(
            store,
            core,
            ifaces,
            runner=runner,
            data_dir=data_dir,
            force=force,
        )

    persist = await persist_peer_egress(store, data_dir=data_dir, runner=runner, force_start=force)
    ok = all(bool(row.get("ok")) for row in cores.values()) if cores else True
    rules = await all_desired_rules_from_store(store)
    return {
        "ok": ok,
        "sysctl_persist": sysctl_ok,
        "cores": cores,
        "persist": persist,
        "tunnels": await all_tunnel_interface_names(store),
        "rules": len(rules),
        "forced": force,
    }


def _peers_by_host(interfaces: list[dict[str, Any]]) -> dict[str, tuple[str, dict[str, Any]]]:
    found: dict[str, tuple[str, dict[str, Any]]] = {}
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        name = str(iface.get("name") or "")
        for peer in iface.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            cidr = peer_source_cidr(peer.get("address"))
            if not cidr:
                continue
            found.setdefault(cidr.split("/", 1)[0], (name, peer))
    return found


async def _drop_conflicting_policy(
    runner: Runner | None,
    interfaces: list[dict[str, Any]],
    applied: list[dict[str, str | int]],
    cache: _EgressCache,
    switched: list[str],
) -> bool:
    """Delete prohibit and foreign lookup rules that outrank the desired rule.

    One failed address does not stop the others. The snapshot is not healthy
    while a conflicting rule is still installed.
    """
    if cache.rules_failed:
        return not applied
    owners = _peers_by_host(interfaces)
    ok = True
    for row in applied:
        addr = str(row.get("addr") or "")
        if not addr:
            continue
        cidr = str(row.get("cidr") or f"{addr}/32")
        action = str(row.get("action") or "lookup")
        table = int(row.get("table") or 0)
        pending: list[tuple[str, str, list[str]]] = []
        if action == "lookup" and cache.has_prohibit(cidr):
            pending.append(("policy_prohibit", "prohibit", ["rule", "del", "from", cidr, "prohibit"]))
        for host, known in list(cache.lookups):
            if host != addr or known <= 0:
                continue
            if action == "lookup" and known == table:
                continue
            pending.append(
                ("policy_table", f"lookup {known}", ["rule", "del", "from", cidr, "lookup", str(known)])
            )
        if not pending:
            continue
        from agent.drivers.wireguard import _recovery_identity, log_peer_recovery

        iface_name, peer = owners.get(addr, ("", {}))
        for reason, before, args in pending:
            deleted = await _mutate_rule(runner, args, cache)
            if deleted:
                switched.append(addr)
            else:
                ok = False
            recovery = {
                "peer_id": str(peer.get("id") or peer.get("email") or addr),
                "public_key": str(peer.get("public_key") or ""),
                "host": addr,
                "reason": reason,
                "live_allowed": before,
                "action": "rule_del",
            }
            log_peer_recovery(
                iface_name,
                [recovery],
                verified=set() if deleted else {_recovery_identity(recovery)},
            )
    return ok


async def reconcile_core_egress(
    store: Store,
    core: str,
    interfaces: list[dict[str, Any]],
    *,
    runner: Runner | None = None,
    data_dir: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """
    Apply peer→exit policy routing.

    Server change (same peer IP, new exit_interface) is atomic:
    warm new table → add new rule → delete old rule → flush conntrack.

    ``force=True`` rebuilds NAT/FORWARD even when health checks look green
    (repair scenario after manual firewall edits).
    """
    if not shutil.which("ip"):
        return {"ok": False, "skipped": True, "reason": "ip not found"}

    cache = _EgressCache()
    desired = desired_rules_from_interfaces(interfaces)
    previous = await store.get_doc(core, _STATE_KIND, _STATE_ID) or {}
    prev_rules = [row for row in (previous.get("rules") or []) if isinstance(row, dict)]
    prev_by_addr = {
        str(row.get("addr") or ""): {
            "table": int(row.get("table") or 0),
            "iface": str(row.get("iface") or ""),
            "cidr": peer_source_cidr(row.get("addr")) or f"{row.get('addr')}/32",
            "action": str(row.get("action") or "lookup"),
            "snat": public_exit_ipv4(row.get("snat")),
        }
        for row in prev_rules
        if str(row.get("addr") or "").strip()
    }

    await _ensure_ip_forward(runner, cache)

    applied: list[dict[str, str | int]] = []
    switched: list[str] = []
    deferred: list[str] = []
    desired_addrs_all = {str(row["addr"]) for row in desired}
    logged_absent: set[str] = set()

    # 1) Warm every desired exit table first (shared by many peers).
    # One link probe per interface name. A transfer can aim hundreds of peers
    # at the same missing exit (nl, tr, de); probing each peer is the slow part.
    warmed: set[tuple[str, int]] = set()
    absent: set[str] = set()
    for row in desired:
        if str(row.get("action") or "lookup") == "prohibit":
            continue
        iface = str(row["iface"])
        table = int(row["table"])
        key = (iface, table)
        if key in warmed:
            continue
        if not iface or iface in absent or not await _iface_exists(runner, iface, cache):
            if iface:
                absent.add(iface)
            continue
        await _soften_rp_filter(runner, iface, cache)
        if await _install_default_route(runner, iface=iface, table=table, cache=cache):
            warmed.add(key)

    # 2) Install desired rules BEFORE removing stale ones (atomic switch).
    # New rule uses a higher priority (lower pref) than the stable pref so it
    # wins immediately even while the old lookup rule still exists.
    for row in desired:
        addr = str(row["addr"])
        cidr = str(row["cidr"])
        action = str(row.get("action") or "lookup")
        pref = rule_pref_for_addr(addr)
        old = prev_by_addr.get(addr)
        old_action = str((old or {}).get("action") or "lookup")
        if action == "prohibit":
            if not await _has_from_prohibit_rule(runner, cidr=cidr, cache=cache):
                if not await _mutate_rule(runner, ["rule", "add", "from", cidr, "pref", str(pref), "prohibit"], cache):
                    log.warning("peer egress skipped %s: failed to add prohibit rule", cidr)
                    continue
            if old and old_action != "prohibit":
                old_table = int(old.get("table") or 0)
                if old_table > 0:
                    await _mutate_rule(runner, ["rule", "del", "from", str(old["cidr"]), "lookup", str(old_table)], cache)
                switched.append(addr)
            applied.append(row)
            continue

        table = int(row["table"])
        iface = str(row["iface"])
        if (iface, table) not in warmed:
            # Keep the previous lookup (even if it targeted another exit) so we
            # never dump this peer onto the main table / region primary IP.
            if iface not in logged_absent:
                logged_absent.add(iface)
                log.warning(
                    "peer egress deferred: exit interface [%s] missing or route failed",
                    iface,
                )
            if old and str(old.get("action") or "lookup") == "lookup" and int(old.get("table") or 0) > 0:
                retained = {
                    "addr": addr,
                    "cidr": str(old.get("cidr") or cidr),
                    "iface": str(old.get("iface") or ""),
                    "table": int(old.get("table") or 0),
                    "action": "lookup",
                }
                if retained["iface"]:
                    applied.append(retained)
                    deferred.append(addr)
                    continue
            deferred.append(addr)
            continue

        switching = bool(old and (int(old["table"]) != table or str(old["iface"]) != iface or old_action != "lookup"))
        already = await _has_from_lookup_rule(runner, cidr=cidr, table=table, cache=cache)

        if switching and not already:
            # Cutover pref beats any lingering old rule briefly.
            cutover = max(100, pref - 1)
            if not await _mutate_rule(
                runner,
                ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(cutover)],
                cache,
            ):
                log.warning("peer egress skipped %s: failed to add cutover rule → %s", cidr, iface)
                if old and int(old.get("table") or 0) > 0 and str(old.get("iface") or ""):
                    applied.append(
                        {
                            "addr": addr,
                            "cidr": str(old.get("cidr") or cidr),
                            "iface": str(old["iface"]),
                            "table": int(old["table"]),
                            "action": "lookup",
                        }
                    )
                    deferred.append(addr)
                continue
            old_table = int(old["table"])
            if old_table > 0:
                await _mutate_rule(runner, ["rule", "del", "from", str(old["cidr"]), "lookup", str(old_table)], cache)
            # Normalize to stable preference.
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "lookup", str(table), "pref", str(cutover)], cache)
            await _mutate_rule(runner, ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(pref)], cache)
            switched.append(addr)
        elif not already:
            if not await _mutate_rule(
                runner,
                ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(pref)],
                cache,
            ):
                log.warning("peer egress skipped %s: failed to add rule → %s", cidr, iface)
                if old and int(old.get("table") or 0) > 0 and str(old.get("iface") or ""):
                    applied.append(
                        {
                            "addr": addr,
                            "cidr": str(old.get("cidr") or cidr),
                            "iface": str(old["iface"]),
                            "table": int(old["table"]),
                            "action": "lookup",
                        }
                    )
                    deferred.append(addr)
                continue
        elif switching:
            old_table = int(old["table"])
            if old_table > 0:
                await _mutate_rule(runner, ["rule", "del", "from", str(old["cidr"]), "lookup", str(old_table)], cache)
            switched.append(addr)

        if old_action == "prohibit":
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "prohibit"], cache)
            switched.append(addr)

        if str((old or {}).get("snat") or "") != str(row.get("snat") or ""):
            switched.append(addr)

        applied.append(row)

    desired_keys = {(str(row["addr"]), int(row["table"]), str(row["iface"])) for row in applied}
    desired_addrs = {str(row["addr"]) for row in applied}

    # 3) Remove rules for peers that left egress entirely (not a switch / defer).
    for row in prev_rules:
        addr = str(row.get("addr") or "")
        table = int(row.get("table") or 0)
        iface = str(row.get("iface") or "")
        key = (addr, table, iface)
        if key in desired_keys:
            continue
        if addr in desired_addrs:
            # Already handled as atomic switch above.
            continue
        if addr in desired_addrs_all:
            # Still desired but deferred (exit missing) — keep kernel rule.
            continue
        cidr = peer_source_cidr(addr) or f"{addr}/32"
        prev_action = str(row.get("action") or "lookup")
        if prev_action == "prohibit":
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "prohibit"], cache)
            switched.append(addr)
        elif table:
            await _mutate_rule(runner, ["rule", "del", "from", cidr, "lookup", str(table)], cache)
            switched.append(addr)

    # A stored "lookup" snapshot used to hide a leftover prohibit or a lookup
    # in another table. Those rules win by priority and blackhole one peer.
    conflicts_ok = await _drop_conflicting_policy(runner, interfaces, applied, cache, switched)

    # 4) Flush conntrack so old NAT paths do not stick after exit change/removal.
    for addr in dict.fromkeys(switched):
        await _flush_conntrack(runner, addr)

    desired_tables = {int(row["table"]): str(row["iface"]) for row in applied if int(row.get("table") or 0) > 0}
    prev_tables = {
        int(row.get("table") or 0): str(row.get("iface") or "")
        for row in prev_rules
        if int(row.get("table") or 0) > 0
    }

    from agent.support.xray_exit_bind import bind_table_ids, reapply_saved_binds

    protected_tables = set(bind_table_ids())
    for table in prev_tables:
        if table not in desired_tables and table not in protected_tables:
            await _ip(runner, ["route", "flush", "table", str(table)])

    masq_ifaces = sorted({str(row["iface"]) for row in applied if str(row.get("iface") or "").strip()})
    # Keep MASQUERADE on recently-used exits too (switch italy→deutch must not
    # briefly leave the new exit without SNAT if apply races).
    for iface in previous.get("masq") or []:
        name = str(iface or "").strip()
        if name and await _iface_exists(runner, name, cache):
            masq_ifaces = sorted(set(masq_ifaces) | {name})
    # Merge masq with other cores so we don't drop shared exits while reconciling one core.
    other_masq: set[str] = set()
    for other in _EGRESS_CORES:
        if other == core:
            continue
        other_state = await store.get_doc(other, _STATE_KIND, _STATE_ID) or {}
        for iface in other_state.get("masq") or []:
            name = str(iface or "").strip()
            if name:
                other_masq.add(name)
    effective_masq = sorted(set(masq_ifaces) | other_masq)
    previous_masq = list(previous.get("masq") or [])
    for iface in other_masq:
        if iface not in previous_masq:
            previous_masq.append(iface)

    prev_masq_set = {str(x).strip() for x in previous_masq if str(x).strip()}
    new_masq_set = set(effective_masq)
    tunnel_ifaces = sorted(set(tunnel_interface_names(interfaces)) | set(await all_tunnel_interface_names(store)))
    needs_main = peers_use_main_table(interfaces) or await _other_cores_use_main_table(store, core)
    new_main: list[str] = []
    if needs_main:
        new_main = await _main_table_egress_devices(runner, cache, skip=set(tunnel_ifaces))
        for dev in new_main:
            await _soften_rp_filter(runner, dev, cache)
        if not new_main:
            log.warning(
                "peer egress main-table peers have no default IPv4 device core=%s",
                core,
            )
    prev_main = _stored_main_egress(previous)
    firewall_now = set(new_masq_set) | set(new_main)
    firewall_prev = set(prev_masq_set) | set(prev_main)
    # An explicit exit already has an oifname MASQUERADE. Scope the extra rule
    # to tunnel ingress only when the main-table device is not one of those exits.
    scoped_main = [dev for dev in new_main if dev not in new_masq_set]
    nat_ok = await _nat_already_healthy(sorted(firewall_now), runner=runner)
    forward_ok = await _forward_already_healthy(tunnel_ifaces, runner=runner)
    snat_now = _snat_rows(applied)
    snat_prev = _snat_rows(prev_rules)
    nat_rebuilt = False
    if (
        force
        or firewall_now != firewall_prev
        or snat_now != snat_prev
        or not nat_ok
        or (tunnel_ifaces and not forward_ok)
    ):
        await _sync_masquerade(
            sorted(firewall_now),
            previous_ifaces=sorted(firewall_prev),
            runner=runner,
            tunnel_ifaces=tunnel_ifaces,
            scoped_ifaces=scoped_main,
            snat_rows=snat_now,
        )
        nat_rebuilt = True

    state = {
        "rules": [
            _with_snat(
                {
                    "addr": str(row["addr"]),
                    "table": int(row["table"]),
                    "iface": str(row["iface"]),
                    "action": str(row.get("action") or "lookup"),
                },
                public_exit_ipv4(row.get("snat")),
            )
            for row in applied
        ],
        "tables": sorted(desired_tables.keys()),
        "masq": masq_ifaces,
        "main_egress": new_main,
    }
    await store.put_doc(core, _STATE_KIND, _STATE_ID, state)

    log.debug(
        "peer egress probes core=%s rule_show=%s link_show=%s route_show=%s route_replace=%s sysctl_write=%s",
        core,
        cache.counts["rule_show"],
        cache.counts["link_show"],
        cache.counts["route_show"],
        cache.counts["route_replace"],
        cache.counts["sysctl_write"],
    )
    try:
        await ensure_peer_source_pins(store, runner=runner)
    except Exception:
        log.exception("peer source pin failed")
    try:
        await reapply_saved_binds(runner=runner)
    except Exception:
        log.exception("xray exit bind reapply failed")
    persist = await persist_peer_egress(store, data_dir=data_dir, runner=runner, force_start=force)
    route_ok = True
    if core in {"wireguard", "amnezia"}:
        from agent.drivers.wireguard import repair_tunnel_routes

        route_report = await repair_tunnel_routes(interfaces, runner=runner)
        route_ok = bool(route_report.get("ok", True))
    return {
        "ok": conflicts_ok and route_ok,
        "skipped": False,
        "rules": len(applied),
        "desired": len(desired),
        "switched": len(dict.fromkeys(switched)),
        "deferred": len(dict.fromkeys(deferred)),
        "masq": masq_ifaces,
        "main_egress": new_main,
        "nat_rebuilt": nat_rebuilt,
        "forced": force,
        "persist": persist,
        "probes": dict(cache.counts),
    }


class _EgressCache:
    """Kernel reads reused for one reconcile_core_egress call. Not kept afterward."""

    def __init__(self) -> None:
        self.ifaces: dict[str, bool] = {}
        self.rules_loaded = False
        self.rules_failed = False
        self.lookups: set[tuple[str, int]] = set()
        self.prohibits: set[str] = set()
        # None until a main-table query succeeds. A failure stays None so it is
        # retried and is never stored as an empty route list.
        self.main_defaults: list[tuple[str, str | None]] | None = None
        self.table_defaults: dict[int, list[tuple[str, str | None]] | None] = {}
        self.counts = {
            "rule_show": 0,
            "link_show": 0,
            "route_show": 0,
            "route_replace": 0,
            "sysctl_write": 0,
        }

    async def ensure_rules(self, runner: Runner) -> None:
        if self.rules_loaded:
            return
        self.rules_loaded = True
        parsed = await _load_policy_rules(runner, self)
        if parsed is None:
            self.rules_failed = True
            self.lookups.clear()
            self.prohibits.clear()
            return
        self.lookups, self.prohibits = parsed

    def invalidate_rules(self) -> None:
        self.rules_loaded = False
        self.rules_failed = False
        self.lookups.clear()
        self.prohibits.clear()

    def has_lookup(self, cidr: str, table: int) -> bool:
        if self.rules_failed:
            return False
        return (_rule_host(cidr), int(table)) in self.lookups

    def has_prohibit(self, cidr: str) -> bool:
        if self.rules_failed:
            return False
        return _rule_host(cidr) in self.prohibits

    def note_rule(self, args: list[str]) -> None:
        if "from" not in args:
            self.invalidate_rules()
            return
        cidr = str(args[args.index("from") + 1])
        host = _rule_host(cidr)
        if "lookup" in args:
            try:
                table = int(args[args.index("lookup") + 1])
            except (TypeError, ValueError, IndexError):
                self.invalidate_rules()
                return
            if "del" in args:
                self.lookups.discard((host, table))
            else:
                self.lookups.add((host, table))
            return
        if "prohibit" in args:
            if "del" in args:
                self.prohibits.discard(host)
            else:
                self.prohibits.add(host)
            return
        self.invalidate_rules()


def _rule_host(cidr: str) -> str:
    return str(cidr or "").split("/", 1)[0].strip()


def _table_number(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.startswith("table") and text[5:].isdigit():
        return int(text[5:])
    if text.isdigit():
        return int(text)
    return None


def _parse_rule_rows(rows: list[Any]) -> tuple[set[tuple[str, int]], set[str]]:
    lookups: set[tuple[str, int]] = set()
    prohibits: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        src = str(row.get("src") or "").strip()
        if src in ("", "all"):
            continue
        host = _rule_host(src)
        kind = str(row.get("type") or row.get("action") or "").lower()
        if kind == "prohibit":
            prohibits.add(host)
            continue
        table = _table_number(row.get("table"))
        if table is None:
            continue
        lookups.add((host, table))
    return lookups, prohibits


def _parse_rule_text(text: str) -> tuple[set[tuple[str, int]], set[str]]:
    lookups: set[tuple[str, int]] = set()
    prohibits: set[str] = set()
    for line in text.splitlines():
        match = re.search(r"\bfrom\s+(\S+)\s+(.*)$", line.strip())
        if not match:
            continue
        src = match.group(1)
        if src == "all":
            continue
        rest = match.group(2)
        host = _rule_host(src)
        if re.search(r"\bprohibit\b", rest):
            prohibits.add(host)
            continue
        found = re.search(r"\b(?:lookup|table)\s+(\d+)\b", rest)
        if not found:
            continue
        lookups.add((host, int(found.group(1))))
    return lookups, prohibits


async def _load_policy_rules(
    runner: Runner,
    cache: _EgressCache | None = None,
) -> tuple[set[tuple[str, int]], set[str]] | None:
    def _count() -> None:
        if cache is not None:
            cache.counts["rule_show"] += 1

    _count()
    try:
        result = await execute(runner, ["ip", "-j", "rule", "show"], check=False, timeout=5)
    except Exception:
        result = None
    if result is not None and getattr(result, "returncode", 1) == 0:
        raw = str(getattr(result, "stdout", "") or "").strip()
        if raw:
            try:
                rows = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                rows = None
            if isinstance(rows, list):
                return _parse_rule_rows(rows)
    _count()
    try:
        result = await execute(runner, ["ip", "rule", "show"], check=False, timeout=5)
    except Exception:
        return None
    if result is None or getattr(result, "returncode", 1) != 0:
        return None
    return _parse_rule_text(str(getattr(result, "stdout", "") or ""))


def _parse_default_routes(text: str) -> list[tuple[str, str | None]]:
    found: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default" or "dev" not in parts:
            continue
        try:
            dev = parts[parts.index("dev") + 1]
        except IndexError:
            continue
        via = None
        if "via" in parts:
            try:
                via = parts[parts.index("via") + 1]
            except IndexError:
                via = None
        found.append((dev, via))
    return found


def _single_default_matches(routes: list[tuple[str, str | None]], iface: str, via: str | None) -> bool:
    if len(routes) != 1:
        return False
    dev, have = routes[0]
    return dev == iface and have == via


def _proc_sys_value(key: str) -> str | None:
    parts = [part for part in str(key).split(".") if part]
    if not parts or any(part in {".", ".."} or "/" in part or "\\" in part for part in parts):
        return None
    path = Path("/proc/sys").joinpath(*parts)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _rule_delete_is_absent(result: Any) -> bool:
    """True only for iproute2's missing-rule replies, not for other failures."""
    text = " ".join(
        str(getattr(result, attr, "") or "")
        for attr in ("stderr", "stdout")
    ).lower()
    return "no such file or directory" in text or "no such process" in text


async def _ip(runner: Runner, args: list[str]) -> bool:
    try:
        result = await execute(runner, ["ip", *args], check=False, timeout=10)
    except Exception as exc:
        log.warning("ip %s failed: %s", " ".join(args), exc)
        return False
    if getattr(result, "returncode", 1) != 0:
        stderr = (getattr(result, "stderr", None) or getattr(result, "stdout", None) or "").strip()
        # Deleting a rule that is already gone is idempotent. Permission,
        # netlink, and argument errors must stay failures so the rule map
        # is reloaded instead of forgetting a rule that is still installed.
        if args[:1] == ["rule"] and "del" in args and _rule_delete_is_absent(result):
            return True
        log.warning("ip %s rc=%s %s", " ".join(args), getattr(result, "returncode", "?"), stderr)
        return False
    return True


async def _iface_exists(runner: Runner, iface: str, cache: _EgressCache | None = None) -> bool:
    if cache is not None and iface in cache.ifaces:
        return cache.ifaces[iface]
    if cache is not None:
        cache.counts["link_show"] += 1
    ok = await _ip(runner, ["link", "show", iface])
    if cache is not None:
        cache.ifaces[iface] = ok
    return ok


async def _mutate_rule(runner: Runner, args: list[str], cache: _EgressCache) -> bool:
    ok = await _ip(runner, args)
    if not ok:
        cache.invalidate_rules()
        return False
    cache.note_rule(args)
    return True


async def _has_from_lookup_rule(
    runner: Runner,
    *,
    cidr: str,
    table: int,
    cache: _EgressCache | None = None,
) -> bool:
    if cache is not None:
        await cache.ensure_rules(runner)
        return cache.has_lookup(cidr, table)
    """True when an identical from/lookup policy rule already exists."""
    try:
        result = await execute(runner, ["ip", "-j", "rule", "show"], check=False, timeout=5)
    except Exception:
        result = None
    if result is not None and getattr(result, "returncode", 1) == 0:
        raw = str(getattr(result, "stdout", "") or "").strip()
        if raw:
            try:
                rows = json.loads(raw)
                if isinstance(rows, list):
                    host = cidr.split("/", 1)[0]
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        src = str(row.get("src") or "").strip()
                        if src not in (host, cidr):
                            continue
                        tbl = row.get("table")
                        if tbl is None:
                            continue
                        if str(tbl) == str(table) or str(tbl) == f"table{table}":
                            return True
                        try:
                            if int(tbl) == int(table):
                                return True
                        except (TypeError, ValueError):
                            pass
            except (TypeError, ValueError, json.JSONDecodeError):
                pass

    # Fallback: plain-text show filtered by src.
    try:
        result = await execute(runner, ["ip", "rule", "show", "from", cidr], check=False, timeout=5)
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        return False
    text = str(getattr(result, "stdout", "") or "")
    needle_a = f"lookup {table}"
    needle_b = f"table {table}"
    return needle_a in text or needle_b in text


async def _has_from_prohibit_rule(
    runner: Runner,
    *,
    cidr: str,
    cache: _EgressCache | None = None,
) -> bool:
    if cache is not None:
        await cache.ensure_rules(runner)
        return cache.has_prohibit(cidr)
    host = cidr.split("/", 1)[0]
    try:
        result = await execute(runner, ["ip", "-j", "rule", "show"], check=False, timeout=5)
    except Exception:
        result = None
    if result is not None and getattr(result, "returncode", 1) == 0:
        raw = str(getattr(result, "stdout", "") or "").strip()
        if raw:
            try:
                rows = json.loads(raw)
                if isinstance(rows, list):
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        src = str(row.get("src") or "").strip()
                        if src not in (host, cidr):
                            continue
                        kind = str(row.get("type") or row.get("action") or "").lower()
                        if kind == "prohibit":
                            return True
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
    try:
        result = await execute(runner, ["ip", "rule", "show", "from", cidr], check=False, timeout=5)
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        return False
    return "prohibit" in str(getattr(result, "stdout", "") or "").lower()


async def _soften_rp_filter(runner: Runner, iface: str, cache: _EgressCache | None = None) -> None:
    """Strict rp_filter breaks multi-exit WG tunnels that share similar addressing."""
    await _sysctl_write(runner, f"net.ipv4.conf.{iface}.rp_filter", "0", cache)


async def _flush_conntrack(runner: Runner, addr: str) -> None:
    """Drop sticky NAT/forward states so the peer immediately uses the new exit."""
    host = str(addr or "").split("/", 1)[0].strip()
    if not host:
        return
    if shutil.which("conntrack"):
        for direction in ("-s", "-d"):
            try:
                await execute(runner, ["conntrack", "-D", direction, host], check=False, timeout=5)
            except Exception:
                pass
        return
    # nft / iptables cannot easily wipe by IP here; conntrack-tools is preferred.


class _GatewayRead:
    """Result of one main-table default lookup. ``ok`` is false when the query failed."""

    __slots__ = ("ok", "via")

    def __init__(self, *, ok: bool, via: str | None = None) -> None:
        self.ok = ok
        self.via = via


async def _install_default_route(
    runner: Runner,
    *,
    iface: str,
    table: int,
    cache: _EgressCache | None = None,
) -> bool:
    """Prefer `default via <gw> dev <iface>` when main table has a gateway on that NIC."""
    gateway = await _gateway_for_iface(runner, iface, cache)
    if not gateway.ok:
        # A failed main-table read is not "this NIC has no gateway".
        return False
    via = gateway.via
    if cache is not None:
        current = await _table_default_routes(runner, table, cache)
        if current is not None and _single_default_matches(current, iface, via):
            return True
    args = ["route", "replace", "default", "dev", iface, "table", str(table)]
    if via:
        args = ["route", "replace", "default", "via", via, "dev", iface, "table", str(table)]
    if cache is not None:
        cache.counts["route_replace"] += 1
    ok = await _ip(runner, args)
    if cache is not None:
        if ok:
            cache.table_defaults[table] = [(iface, via)]
        else:
            cache.ifaces.pop(iface, None)
            cache.table_defaults.pop(table, None)
    return ok


async def _table_default_routes(
    runner: Runner,
    table: int,
    cache: _EgressCache,
) -> list[tuple[str, str | None]] | None:
    if table in cache.table_defaults:
        return cache.table_defaults[table]
    cache.counts["route_show"] += 1
    try:
        result = await execute(
            runner,
            ["ip", "-4", "route", "show", "table", str(table)],
            check=False,
            timeout=5,
        )
    except Exception:
        cache.table_defaults[table] = None
        return None
    if getattr(result, "returncode", 1) != 0:
        cache.table_defaults[table] = None
        return None
    parsed = _parse_default_routes(str(getattr(result, "stdout", "") or ""))
    cache.table_defaults[table] = parsed
    return parsed


async def _gateway_for_iface(
    runner: Runner,
    iface: str,
    cache: _EgressCache | None = None,
) -> _GatewayRead:
    """Read the main-table gateway for ``iface``.

    A successful query with no default, or with no default on this NIC, returns
    ``ok`` and ``via is None`` (on-link install). A failed query returns
    ``ok`` false and is not cached.
    """
    routes = cache.main_defaults if cache is not None else None
    if routes is None:
        if cache is not None:
            cache.counts["route_show"] += 1
        try:
            result = await execute(runner, ["ip", "-4", "route", "show", "default"], check=False, timeout=5)
        except Exception:
            result = None
        if result is None or getattr(result, "returncode", 1) != 0:
            return _GatewayRead(ok=False)
        routes = _parse_default_routes(str(getattr(result, "stdout", "") or ""))
        if cache is not None:
            cache.main_defaults = routes
    for dev, via in routes:
        if dev == iface:
            return _GatewayRead(ok=True, via=via)
    return _GatewayRead(ok=True, via=None)


async def _main_table_egress_devices(
    runner: Runner,
    cache: _EgressCache | None,
    *,
    skip: set[str],
) -> list[str]:
    """Devices that actually carry main-table IPv4, excluding tunnel and loopback.

    ``ip route get`` is the fib decision. The default-route list is only used
    when that lookup does not name a device. Nothing here is a host-specific name.
    """
    probed: list[str] = []
    try:
        result = await execute(runner, ["ip", "-4", "route", "get", "1.1.1.1"], check=False, timeout=5)
    except Exception:
        result = None
    if result is not None and getattr(result, "returncode", 1) == 0:
        for dev in devices_from_route_text(str(getattr(result, "stdout", "") or "")):
            acceptable = _acceptable_egress_device(dev, skip)
            if acceptable and acceptable not in probed:
                probed.append(acceptable)
    if probed:
        return probed

    routes = cache.main_defaults if cache is not None else None
    if routes is None:
        if cache is not None:
            cache.counts["route_show"] += 1
        try:
            shown = await execute(runner, ["ip", "-4", "route", "show", "default"], check=False, timeout=5)
        except Exception:
            shown = None
        if shown is None or getattr(shown, "returncode", 1) != 0:
            return []
        routes = _parse_default_routes(str(getattr(shown, "stdout", "") or ""))
        if cache is not None:
            cache.main_defaults = routes
    found: list[str] = []
    for dev, _via in routes:
        acceptable = _acceptable_egress_device(dev, skip)
        if acceptable and acceptable not in found:
            found.append(acceptable)
    return found


async def _sysctl_write(
    runner: Runner,
    key: str,
    value: str,
    cache: _EgressCache | None = None,
) -> None:
    current = _proc_sys_value(key)
    if current is not None and current == value:
        return
    if not shutil.which("sysctl"):
        return
    if cache is not None:
        cache.counts["sysctl_write"] += 1
    try:
        await execute(runner, ["sysctl", "-w", f"{key}={value}"], check=False, timeout=5)
    except Exception:
        pass


async def _ensure_ip_forward(runner: Runner, cache: _EgressCache | None = None) -> None:
    if _proc_sys_value("net.ipv4.ip_forward") != "1":
        try:
            path = "/proc/sys/net/ipv4/ip_forward"
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("1\n")
        except OSError:
            await _sysctl_write(runner, "net.ipv4.ip_forward", "1", cache)

    # Strict all/default rp_filter breaks multi-exit peer egress after region switch.
    for key in ("all", "default"):
        await _sysctl_write(runner, f"net.ipv4.conf.{key}.rp_filter", "0", cache)

    await _persist_sysctl_forward()


async def _persist_sysctl_forward() -> bool:
    """Survive reboot without relying on manual host firewall edits."""
    content = (
        "# Managed by Netinja agent peer egress — do not edit.\n"
        "net.ipv4.ip_forward=1\n"
        "net.ipv4.conf.all.rp_filter=0\n"
        "net.ipv4.conf.default.rp_filter=0\n"
    )
    try:
        _SYSCTL_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        previous = (
            await aiofs.read_text(_SYSCTL_DROPIN, encoding="utf-8") if _SYSCTL_DROPIN.is_file() else ""
        )
        if previous != content:
            await aiofs.atomic_write(_SYSCTL_DROPIN, content, encoding="utf-8")
        return True
    except OSError as exc:
        log.warning("peer egress sysctl drop-in failed: %s", exc)
        return False


async def _nat_already_healthy(ifaces: list[str], *, runner: Runner) -> bool:
    """True when the preferred NAT backend already covers every exit iface."""
    if not ifaces:
        return True
    if shutil.which("nft"):
        return await _nft_has_masquerade_for(ifaces, runner=runner)
    if shutil.which("iptables-legacy"):
        for iface in ifaces:
            if not (
                await _iptables(
                    runner,
                    ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                    quiet=True,
                    binary="iptables-legacy",
                )
                or await _iptables(
                    runner,
                    [
                        "-t",
                        "nat",
                        "-C",
                        "POSTROUTING",
                        "-o",
                        iface,
                        "-m",
                        "comment",
                        "--comment",
                        f"{_MASQ_COMMENT_PREFIX}{iface}",
                        "-j",
                        "MASQUERADE",
                    ],
                    quiet=True,
                    binary="iptables-legacy",
                )
                or await _iptables_has_comment_masquerade(runner, "iptables-legacy", iface)
            ):
                return False
        return True
    if shutil.which("iptables"):
        for iface in ifaces:
            if not (
                await _iptables(
                    runner,
                    ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                    quiet=True,
                )
                or await _iptables(
                    runner,
                    [
                        "-t",
                        "nat",
                        "-C",
                        "POSTROUTING",
                        "-o",
                        iface,
                        "-m",
                        "comment",
                        "--comment",
                        f"{_MASQ_COMMENT_PREFIX}{iface}",
                        "-j",
                        "MASQUERADE",
                    ],
                    quiet=True,
                )
                or await _iptables_has_comment_masquerade(runner, "iptables", iface)
            ):
                return False
        return True
    return False


async def _sync_masquerade(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
    scoped_ifaces: list[str] | None = None,
    snat_rows: list[dict[str, str]] | None = None,
) -> None:
    """Install SNAT/MASQUERADE on every exit NIC using a single backend.

    Installing the same MASQUERADE on nft + iptables + iptables-legacy at once
    double-SNATs packets and shows up as packet loss after region switches.

    ``scoped_ifaces`` are main-table egress devices. Their MASQUERADE matches
    tunnel ingress as well as the egress name, so host-originated traffic on
    the primary NIC is not rewritten. Explicit exits stay oifname-only.
    """
    targets = sorted({*ifaces, *[str(x) for x in previous_ifaces if str(x).strip()]})
    scoped = [str(name) for name in (scoped_ifaces or []) if str(name).strip()]
    nft_ok = False
    if shutil.which("nft"):
        await _sync_masquerade_nft(
            ifaces,
            runner=runner,
            tunnel_ifaces=tunnel_ifaces or [],
            scoped_ifaces=scoped,
            snat_rows=snat_rows or [],
        )
        nft_ok = await _nft_has_masquerade_for(ifaces, runner=runner)

    if nft_ok:
        for binary in ("iptables", "iptables-legacy"):
            if shutil.which(binary):
                await _purge_iptables_exit_masq(targets, runner=runner, binary=binary)
        await _restore_xray_source_pins(runner)
        return

    if shutil.which("iptables-legacy"):
        await _sync_masquerade_iptables(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            binary="iptables-legacy",
            tunnel_ifaces=tunnel_ifaces or [],
            scoped_ifaces=scoped,
            snat_rows=snat_rows or [],
        )
        await _sync_forward(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            tunnel_ifaces=tunnel_ifaces or [],
            binary="iptables-legacy",
        )
        if shutil.which("iptables") and await _iptables_is_nft(runner):
            await _purge_iptables_exit_masq(targets, runner=runner, binary="iptables")
        await _restore_xray_source_pins(runner)
        return

    if shutil.which("iptables"):
        await _sync_masquerade_iptables(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            binary="iptables",
            tunnel_ifaces=tunnel_ifaces or [],
            scoped_ifaces=scoped,
            snat_rows=snat_rows or [],
        )
        await _sync_forward(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            tunnel_ifaces=tunnel_ifaces or [],
            binary="iptables",
        )
    await _restore_xray_source_pins(runner)


async def _restore_xray_source_pins(runner: Runner) -> None:
    """Put the Xray source pin back after a NAT rebuild.

    Peer MASQUERADE is installed in the normal srcnat hook. The earlier pin is
    what stops that hook from rewriting a node address to the server primary.
    Rebuilding NAT must not leave that pin missing.
    """
    try:
        from agent.support.xray_exit_bind import reapply_config_public_pins

        path = os.environ.get("XRAY_CONFIG", "").strip() or "/usr/local/etc/xray/config.json"
        await reapply_config_public_pins(path)
    except Exception:
        log.exception("xray source pin restore failed")


async def _sync_forward(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
    binary: str | None = None,
) -> None:
    # nft FORWARD (+ MSS clamp) lives in _sync_masquerade_nft.
    if shutil.which("nft") and await _nft_has_masquerade_for(ifaces, runner=runner):
        return
    chosen = binary
    if not chosen:
        if shutil.which("iptables-legacy"):
            chosen = "iptables-legacy"
        elif shutil.which("iptables"):
            chosen = "iptables"
        else:
            return
    await _sync_forward_iptables(
        ifaces,
        previous_ifaces=previous_ifaces,
        runner=runner,
        binary=chosen,
        tunnel_ifaces=tunnel_ifaces or [],
    )

async def _iptables_is_nft(runner: Runner) -> bool:
    try:
        result = await execute(runner, ["iptables", "-V"], check=False, timeout=5)
    except Exception:
        return False
    text = f"{getattr(result, 'stdout', '')} {getattr(result, 'stderr', '')}".lower()
    return "nf_tables" in text


async def _nft_has_masquerade_for(ifaces: list[str], *, runner: Runner) -> bool:
    if not ifaces:
        return True
    try:
        result = await execute(
            runner,
            ["nft", "-j", "list", "chain", "inet", "netinja_egress", "postrouting"],
            check=False,
            timeout=10,
        )
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        # Fallback: plain text list
        try:
            result = await execute(
                runner,
                ["nft", "list", "chain", "inet", "netinja_egress", "postrouting"],
                check=False,
                timeout=10,
            )
        except Exception:
            return False
        if getattr(result, "returncode", 1) != 0:
            return False
        text = str(getattr(result, "stdout", "") or "")
        return all(f'oifname "{iface}"' in text or f'oifname {iface}' in text for iface in ifaces)

    raw = str(getattr(result, "stdout", "") or "").strip()
    if not raw:
        return False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return False
    found: set[str] = set()
    for item in payload.get("nftables") or []:
        if not isinstance(item, dict) or "rule" not in item:
            continue
        rule = item.get("rule") or {}
        expr = rule.get("expr") or []
        oif = None
        is_masq = False
        for part in expr:
            if not isinstance(part, dict):
                continue
            if "masquerade" in part or "masq" in part:
                is_masq = True
            match = part.get("match") or {}
            left = match.get("left") or {}
            meta = left.get("meta") or {}
            if meta.get("key") in {"oifname", "oif"}:
                right = match.get("right")
                if isinstance(right, str):
                    oif = right
        if is_masq and oif:
            found.add(oif)
    return all(iface in found for iface in ifaces)


async def _iptables_delete_by_comment(
    runner: Runner,
    *,
    binary: str,
    table: str,
    chain: str,
    comment: str,
) -> None:
    """Delete every rule in ``chain`` whose comment is exactly ``comment``.

    A rule that also matches ``-i <tunnel>`` is invisible to ``-D -o iface``.
    Listing the chain removes both the generic and the tunnel-scoped forms,
    including duplicates left by an earlier apply.
    """
    try:
        result = await execute(runner, [binary, "-t", table, "-S", chain], check=False, timeout=10)
    except Exception:
        return
    if getattr(result, "returncode", 1) != 0:
        return
    text = str(getattr(result, "stdout", "") or "")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("-A "):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        if len(tokens) < 3 or tokens[0] != "-A" or tokens[1] != chain:
            continue
        if comment not in tokens:
            continue
        await _iptables(
            runner,
            ["-t", table, "-D", chain, *tokens[2:]],
            quiet=True,
            binary=binary,
        )


async def _iptables_has_comment_masquerade(runner: Runner, binary: str, iface: str) -> bool:
    comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
    try:
        result = await execute(runner, [binary, "-t", "nat", "-S", "POSTROUTING"], check=False, timeout=10)
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        return False
    for line in str(getattr(result, "stdout", "") or "").splitlines():
        if comment in line and "MASQUERADE" in line and iface in line:
            return True
    return False


async def _purge_iptables_exit_masq(ifaces: list[str], *, runner: Runner, binary: str) -> None:
    for iface in ifaces:
        if not iface:
            continue
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        await _iptables_delete_by_comment(
            runner,
            binary=binary,
            table="nat",
            chain="POSTROUTING",
            comment=comment,
        )
        # Uncommented duplicates from manual ops / older agent.
        for _ in range(8):
            if not await _iptables(
                runner,
                ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                quiet=True,
                binary=binary,
            ):
                break
        for _ in range(8):
            if not await _iptables(
                runner,
                [
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    iface,
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                    "-j",
                    "MASQUERADE",
                ],
                quiet=True,
                binary=binary,
            ):
                break


async def _sync_forward_iptables(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    binary: str = "iptables",
    tunnel_ifaces: list[str] | None = None,
) -> None:
    tunnels = [str(name).strip() for name in (tunnel_ifaces or []) if str(name).strip()]
    wanted = set(ifaces)
    for iface in previous_ifaces:
        if iface in wanted:
            continue
        for comment, args in (
            (f"{_MASQ_COMMENT_PREFIX}{iface}-mss", ["-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"]),
            (f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-out", ["-o", iface]),
            (f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-in", ["-i", iface, "-m", "state", "--state", "RELATED,ESTABLISHED"]),
        ):
            jump = "TCPMSS" if comment.endswith("-mss") else "ACCEPT"
            extra = ["--clamp-mss-to-pmtu"] if jump == "TCPMSS" else []
            await _iptables(
                runner,
                ["-D", "FORWARD", *args, "-m", "comment", "--comment", comment, "-j", jump, *extra],
                binary=binary,
            )

    for iface in ifaces:
        mss_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-mss"
        out_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-out"
        in_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-in"
        if not await _iptables(
            runner,
            [
                "-C",
                "FORWARD",
                "-o",
                iface,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                mss_comment,
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                [
                    "-I",
                    "FORWARD",
                    "1",
                    "-o",
                    iface,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-m",
                    "comment",
                    "--comment",
                    mss_comment,
                    "-j",
                    "TCPMSS",
                    "--clamp-mss-to-pmtu",
                ],
                binary=binary,
            )
        if not await _iptables(
            runner,
            ["-C", "FORWARD", "-o", iface, "-m", "comment", "--comment", out_comment, "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                ["-I", "FORWARD", "1", "-o", iface, "-m", "comment", "--comment", out_comment, "-j", "ACCEPT"],
                binary=binary,
            )
        if not await _iptables(
            runner,
            [
                "-C",
                "FORWARD",
                "-i",
                iface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                in_comment,
                "-j",
                "ACCEPT",
            ],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                [
                    "-I",
                    "FORWARD",
                    "1",
                    "-i",
                    iface,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-m",
                    "comment",
                    "--comment",
                    in_comment,
                    "-j",
                    "ACCEPT",
                ],
                binary=binary,
            )

    for tunnel in tunnels:
        if not _is_wildcard_iface(tunnel):
            await _soften_rp_filter(runner, tunnel)
        tunnel_comment = _tunnel_egress_comment(tunnel)
        if not await _iptables(
            runner,
            [
                "-C",
                "FORWARD",
                "-i",
                tunnel,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                f"{tunnel_comment}-mss",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                [
                    "-I",
                    "FORWARD",
                    "1",
                    "-i",
                    tunnel,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-m",
                    "comment",
                    "--comment",
                    f"{tunnel_comment}-mss",
                    "-j",
                    "TCPMSS",
                    "--clamp-mss-to-pmtu",
                ],
                binary=binary,
            )
        if not await _iptables(
            runner,
            ["-C", "FORWARD", "-i", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-in", "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                ["-I", "FORWARD", "1", "-i", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-in", "-j", "ACCEPT"],
                binary=binary,
            )
        if not await _iptables(
            runner,
            ["-C", "FORWARD", "-o", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-out", "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            await _iptables(
                runner,
                ["-I", "FORWARD", "1", "-o", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-out", "-j", "ACCEPT"],
                binary=binary,
            )


async def _forward_already_healthy(tunnel_ifaces: list[str], *, runner: Runner) -> bool:
    if not tunnel_ifaces:
        return True
    if shutil.which("nft"):
        try:
            result = await execute(
                runner,
                ["nft", "list", "chain", "inet", "netinja_egress", "forward"],
                check=False,
                timeout=10,
            )
        except Exception:
            return False
        if getattr(result, "returncode", 1) != 0:
            return False
        text = str(getattr(result, "stdout", "") or "")
        return all(
            f"{_tunnel_egress_comment(tunnel)}-in" in text
            or f"{_tunnel_egress_comment(tunnel)}-mss" in text
            for tunnel in tunnel_ifaces
        )

    binary = "iptables-legacy" if shutil.which("iptables-legacy") else ("iptables" if shutil.which("iptables") else None)
    if not binary:
        return False
    for tunnel in tunnel_ifaces:
        comment = f"{_tunnel_egress_comment(tunnel)}-in"
        if not await _iptables(
            runner,
            ["-C", "FORWARD", "-i", tunnel, "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            return False
    return True

async def _sync_masquerade_nft(
    ifaces: list[str],
    *,
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
    scoped_ifaces: list[str] | None = None,
    snat_rows: list[dict[str, str]] | None = None,
) -> None:
    await _nft(runner, ["add", "table", "inet", "netinja_egress"])
    await _nft(
        runner,
        [
            "add",
            "chain",
            "inet",
            "netinja_egress",
            _NFT_CHAIN,
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
    )
    await _nft(
        runner,
        [
            "add",
            "chain",
            "inet",
            "netinja_egress",
            "forward",
            "{ type filter hook forward priority filter; policy accept; }",
        ],
    )
    await _nft(runner, ["flush", "chain", "inet", "netinja_egress", _NFT_CHAIN])
    await _nft(runner, ["flush", "chain", "inet", "netinja_egress", "forward"])
    kept_sources: set[str] = set()
    for row in snat_rows or []:
        cidr = str(row.get("cidr") or "").strip()
        iface = str(row.get("iface") or "").strip()
        snat = str(row.get("snat") or "").strip()
        if not cidr or not iface or not snat:
            continue
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                _NFT_CHAIN,
                "ip",
                "saddr",
                cidr,
                "oifname",
                iface,
                "snat",
                "to",
                snat,
                "accept",
                "comment",
                f"netinja-src-{snat}",
            ],
        )
        kept_sources.add(snat)
    for ip in sorted(kept_sources):
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                _NFT_CHAIN,
                "ip",
                "saddr",
                ip,
                "accept",
                "comment",
                f"netinja-keep-{ip}",
            ],
        )
    scoped = set(scoped_ifaces or [])
    tunnels = [str(name).strip() for name in (tunnel_ifaces or []) if str(name).strip()]
    for iface in ifaces:
        if iface in scoped and tunnels:
            for tunnel in tunnels:
                await _nft(
                    runner,
                    [
                        "add",
                        "rule",
                        "inet",
                        "netinja_egress",
                        _NFT_CHAIN,
                        "iifname",
                        _nft_iface_match(tunnel),
                        "oifname",
                        iface,
                        "masquerade",
                        "comment",
                        f"{_MASQ_COMMENT_PREFIX}{iface}",
                    ],
                )
        else:
            await _nft(
                runner,
                [
                    "add",
                    "rule",
                    "inet",
                    "netinja_egress",
                    _NFT_CHAIN,
                    "oifname",
                    iface,
                    "masquerade",
                    "comment",
                    f"{_MASQ_COMMENT_PREFIX}{iface}",
                ],
            )
        # Clamp MSS for WG MTU (1420) — reduces blackhole-looking TCP loss.
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "oifname",
                iface,
                "tcp",
                "flags",
                "syn",
                "/",
                "syn,rst",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                "rt",
                "mtu",
                "comment",
                f"{_MASQ_COMMENT_PREFIX}{iface}-mss",
            ],
        )
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "oifname",
                iface,
                "accept",
                "comment",
                f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-out",
            ],
        )
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "iifname",
                iface,
                "ct",
                "state",
                "related,established",
                "accept",
                "comment",
                f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-in",
            ],
        )
    for tunnel in tunnel_ifaces or []:
        if not tunnel:
            continue
        if not _is_wildcard_iface(tunnel):
            await _soften_rp_filter(runner, tunnel)
        match = _nft_iface_match(tunnel)
        tunnel_comment = _tunnel_egress_comment(tunnel)
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "iifname",
                match,
                "tcp",
                "flags",
                "syn",
                "/",
                "syn,rst",
                "tcp",
                "option",
                "maxseg",
                "size",
                "set",
                "rt",
                "mtu",
                "comment",
                f"{tunnel_comment}-mss",
            ],
        )
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "iifname",
                match,
                "accept",
                "comment",
                f"{tunnel_comment}-in",
            ],
        )
        await _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "oifname",
                match,
                "accept",
                "comment",
                f"{tunnel_comment}-out",
            ],
        )


async def _sync_masquerade_iptables(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    binary: str = "iptables",
    tunnel_ifaces: list[str] | None = None,
    scoped_ifaces: list[str] | None = None,
    snat_rows: list[dict[str, str]] | None = None,
) -> None:
    wanted = set(ifaces)
    scoped = set(scoped_ifaces or [])
    tunnels = [str(name).strip() for name in (tunnel_ifaces or []) if str(name).strip()]
    for iface in previous_ifaces:
        if iface in wanted:
            continue
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        await _iptables_delete_by_comment(
            runner,
            binary=binary,
            table="nat",
            chain="POSTROUTING",
            comment=comment,
        )
        await _iptables(
            runner,
            ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            binary=binary,
        )
        # Also drop un-commented legacy rules we may have installed manually.
        await _iptables(
            runner,
            ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        )
    for iface in ifaces:
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        if iface in scoped:
            # Rebuild from a clean comment so a renamed tunnel cannot leave a twin.
            await _iptables_delete_by_comment(
                runner,
                binary=binary,
                table="nat",
                chain="POSTROUTING",
                comment=comment,
            )
            sources = tunnels or [""]
            for tunnel in sources:
                args = ["-t", "nat", "-A", "POSTROUTING"]
                if tunnel:
                    args.extend(["-i", tunnel])
                args.extend(
                    ["-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"]
                )
                await _iptables(runner, args, binary=binary)
            continue
        check = await _iptables(
            runner,
            ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        )
        if check:
            continue
        # Prefer commented rule; if an uncommented twin exists, keep one path working.
        if await _iptables(
            runner,
            ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        ):
            continue
        await _iptables(
            runner,
            ["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            binary=binary,
        )
    kept_sources: set[str] = set()
    for row in snat_rows or []:
        cidr = str(row.get("cidr") or "").strip()
        iface = str(row.get("iface") or "").strip()
        snat = str(row.get("snat") or "").strip()
        if not cidr or not iface or not snat:
            continue
        comment = f"netinja-src-{snat}"
        exists = await _iptables(
            runner,
            [
                "-t", "nat", "-C", "POSTROUTING", "-s", cidr, "-o", iface,
                "-m", "comment", "--comment", comment, "-j", "SNAT", "--to-source", snat,
            ],
            quiet=True,
            binary=binary,
        )
        if not exists:
            await _iptables(
                runner,
                [
                    "-t", "nat", "-I", "POSTROUTING", "1", "-s", cidr, "-o", iface,
                    "-m", "comment", "--comment", comment, "-j", "SNAT", "--to-source", snat,
                ],
                binary=binary,
            )
        kept_sources.add(snat)
    for ip in sorted(kept_sources):
        comment = f"netinja-keep-{ip}"
        exists = await _iptables(
            runner,
            ["-t", "nat", "-C", "POSTROUTING", "-s", ip, "-m", "comment", "--comment", comment, "-j", "RETURN"],
            quiet=True,
            binary=binary,
        )
        if not exists:
            await _iptables(
                runner,
                ["-t", "nat", "-I", "POSTROUTING", "1", "-s", ip, "-m", "comment", "--comment", comment, "-j", "RETURN"],
                binary=binary,
            )


def _nft_iface_match(name: str) -> str:
    """iptables uses ppp+; nft wants ppp*."""
    text = str(name or "").strip()
    if text.endswith("+"):
        return text[:-1] + "*"
    return text


def _is_wildcard_iface(name: str) -> bool:
    text = str(name or "")
    return "+" in text or "*" in text


async def _nft(runner: Runner, args: list[str]) -> bool:
    fixed: list[str] = []
    index = 0
    while index < len(args):
        fixed.append(args[index])
        if args[index] == "comment" and index + 1 < len(args):
            value = str(args[index + 1])
            if not (value.startswith('"') and value.endswith('"')):
                value = f'"{value}"'
            fixed.append(value)
            index += 2
            continue
        index += 1

    try:
        result = await execute(runner, ["nft", *fixed], check=False, timeout=10)
    except Exception as exc:
        log.warning("nft %s failed: %s", " ".join(fixed), exc)
        return False
    if getattr(result, "returncode", 1) != 0:
        stderr = (getattr(result, "stderr", None) or "").strip().lower()
        if "exist" in stderr:
            return True
        log.warning("nft %s rc=%s %s", " ".join(fixed), getattr(result, "returncode", "?"), stderr)
        return False
    return True


async def _iptables(runner: Runner, args: list[str], *, quiet: bool = False, binary: str = "iptables") -> bool:
    try:
        result = await execute(runner, [binary, *args], check=False, timeout=10)
    except Exception as exc:
        if not quiet:
            log.warning("%s %s failed: %s", binary, " ".join(args), exc)
        return False
    ok = getattr(result, "returncode", 1) == 0
    if not ok and not quiet:
        stderr = (getattr(result, "stderr", None) or "").strip()
        if "does a matching rule exist" not in stderr.lower():
            log.warning("%s %s rc=%s %s", binary, " ".join(args), getattr(result, "returncode", "?"), stderr)
    return ok
