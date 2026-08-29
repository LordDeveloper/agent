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

Live apply must be idempotent:
  • ip rules: add/switch only when needed (stable pref per peer IP)
  • NAT/MSS: rebuild only when the exit set changes (never flush on no-op)
  • systemd oneshot: rewrite/start only when the apply script content changes

Blind nft flush + systemctl start on every peer update caused multi-second
packet loss every time the panel/API touched a peer.
"""

import json
import os
import re
import shutil
import zlib
from pathlib import Path
from typing import Any, Callable

from agent.db import Store
from agent.logutil import get_logger
from agent.support import record_is_enabled
from agent.support.process import run

log = get_logger("peer_egress")

Runner = Callable[..., Any]

_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
_STATE_KIND = "egress_state"
_STATE_ID = "applied"
_IFACE_KIND = "interface"
_NFT_CHAIN = "postrouting"
_MASQ_COMMENT_PREFIX = "netinja-egress-"
_UNIT_NAME = "agent-peer-egress.service"
_UNIT_PATH = Path("/etc/systemd/system") / _UNIT_NAME
_SYSCTL_DROPIN = Path("/etc/sysctl.d/99-netinja-peer-egress.conf")
_EGRESS_CORES = ("wireguard", "amnezia")


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


def all_tunnel_interface_names(store: Store) -> list[str]:
    names: set[str] = set()
    for core in _EGRESS_CORES:
        for row in store.list_docs(core, _IFACE_KIND):
            name = str(row.get("name") or "").strip()
            if name:
                names.add(name)
    return sorted(names)


def peer_source_cidr(address: Any) -> str | None:
    text = str(address or "").strip()
    if not text:
        return None
    host = text.split("/", 1)[0].strip()
    if not host:
        return None
    return f"{host}/32"


def apply_script_path(data_dir: str | Path | None = None) -> Path:
    base = Path(data_dir or os.environ.get("DATA_DIR") or "/var/lib/agent")
    return base / "peer-egress-apply.sh"


def desired_rules_from_interfaces(interfaces: list[dict[str, Any]]) -> list[dict[str, str | int]]:
    rules: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for iface in interfaces:
        for peer in iface.get("peers") or []:
            if not isinstance(peer, dict) or not record_is_enabled(peer):
                continue
            exit_iface = normalize_exit_interface(peer.get("exit_interface"))
            cidr = peer_source_cidr(peer.get("address"))
            if not exit_iface or not cidr:
                continue
            addr = cidr.split("/", 1)[0]
            if addr in seen:
                continue
            seen.add(addr)
            rules.append(
                {
                    "addr": addr,
                    "cidr": cidr,
                    "iface": exit_iface,
                    "table": table_id_for_interface(exit_iface),
                }
            )
    return rules


def all_desired_rules_from_store(store: Store) -> list[dict[str, str | int]]:
    """Prefer live interface docs; fall back to last applied egress_state."""
    merged: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for core in _EGRESS_CORES:
        ifaces = store.list_docs(core, _IFACE_KIND)
        if ifaces:
            source = desired_rules_from_interfaces(ifaces)
        else:
            state = store.get_doc(core, _STATE_KIND, _STATE_ID) or {}
            source = []
            for row in state.get("rules") or []:
                if not isinstance(row, dict):
                    continue
                addr = str(row.get("addr") or "").strip()
                iface = str(row.get("iface") or "").strip()
                table = int(row.get("table") or 0)
                if not addr or not iface or table <= 0:
                    continue
                source.append(
                    {
                        "addr": addr,
                        "cidr": f"{addr}/32",
                        "iface": iface,
                        "table": table,
                    }
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
) -> str:
    """Self-contained shell script so egress survives reboot (wg-quick PostUp / systemd)."""
    lines = [
        "#!/bin/sh",
        "# Generated by Netinja agent — peer egress policy routing. Do not edit.",
        "set +e",
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true",
        "",
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

    masq: set[str] = set()
    for row in rules:
        addr = str(row["addr"])
        cidr = str(row.get("cidr") or f"{addr}/32")
        table = int(row["table"])
        iface = str(row["iface"])
        masq.add(iface)
        # Cold boot / PostUp: install table then rule with stable preference.
        pref = rule_pref_for_addr(addr)
        lines.append(f'if _default_for_iface "{iface}" {table}; then')
        lines.append(f'  ip rule del from "{cidr}" lookup {table} 2>/dev/null || true')
        lines.append(
            f'  ip rule add from "{cidr}" lookup {table} pref {pref} 2>/dev/null || true'
        )
        lines.append("else")
        lines.append(f'  ip rule del from "{cidr}" lookup {table} 2>/dev/null || true')
        lines.append(
            f'  echo "peer-egress: skipped {cidr} -> {iface} (interface missing or route failed)" >&2'
        )
        lines.append("fi")

    lines.append("")
    tunnels = sorted({str(name).strip() for name in (tunnel_ifaces or []) if str(name).strip()})
    for tunnel in tunnels:
        lines.append(f'_soften_rp_filter "{tunnel}"')
    if tunnels:
        lines.append("")

    # Prefer a SINGLE NAT backend to avoid double MASQUERADE (causes packet loss).
    lines.extend(
        [
            "if command -v nft >/dev/null 2>&1; then",
            "  nft add table inet netinja_egress 2>/dev/null || true",
            "  nft add chain inet netinja_egress postrouting "
            '"{ type nat hook postrouting priority srcnat; policy accept; }" 2>/dev/null || true',
            "  nft add chain inet netinja_egress forward "
            '"{ type filter hook forward priority filter; policy accept; }" 2>/dev/null || true',
            "  nft flush chain inet netinja_egress postrouting 2>/dev/null || true",
            "  nft flush chain inet netinja_egress forward 2>/dev/null || true",
        ]
    )
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
    for tunnel in tunnels:
        tunnel_comment = f"{_MASQ_COMMENT_PREFIX}tunnel-{tunnel}"
        lines.append(
            f'  nft add rule inet netinja_egress forward iifname "{tunnel}" '
            f'tcp flags syn / syn,rst tcp option maxseg size set rt mtu '
            f'comment "{tunnel_comment}-mss" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward iifname "{tunnel}" '
            f'accept comment "{tunnel_comment}-in" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress forward oifname "{tunnel}" '
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
    _append_iptables_firewall_shell(lines, binary="iptables", masq=masq, tunnels=tunnels, indent="  ")
    lines.append("elif command -v iptables-legacy >/dev/null 2>&1; then")
    _append_iptables_firewall_shell(lines, binary="iptables-legacy", masq=masq, tunnels=tunnels, indent="  ")
    lines.append("fi")
    lines.append("")

    lines.append("exit 0")
    return "\n".join(lines) + "\n"


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
        tunnel_comment = f"{_MASQ_COMMENT_PREFIX}tunnel-{tunnel}"
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


def write_apply_script(
    rules: list[dict[str, str | int]],
    *,
    data_dir: str | Path | None = None,
    tunnel_ifaces: list[str] | None = None,
) -> Path:
    path = apply_script_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_apply_script(rules, tunnel_ifaces), encoding="utf-8")
    try:
        path.chmod(0o755)
    except OSError:
        pass
    return path


def ensure_peer_egress_unit(
    script_path: Path,
    *,
    runner: Runner | None = None,
    start: bool = False,
) -> dict[str, Any]:
    """Install/enable a oneshot systemd unit that restores egress after reboot.

    ``start`` should be true only when the apply script content actually changed;
    starting on every reconcile flushed nft NAT and caused periodic packet loss.
    """
    execute = runner or run
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
        previous = _UNIT_PATH.read_text(encoding="utf-8") if _UNIT_PATH.is_file() else ""
        if previous != unit:
            _UNIT_PATH.write_text(unit, encoding="utf-8")
            execute(["systemctl", "daemon-reload"], check=False, timeout=30)
    except OSError as exc:
        log.warning("peer egress unit write failed: %s", exc)
        return {"ok": False, "skipped": False, "reason": str(exc)}

    enable = execute(["systemctl", "enable", _UNIT_NAME], check=False, timeout=30)
    started = False
    if start:
        start_result = execute(["systemctl", "start", _UNIT_NAME], check=False, timeout=60)
        started = getattr(start_result, "returncode", 1) == 0
    return {
        "ok": getattr(enable, "returncode", 1) == 0,
        "started": started,
        "unit": str(_UNIT_PATH),
        "script": str(script_path),
    }


def persist_peer_egress(
    store: Store,
    *,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
    force_start: bool = False,
) -> dict[str, Any]:
    rules = all_desired_rules_from_store(store)
    tunnels = all_tunnel_interface_names(store)
    path = apply_script_path(data_dir)
    new_text = render_apply_script(rules, tunnels)
    previous = path.read_text(encoding="utf-8") if path.is_file() else None
    changed = previous != new_text
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_text, encoding="utf-8")
        try:
            path.chmod(0o755)
        except OSError:
            pass
    unit = ensure_peer_egress_unit(path, runner=runner, start=changed or force_start)
    return {"script": str(path), "rules": len(rules), "changed": changed, "unit": unit}


def repair_peer_egress(
    store: Store,
    *,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """
    Full repair scenario owned by the agent:

      1) ip_forward + persist sysctl drop-in
      2) soften rp_filter on all / default
      3) force-reconcile policy routing + NAT/FORWARD for every WG/Amnezia core
      4) rewrite PostUp script and (re)start systemd oneshot

    Use after RX≈0 with healthy handshake, or after manual iptables experiments.
    """
    execute = runner or run
    _ensure_ip_forward(execute)
    sysctl_ok = _persist_sysctl_forward()

    cores: dict[str, Any] = {}
    for core in _EGRESS_CORES:
        ifaces = store.list_docs(core, _IFACE_KIND)
        state = store.get_doc(core, _STATE_KIND, _STATE_ID)
        if not ifaces and not state:
            continue
        cores[core] = reconcile_core_egress(
            store,
            core,
            ifaces,
            runner=execute,
            data_dir=data_dir,
            force=True,
        )

    persist = persist_peer_egress(store, data_dir=data_dir, runner=execute, force_start=True)
    ok = all(bool(row.get("ok")) for row in cores.values()) if cores else True
    return {
        "ok": ok,
        "sysctl_persist": sysctl_ok,
        "cores": cores,
        "persist": persist,
        "tunnels": all_tunnel_interface_names(store),
        "rules": len(all_desired_rules_from_store(store)),
    }


def reconcile_core_egress(
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
    execute = runner or run
    if not shutil.which("ip"):
        return {"ok": False, "skipped": True, "reason": "ip not found"}

    desired = desired_rules_from_interfaces(interfaces)
    previous = store.get_doc(core, _STATE_KIND, _STATE_ID) or {}
    prev_rules = [row for row in (previous.get("rules") or []) if isinstance(row, dict)]
    prev_by_addr = {
        str(row.get("addr") or ""): {
            "table": int(row.get("table") or 0),
            "iface": str(row.get("iface") or ""),
            "cidr": peer_source_cidr(row.get("addr")) or f"{row.get('addr')}/32",
        }
        for row in prev_rules
        if str(row.get("addr") or "").strip() and int(row.get("table") or 0) > 0
    }

    _ensure_ip_forward(execute)

    applied: list[dict[str, str | int]] = []
    switched: list[str] = []

    # 1) Warm every desired exit table first (shared by many peers).
    warmed: set[tuple[str, int]] = set()
    for row in desired:
        iface = str(row["iface"])
        table = int(row["table"])
        key = (iface, table)
        if key in warmed:
            continue
        if not _iface_exists(execute, iface):
            continue
        _soften_rp_filter(execute, iface)
        if _install_default_route(execute, iface=iface, table=table):
            warmed.add(key)

    # 2) Install desired rules BEFORE removing stale ones (atomic switch).
    # New rule uses a higher priority (lower pref) than the stable pref so it
    # wins immediately even while the old lookup rule still exists.
    for row in desired:
        addr = str(row["addr"])
        cidr = str(row["cidr"])
        table = int(row["table"])
        iface = str(row["iface"])
        if (iface, table) not in warmed:
            log.warning("peer egress skipped %s: exit interface [%s] missing or route failed", cidr, iface)
            continue

        pref = rule_pref_for_addr(addr)
        old = prev_by_addr.get(addr)
        switching = bool(old and (int(old["table"]) != table or str(old["iface"]) != iface))
        already = _has_from_lookup_rule(execute, cidr=cidr, table=table)

        if switching and not already:
            # Cutover pref beats any lingering old rule briefly.
            cutover = max(100, pref - 1)
            if not _ip(
                execute,
                ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(cutover)],
            ):
                log.warning("peer egress skipped %s: failed to add cutover rule → %s", cidr, iface)
                continue
            old_table = int(old["table"])
            if old_table > 0:
                _ip(execute, ["rule", "del", "from", str(old["cidr"]), "lookup", str(old_table)])
            # Normalize to stable preference.
            _ip(execute, ["rule", "del", "from", cidr, "lookup", str(table), "pref", str(cutover)])
            _ip(execute, ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(pref)])
            switched.append(addr)
        elif not already:
            if not _ip(
                execute,
                ["rule", "add", "from", cidr, "lookup", str(table), "pref", str(pref)],
            ):
                log.warning("peer egress skipped %s: failed to add rule → %s", cidr, iface)
                continue
        elif switching:
            old_table = int(old["table"])
            if old_table > 0:
                _ip(execute, ["rule", "del", "from", str(old["cidr"]), "lookup", str(old_table)])
            switched.append(addr)

        applied.append(row)

    desired_keys = {(str(row["addr"]), int(row["table"]), str(row["iface"])) for row in applied}
    desired_addrs = {str(row["addr"]) for row in applied}

    # 3) Remove rules for peers that left egress entirely (not a switch).
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
        cidr = peer_source_cidr(addr) or f"{addr}/32"
        if table:
            _ip(execute, ["rule", "del", "from", cidr, "lookup", str(table)])
            switched.append(addr)

    # 4) Flush conntrack so old NAT paths do not stick after exit change/removal.
    for addr in dict.fromkeys(switched):
        _flush_conntrack(execute, addr)

    desired_tables = {int(row["table"]): str(row["iface"]) for row in applied}
    prev_tables = {
        int(row.get("table") or 0): str(row.get("iface") or "")
        for row in prev_rules
        if int(row.get("table") or 0) > 0
    }

    for table in prev_tables:
        if table not in desired_tables:
            _ip(execute, ["route", "flush", "table", str(table)])

    masq_ifaces = sorted({str(row["iface"]) for row in applied})
    # Keep MASQUERADE on recently-used exits too (switch italy→deutch must not
    # briefly leave the new exit without SNAT if apply races).
    for iface in previous.get("masq") or []:
        name = str(iface or "").strip()
        if name and _iface_exists(execute, name):
            masq_ifaces = sorted(set(masq_ifaces) | {name})
    # Merge masq with other cores so we don't drop shared exits while reconciling one core.
    other_masq: set[str] = set()
    for other in _EGRESS_CORES:
        if other == core:
            continue
        other_state = store.get_doc(other, _STATE_KIND, _STATE_ID) or {}
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
    tunnel_ifaces = sorted(set(tunnel_interface_names(interfaces)) | set(all_tunnel_interface_names(store)))
    nat_ok = _nat_already_healthy(effective_masq, runner=execute)
    forward_ok = _forward_already_healthy(tunnel_ifaces, runner=execute)
    nat_rebuilt = False
    if force or new_masq_set != prev_masq_set or not nat_ok or (tunnel_ifaces and not forward_ok):
        _sync_masquerade(
            effective_masq,
            previous_ifaces=previous_masq,
            runner=execute,
            tunnel_ifaces=tunnel_ifaces,
        )
        nat_rebuilt = True

    state = {
        "rules": [
            {"addr": str(row["addr"]), "table": int(row["table"]), "iface": str(row["iface"])}
            for row in applied
        ],
        "tables": sorted(desired_tables.keys()),
        "masq": masq_ifaces,
    }
    store.put_doc(core, _STATE_KIND, _STATE_ID, state)

    persist = persist_peer_egress(store, data_dir=data_dir, runner=execute, force_start=force)
    return {
        "ok": True,
        "skipped": False,
        "rules": len(applied),
        "desired": len(desired),
        "switched": len(dict.fromkeys(switched)),
        "masq": masq_ifaces,
        "nat_rebuilt": nat_rebuilt,
        "forced": force,
        "persist": persist,
    }


def _ip(runner: Runner, args: list[str]) -> bool:
    try:
        result = runner(["ip", *args], check=False, timeout=10)
    except Exception as exc:
        log.warning("ip %s failed: %s", " ".join(args), exc)
        return False
    if getattr(result, "returncode", 1) != 0:
        stderr = (getattr(result, "stderr", None) or getattr(result, "stdout", None) or "").strip()
        # delete of missing rule is expected
        if args[:1] == ["rule"] and "del" in args:
            return True
        log.warning("ip %s rc=%s %s", " ".join(args), getattr(result, "returncode", "?"), stderr)
        return False
    return True


def _iface_exists(runner: Runner, iface: str) -> bool:
    return _ip(runner, ["link", "show", iface])


def _has_from_lookup_rule(runner: Runner, *, cidr: str, table: int) -> bool:
    """True when an identical from/lookup policy rule already exists."""
    try:
        result = runner(["ip", "-j", "rule", "show"], check=False, timeout=5)
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
        result = runner(["ip", "rule", "show", "from", cidr], check=False, timeout=5)
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        return False
    text = str(getattr(result, "stdout", "") or "")
    needle_a = f"lookup {table}"
    needle_b = f"table {table}"
    return needle_a in text or needle_b in text


def _soften_rp_filter(runner: Runner, iface: str) -> None:
    """Strict rp_filter breaks multi-exit WG tunnels that share similar addressing."""
    if not shutil.which("sysctl"):
        return
    try:
        runner(
            ["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0"],
            check=False,
            timeout=5,
        )
    except Exception:
        pass


def _flush_conntrack(runner: Runner, addr: str) -> None:
    """Drop sticky NAT/forward states so the peer immediately uses the new exit."""
    host = str(addr or "").split("/", 1)[0].strip()
    if not host:
        return
    if shutil.which("conntrack"):
        for direction in ("-s", "-d"):
            try:
                runner(["conntrack", "-D", direction, host], check=False, timeout=5)
            except Exception:
                pass
        return
    # nft / iptables cannot easily wipe by IP here; conntrack-tools is preferred.


def _install_default_route(runner: Runner, *, iface: str, table: int) -> bool:
    """Prefer `default via <gw> dev <iface>` when main table has a gateway on that NIC."""
    via = _gateway_for_iface(runner, iface)
    if via:
        return _ip(runner, ["route", "replace", "default", "via", via, "dev", iface, "table", str(table)])
    return _ip(runner, ["route", "replace", "default", "dev", iface, "table", str(table)])


def _gateway_for_iface(runner: Runner, iface: str) -> str | None:
    try:
        result = runner(["ip", "-4", "route", "show", "default"], check=False, timeout=5)
    except Exception:
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    stdout = str(getattr(result, "stdout", "") or "")
    for line in stdout.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        try:
            dev = parts[parts.index("dev") + 1]
        except (ValueError, IndexError):
            continue
        if dev != iface:
            continue
        if "via" in parts:
            try:
                return parts[parts.index("via") + 1]
            except (ValueError, IndexError):
                return None
        return None
    return None


def _ensure_ip_forward(runner: Runner) -> None:
    try:
        path = "/proc/sys/net/ipv4/ip_forward"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("1\n")
    except OSError:
        if shutil.which("sysctl"):
            try:
                runner(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, timeout=5)
            except Exception:
                pass

    # Strict all/default rp_filter breaks multi-exit peer egress after region switch.
    if shutil.which("sysctl"):
        for key in ("all", "default"):
            try:
                runner(
                    ["sysctl", "-w", f"net.ipv4.conf.{key}.rp_filter=0"],
                    check=False,
                    timeout=5,
                )
            except Exception:
                pass

    _persist_sysctl_forward()


def _persist_sysctl_forward() -> bool:
    """Survive reboot without relying on manual host firewall edits."""
    content = (
        "# Managed by Netinja agent peer egress — do not edit.\n"
        "net.ipv4.ip_forward=1\n"
        "net.ipv4.conf.all.rp_filter=0\n"
        "net.ipv4.conf.default.rp_filter=0\n"
    )
    try:
        _SYSCTL_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        previous = _SYSCTL_DROPIN.read_text(encoding="utf-8") if _SYSCTL_DROPIN.is_file() else ""
        if previous != content:
            _SYSCTL_DROPIN.write_text(content, encoding="utf-8")
        return True
    except OSError as exc:
        log.warning("peer egress sysctl drop-in failed: %s", exc)
        return False


def _nat_already_healthy(ifaces: list[str], *, runner: Runner) -> bool:
    """True when the preferred NAT backend already covers every exit iface."""
    if not ifaces:
        return True
    if shutil.which("nft"):
        return _nft_has_masquerade_for(ifaces, runner=runner)
    if shutil.which("iptables-legacy"):
        return all(
            _iptables(
                runner,
                ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                quiet=True,
                binary="iptables-legacy",
            )
            or _iptables(
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
            for iface in ifaces
        )
    if shutil.which("iptables"):
        return all(
            _iptables(
                runner,
                ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                quiet=True,
            )
            or _iptables(
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
            for iface in ifaces
        )
    return False


def _sync_masquerade(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
) -> None:
    """Install SNAT/MASQUERADE on every exit NIC using a single backend.

    Installing the same MASQUERADE on nft + iptables + iptables-legacy at once
    double-SNATs packets and shows up as packet loss after region switches.
    """
    targets = sorted({*ifaces, *[str(x) for x in previous_ifaces if str(x).strip()]})
    nft_ok = False
    if shutil.which("nft"):
        _sync_masquerade_nft(ifaces, runner=runner, tunnel_ifaces=tunnel_ifaces or [])
        nft_ok = _nft_has_masquerade_for(ifaces, runner=runner)

    if nft_ok:
        for binary in ("iptables", "iptables-legacy"):
            if shutil.which(binary):
                _purge_iptables_exit_masq(targets, runner=runner, binary=binary)
        return

    if shutil.which("iptables-legacy"):
        _sync_masquerade_iptables(ifaces, previous_ifaces=previous_ifaces, runner=runner, binary="iptables-legacy")
        _sync_forward(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            tunnel_ifaces=tunnel_ifaces or [],
            binary="iptables-legacy",
        )
        if shutil.which("iptables") and _iptables_is_nft(runner):
            _purge_iptables_exit_masq(targets, runner=runner, binary="iptables")
        return

    if shutil.which("iptables"):
        _sync_masquerade_iptables(ifaces, previous_ifaces=previous_ifaces, runner=runner, binary="iptables")
        _sync_forward(
            ifaces,
            previous_ifaces=previous_ifaces,
            runner=runner,
            tunnel_ifaces=tunnel_ifaces or [],
            binary="iptables",
        )


def _sync_forward(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
    binary: str | None = None,
) -> None:
    # nft FORWARD (+ MSS clamp) lives in _sync_masquerade_nft.
    if shutil.which("nft") and _nft_has_masquerade_for(ifaces, runner=runner):
        return
    chosen = binary
    if not chosen:
        if shutil.which("iptables-legacy"):
            chosen = "iptables-legacy"
        elif shutil.which("iptables"):
            chosen = "iptables"
        else:
            return
    _sync_forward_iptables(
        ifaces,
        previous_ifaces=previous_ifaces,
        runner=runner,
        binary=chosen,
        tunnel_ifaces=tunnel_ifaces or [],
    )

def _iptables_is_nft(runner: Runner) -> bool:
    try:
        result = runner(["iptables", "-V"], check=False, timeout=5)
    except Exception:
        return False
    text = f"{getattr(result, 'stdout', '')} {getattr(result, 'stderr', '')}".lower()
    return "nf_tables" in text


def _nft_has_masquerade_for(ifaces: list[str], *, runner: Runner) -> bool:
    if not ifaces:
        return True
    try:
        result = runner(
            ["nft", "-j", "list", "chain", "inet", "netinja_egress", "postrouting"],
            check=False,
            timeout=10,
        )
    except Exception:
        return False
    if getattr(result, "returncode", 1) != 0:
        # Fallback: plain text list
        try:
            result = runner(
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


def _purge_iptables_exit_masq(ifaces: list[str], *, runner: Runner, binary: str) -> None:
    for iface in ifaces:
        if not iface:
            continue
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        # Uncommented duplicates from manual ops / older agent.
        for _ in range(8):
            if not _iptables(
                runner,
                ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                quiet=True,
                binary=binary,
            ):
                break
        for _ in range(8):
            if not _iptables(
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


def _sync_forward_iptables(
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
            _iptables(
                runner,
                ["-D", "FORWARD", *args, "-m", "comment", "--comment", comment, "-j", jump, *extra],
                binary=binary,
            )

    for iface in ifaces:
        mss_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-mss"
        out_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-out"
        in_comment = f"{_MASQ_COMMENT_PREFIX}{iface}-fwd-in"
        if not _iptables(
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
            _iptables(
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
        if not _iptables(
            runner,
            ["-C", "FORWARD", "-o", iface, "-m", "comment", "--comment", out_comment, "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            _iptables(
                runner,
                ["-I", "FORWARD", "1", "-o", iface, "-m", "comment", "--comment", out_comment, "-j", "ACCEPT"],
                binary=binary,
            )
        if not _iptables(
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
            _iptables(
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
        _soften_rp_filter(runner, tunnel)
        tunnel_comment = f"{_MASQ_COMMENT_PREFIX}tunnel-{tunnel}"
        if not _iptables(
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
            _iptables(
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
        if not _iptables(
            runner,
            ["-C", "FORWARD", "-i", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-in", "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            _iptables(
                runner,
                ["-I", "FORWARD", "1", "-i", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-in", "-j", "ACCEPT"],
                binary=binary,
            )
        if not _iptables(
            runner,
            ["-C", "FORWARD", "-o", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-out", "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            _iptables(
                runner,
                ["-I", "FORWARD", "1", "-o", tunnel, "-m", "comment", "--comment", f"{tunnel_comment}-out", "-j", "ACCEPT"],
                binary=binary,
            )


def _forward_already_healthy(tunnel_ifaces: list[str], *, runner: Runner) -> bool:
    if not tunnel_ifaces:
        return True
    if shutil.which("nft"):
        try:
            result = runner(
                ["nft", "list", "chain", "inet", "netinja_egress", "forward"],
                check=False,
                timeout=10,
            )
        except Exception:
            return False
        if getattr(result, "returncode", 1) != 0:
            return False
        text = str(getattr(result, "stdout", "") or "")
        return all(f"tunnel-{tunnel}-in" in text or f"tunnel-{tunnel}-mss" in text for tunnel in tunnel_ifaces)

    binary = "iptables-legacy" if shutil.which("iptables-legacy") else ("iptables" if shutil.which("iptables") else None)
    if not binary:
        return False
    for tunnel in tunnel_ifaces:
        comment = f"{_MASQ_COMMENT_PREFIX}tunnel-{tunnel}-in"
        if not _iptables(
            runner,
            ["-C", "FORWARD", "-i", tunnel, "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            quiet=True,
            binary=binary,
        ):
            return False
    return True

def _sync_masquerade_nft(
    ifaces: list[str],
    *,
    runner: Runner,
    tunnel_ifaces: list[str] | None = None,
) -> None:
    _nft(runner, ["add", "table", "inet", "netinja_egress"])
    _nft(
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
    _nft(
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
    _nft(runner, ["flush", "chain", "inet", "netinja_egress", _NFT_CHAIN])
    _nft(runner, ["flush", "chain", "inet", "netinja_egress", "forward"])
    for iface in ifaces:
        _nft(
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
        _nft(
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
        _nft(
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
        _nft(
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
        _soften_rp_filter(runner, tunnel)
        tunnel_comment = f"{_MASQ_COMMENT_PREFIX}tunnel-{tunnel}"
        _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "iifname",
                tunnel,
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
        _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "iifname",
                tunnel,
                "accept",
                "comment",
                f"{tunnel_comment}-in",
            ],
        )
        _nft(
            runner,
            [
                "add",
                "rule",
                "inet",
                "netinja_egress",
                "forward",
                "oifname",
                tunnel,
                "accept",
                "comment",
                f"{tunnel_comment}-out",
            ],
        )


def _sync_masquerade_iptables(
    ifaces: list[str],
    *,
    previous_ifaces: list[str],
    runner: Runner,
    binary: str = "iptables",
) -> None:
    wanted = set(ifaces)
    for iface in previous_ifaces:
        if iface in wanted:
            continue
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        _iptables(
            runner,
            ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            binary=binary,
        )
        # Also drop un-commented legacy rules we may have installed manually.
        _iptables(
            runner,
            ["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        )
    for iface in ifaces:
        comment = f"{_MASQ_COMMENT_PREFIX}{iface}"
        check = _iptables(
            runner,
            ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        )
        if check:
            continue
        # Prefer commented rule; if an uncommented twin exists, keep one path working.
        if _iptables(
            runner,
            ["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
            quiet=True,
            binary=binary,
        ):
            continue
        _iptables(
            runner,
            ["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"],
            binary=binary,
        )


def _nft(runner: Runner, args: list[str]) -> bool:
    try:
        result = runner(["nft", *args], check=False, timeout=10)
    except Exception as exc:
        log.warning("nft %s failed: %s", " ".join(args), exc)
        return False
    if getattr(result, "returncode", 1) != 0:
        stderr = (getattr(result, "stderr", None) or "").strip().lower()
        if "exist" in stderr:
            return True
        log.warning("nft %s rc=%s %s", " ".join(args), getattr(result, "returncode", "?"), stderr)
        return False
    return True


def _iptables(runner: Runner, args: list[str], *, quiet: bool = False, binary: str = "iptables") -> bool:
    try:
        result = runner([binary, *args], check=False, timeout=10)
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
