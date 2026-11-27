"""Route Xray freedom sockets that are bound to an exit device.

Mullvad-style tunnels use ``Table = off``, so ``SO_BINDTODEVICE`` still
follows the main routing table unless an ``oif`` rule selects the
per-interface table. These helpers never replace the main default route.
"""

from __future__ import annotations

import json
import os
import re
import zlib
from pathlib import Path
from typing import Any, Callable

from agent.errors import AgentError
from agent.support.peer_egress import normalize_exit_interface, table_id_for_interface
from agent.support.process import execute

Runner = Callable[..., Any]
_INET_RE = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)")


def public_pin_state_path() -> Path:
    override = os.environ.get("NETINJA_XRAY_PUBLIC_PINS", "").strip()
    if override:
        return Path(override)
    return Path("/var/lib/netinja-agent/xray-public-pins.json")


def pins_from_outbounds(outbounds: list[Any]) -> list[dict[str, Any]]:
    """Public sources already stored on freedom outbounds."""
    from agent.support.peer_egress import egress_mark, public_exit_ipv4

    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        if str(outbound.get("protocol") or "").lower() != "freedom":
            continue
        address = public_exit_ipv4(outbound.get("sendThrough"))
        if not address or address in seen:
            continue
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
        try:
            mark = int(sockopt.get("mark") or 0)
        except (TypeError, ValueError):
            mark = 0
        if mark <= 0:
            mark = egress_mark(address)
        seen.add(address)
        found.append({"ip": address, "mark": mark})
    return found


def load_public_pins(path: Path | None = None) -> list[dict[str, Any]]:
    file = path or public_pin_state_path()
    if not file.is_file():
        return []
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw = payload.get("pins") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    return pins_from_outbounds(
        [
            {
                "protocol": "freedom",
                "sendThrough": row.get("ip"),
                "streamSettings": {"sockopt": {"mark": row.get("mark")}},
            }
            for row in raw
            if isinstance(row, dict)
        ]
    )


def save_public_pins(pins: list[dict[str, Any]], path: Path | None = None) -> None:
    file = path or public_pin_state_path()
    file.parent.mkdir(parents=True, exist_ok=True)
    clean = pins_from_outbounds(
        [
            {
                "protocol": "freedom",
                "sendThrough": row.get("ip"),
                "streamSettings": {"sockopt": {"mark": row.get("mark")}},
            }
            for row in pins
            if isinstance(row, dict)
        ]
    )
    file.write_text(json.dumps({"pins": clean}, indent=2) + "\n", encoding="utf-8")


def remember_public_pins(pins: list[dict[str, Any]], path: Path | None = None) -> None:
    """Keep pins from one outbound edit without dropping the other nodes."""
    merged = {str(row["ip"]): row for row in load_public_pins(path)}
    for row in pins_from_outbounds(
        [
            {
                "protocol": "freedom",
                "sendThrough": item.get("ip"),
                "streamSettings": {"sockopt": {"mark": item.get("mark")}},
            }
            for item in pins
            if isinstance(item, dict)
        ]
    ):
        merged[str(row["ip"])] = row
    save_public_pins(list(merged.values()), path)


def public_pin_script_lines(pins: list[dict[str, Any]]) -> list[str]:
    """Boot snippet: NAT pin plus a from-source route for each saved Xray address."""
    lines: list[str] = []
    if not pins:
        return lines
    lines.extend(
        [
            "if command -v nft >/dev/null 2>&1; then",
            "  nft add table inet netinja_egress 2>/dev/null || true",
            "  nft add chain inet netinja_egress srcpin "
            '"{ type nat hook postrouting priority -10; policy accept; }" 2>/dev/null || true',
            "  nft flush chain inet netinja_egress srcpin 2>/dev/null || true",
        ]
    )
    for row in pins:
        address = str(row["ip"])
        mark = int(row["mark"])
        lines.append(
            f'  nft add rule inet netinja_egress srcpin ip saddr {address} '
            f'accept comment "netinja-pin-{address}" 2>/dev/null || true'
        )
        lines.append(
            f'  nft add rule inet netinja_egress srcpin meta mark {hex(mark)} '
            f'snat to {address} accept comment "netinja-mark-{mark}" 2>/dev/null || true'
        )
    lines.append("fi")
    for row in pins:
        address = str(row["ip"])
        table = table_id_for_source(address)
        pref = source_rule_pref(address)
        lines.extend(
            [
                f'_src_dev=$(ip -o -4 addr show | awk \'$4 ~ /^{address}\\// {{print $2; exit}}\')',
                'if [ -n "$_src_dev" ]; then',
                '  _src_gw=$(ip -4 route show default | awk -v dev="$_src_dev" \'$1=="default" && $2=="via" && index($0, "dev " dev)>0 {print $3; exit}\')',
                '  if [ -n "$_src_gw" ]; then',
                f'    ip route replace default via "$_src_gw" dev "$_src_dev" src {address} table {table} 2>/dev/null || true',
                f'    ip rule del from {address} lookup {table} 2>/dev/null || true',
                f'    ip rule add from {address} lookup {table} pref {pref} 2>/dev/null || true',
                "  fi",
                "fi",
            ]
        )
    return lines


async def reapply_config_public_pins(config_path: str | Path | None) -> list[dict[str, Any]]:
    """Put saved Xray source pins back after an agent restart.

    The nft rules are not part of the Xray config. A package update drops them
    unless they are installed again from sendThrough on disk.
    """
    from agent.support.peer_egress import pin_public_egress

    pins: list[dict[str, Any]] = []
    path = Path(config_path) if config_path else None
    if path is not None and path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            pins = pins_from_outbounds(list(payload.get("outbounds") or []))
    if pins:
        save_public_pins(pins)
    else:
        pins = load_public_pins()
    for row in pins:
        await pin_public_egress(str(row["ip"]), int(row["mark"]))
        try:
            await ensure_source_address_route(str(row["ip"]))
        except Exception:
            continue
    return pins


def bind_state_path() -> Path:
    override = os.environ.get("NETINJA_XRAY_EXIT_BINDS", "").strip()
    if override:
        return Path(override)
    return Path("/var/lib/netinja-agent/xray-exit-binds.json")


def bind_pref(iface: str) -> int:
    """Stable preference below peer rules (15000+) and above local specials."""
    digest = zlib.crc32(iface.encode("utf-8")) & 0xFFFF
    return 11000 + (digest % 3000)


def load_bind_ifaces(path: Path | None = None) -> list[str]:
    file = path or bind_state_path()
    if not file.is_file():
        return []
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw = payload.get("interfaces") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in raw:
        name = normalize_exit_interface(item)
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def save_bind_ifaces(ifaces: list[str], path: Path | None = None) -> None:
    file = path or bind_state_path()
    file.parent.mkdir(parents=True, exist_ok=True)
    clean = load_bind_ifaces(file)
    seen = set(clean)
    for item in ifaces:
        name = normalize_exit_interface(item)
        if not name or name in seen:
            continue
        seen.add(name)
        clean.append(name)
    file.write_text(
        json.dumps({"interfaces": clean}, indent=2) + "\n",
        encoding="utf-8",
    )


def forget_bind_iface(iface: str, path: Path | None = None) -> None:
    name = normalize_exit_interface(iface)
    if not name:
        return
    file = path or bind_state_path()
    kept = [item for item in load_bind_ifaces(file) if item != name]
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"interfaces": kept}, indent=2) + "\n", encoding="utf-8")


def bind_table_ids(path: Path | None = None) -> list[int]:
    return [table_id_for_interface(name) for name in load_bind_ifaces(path)]


def script_lines(ifaces: list[str]) -> list[str]:
    """Shell applied on boot. Routes go into the interface table, not main."""
    lines = [
        "",
        "# Xray freedom sockets bound to an exit device. Does not change the main default route.",
    ]
    for raw in ifaces:
        name = normalize_exit_interface(raw)
        if not name:
            continue
        table = table_id_for_interface(name)
        if table < 10000:
            continue
        pref = bind_pref(name)
        lines.extend(
            [
                f'if ip link show "{name}" >/dev/null 2>&1; then',
                f'  sysctl -w "net.ipv4.conf.{name}.rp_filter=0" >/dev/null 2>&1 || true',
                f'  ip route replace default dev "{name}" table {table} 2>/dev/null || true',
                f'  ip rule del pref {pref} 2>/dev/null || true',
                f'  ip rule del oif "{name}" lookup {table} 2>/dev/null || true',
                f'  ip rule add oif "{name}" lookup {table} pref {pref} 2>/dev/null || true',
                "fi",
            ]
        )
    lines.append("")
    return lines


def _stdout(result: Any) -> str:
    return str(getattr(result, "stdout", "") or "")


def _ok(result: Any) -> bool:
    return int(getattr(result, "returncode", 1) or 0) == 0


def parse_ip_rule_line(line: str) -> dict[str, Any] | None:
    """One ``ip rule show`` line: ``11042: from all oif uk lookup 15234``."""
    raw = line.strip()
    if not raw or ":" not in raw:
        return None
    pref_text, rest = raw.split(":", 1)
    pref_text = pref_text.strip()
    if not pref_text.isdigit():
        return None
    parts = rest.split()
    oif = ""
    table = ""
    index = 0
    while index < len(parts):
        token = parts[index]
        if token == "oif" and index + 1 < len(parts):
            oif = parts[index + 1]
            index += 2
            continue
        if token == "lookup" and index + 1 < len(parts):
            table = parts[index + 1]
            index += 2
            continue
        index += 1
    if table == "":
        return None
    return {"pref": int(pref_text), "oif": oif, "table": table}


def parse_ip_rules(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in str(text or "").splitlines():
        row = parse_ip_rule_line(line)
        if row is not None:
            rows.append(row)
    return rows


def _same_table(token: str, table: int) -> bool:
    raw = str(token or "").strip()
    if raw == str(table):
        return True
    try:
        return int(raw, 10) == table
    except ValueError:
        return False


def choose_bind_pref(iface: str, taken: set[int]) -> int:
    """Preference in 11000–13999. A hash collision uses the next free slot."""
    base = bind_pref(iface)
    if base not in taken:
        return base
    origin = (base - 11000) % 3000
    for offset in range(1, 3000):
        candidate = 11000 + ((origin + offset) % 3000)
        if candidate not in taken:
            return candidate
    raise AgentError(
        "EXEC_ERROR",
        f"No free ip-rule preference for exit interface [{iface}]",
        500,
    )


def _rule_is_ours(row: dict[str, Any], name: str, table: int) -> bool:
    return str(row.get("oif") or "") == name and _same_table(str(row.get("table") or ""), table)


def _rule_to_drop(row: dict[str, Any], name: str, table: int, keep_pref: int | None) -> bool:
    """Stale oif rules for this exit, plus a dead ifindex still holding our table."""
    pref = int(row["pref"])
    if keep_pref is not None and pref == keep_pref:
        return False
    oif = str(row.get("oif") or "")
    if oif == name:
        return True
    return oif.isdigit() and _same_table(str(row.get("table") or ""), table)


def _keeper(rows: list[dict[str, Any]], name: str) -> dict[str, Any]:
    preferred = bind_pref(name)
    return min(rows, key=lambda row: (int(row["pref"]) != preferred, int(row["pref"])))


async def _primary_ipv4(iface: str, runner: Runner | None) -> str:
    result = await execute(runner, ["ip", "-4", "addr", "show", "dev", iface], check=False, timeout=5)
    if not _ok(result):
        return ""
    match = _INET_RE.search(_stdout(result))
    return match.group(1) if match else ""


def _gateway_on_dev(route_text: str, dev: str) -> str:
    """Gateway of a main-table default route already leaving through ``dev``."""
    iface = str(dev or "").strip()
    for line in str(route_text or "").splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        found = ""
        gateway = ""
        for index, token in enumerate(parts):
            if token == "dev" and index + 1 < len(parts):
                found = parts[index + 1]
            elif token == "via" and index + 1 < len(parts):
                gateway = parts[index + 1]
        if found == iface and gateway:
            return gateway
    return ""


async def _main_gateway(dev: str, runner: Runner | None) -> str:
    result = await execute(runner, ["ip", "-4", "route", "show", "default"], check=False, timeout=5)
    if not _ok(result):
        return ""
    return _gateway_on_dev(_stdout(result), dev)


async def release_interface_bind_route(iface: str, *, runner: Runner | None = None) -> dict[str, Any]:
    """Drop an oif policy rule for a normal NIC. That rule blackholes its main default route."""
    name = normalize_exit_interface(iface)
    if not name:
        raise AgentError("VALIDATION_ERROR", f"Invalid exit interface [{iface}]", 422)

    table = table_id_for_interface(name)
    rules = await _show_ip_rules(runner)
    removed = 0
    for row in rules:
        if table >= 10000 and _rule_to_drop(row, name, table, None):
            await _delete_rule_pref(runner, int(row["pref"]))
            removed += 1
    if table >= 10000:
        await execute(
            runner,
            ["ip", "route", "del", "default", "dev", name, "table", str(table)],
            check=False,
            timeout=5,
        )
    forget_bind_iface(name)
    return {"ok": True, "released": True, "interface": name, "removed_rules": removed}


async def release_binds_on_main_nics(*, runner: Runner | None = None) -> None:
    for name in load_bind_ifaces():
        if await _main_gateway(name, runner):
            await release_interface_bind_route(name, runner=runner)


async def ensure_interface_bind_route(iface: str, *, runner: Runner | None = None) -> dict[str, Any]:
    name = normalize_exit_interface(iface)
    if not name:
        raise AgentError("VALIDATION_ERROR", f"Invalid exit interface [{iface}]", 422)

    # A host NIC that already has ``default via <gw> dev <nic>`` must not get an
    # ``oif <nic>`` rule. That rule sends every packet out the NIC into a table
    # whose default route has no gateway, which drops the server's own traffic.
    if await _main_gateway(name, runner):
        released = await release_interface_bind_route(name, runner=runner)
        return {**released, "skipped": "main-default-route"}

    link = await execute(runner, ["ip", "link", "show", "dev", name], check=False, timeout=5)
    if not _ok(link):
        detail = (_stdout(link) or str(getattr(link, "stderr", "") or "")).strip()
        raise AgentError(
            "CONFIG_NOT_FOUND",
            f"Exit interface [{name}] is not present on this host"
            + (f": {detail[:160]}" if detail else ""),
            422,
        )

    table = table_id_for_interface(name)
    if table < 10000:
        raise AgentError("VALIDATION_ERROR", f"Refusing to install a main-table route for [{name}]", 422)
    source = await _primary_ipv4(name, runner)

    await execute(
        runner,
        ["sysctl", "-w", f"net.ipv4.conf.{name}.rp_filter=0"],
        check=False,
        timeout=5,
    )
    route = ["ip", "route", "replace", "default", "dev", name]
    if source:
        route.extend(["src", source])
    route.extend(["table", str(table)])
    replaced = await execute(runner, route, check=False, timeout=5)
    if not _ok(replaced):
        detail = str(getattr(replaced, "stderr", "") or _stdout(replaced)).strip()
        raise AgentError(
            "EXEC_ERROR",
            f"Could not install a default route for [{name}] in table {table}"
            + (f": {detail[:180]}" if detail else ""),
            500,
        )

    # ``ip rule add pref N`` returns EEXIST when that priority is already taken.
    # Re-sync hits this whenever the oif rule is already installed, or a previous
    # ifindex still occupies N after the tunnel device was recreated. Delete only
    # this interface's stale rules; leave another exit's rule on a shared pref.
    rules = await _show_ip_rules(runner)
    correct = [row for row in rules if _rule_is_ours(row, name, table)]
    keep_pref = int(_keeper(correct, name)["pref"]) if correct else None
    for row in rules:
        if _rule_to_drop(row, name, table, keep_pref):
            await _delete_rule_pref(runner, int(row["pref"]))

    if keep_pref is not None:
        save_bind_ifaces([name])
        return {
            "ok": True,
            "interface": name,
            "table": table,
            "pref": keep_pref,
            "source": source or None,
        }

    taken = {
        int(row["pref"])
        for row in rules
        if not _rule_to_drop(row, name, table, None)
    }
    pref = choose_bind_pref(name, taken)
    added = await execute(
        runner,
        ["ip", "rule", "add", "oif", name, "lookup", str(table), "pref", str(pref)],
        check=False,
        timeout=5,
    )
    if not _ok(added):
        detail = str(getattr(added, "stderr", "") or _stdout(added)).strip()
        if "file exists" in detail.lower():
            again = await _show_ip_rules(runner)
            existing = next((row for row in again if _rule_is_ours(row, name, table)), None)
            if existing is not None:
                save_bind_ifaces([name])
                return {
                    "ok": True,
                    "interface": name,
                    "table": table,
                    "pref": int(existing["pref"]),
                    "source": source or None,
                }
        raise AgentError(
            "EXEC_ERROR",
            f"Could not add oif rule for [{name}]"
            + (f": {detail[:180]}" if detail else ""),
            500,
        )

    save_bind_ifaces([name])
    return {
        "ok": True,
        "interface": name,
        "table": table,
        "pref": pref,
        "source": source or None,
    }


async def _show_ip_rules(runner: Runner | None) -> list[dict[str, Any]]:
    result = await execute(runner, ["ip", "rule", "show"], check=False, timeout=5)
    if not _ok(result):
        detail = str(getattr(result, "stderr", "") or _stdout(result)).strip()
        raise AgentError(
            "EXEC_ERROR",
            "Could not list ip rules" + (f": {detail[:180]}" if detail else ""),
            500,
        )
    return parse_ip_rules(_stdout(result))


async def _delete_rule_pref(runner: Runner | None, pref: int) -> None:
    await execute(
        runner,
        ["ip", "rule", "del", "pref", str(pref)],
        check=False,
        timeout=5,
    )


def table_id_for_source(ip: str) -> int:
    """Side table for one public source address. Kept out of the oif-bind range."""
    digest = zlib.crc32(f"src:{ip}".encode("utf-8")) & 0xFFFF
    return 30000 + (digest % 20000)


def source_rule_pref(ip: str) -> int:
    digest = zlib.crc32(f"src-pref:{ip}".encode("utf-8")) & 0xFFFF
    return 9000 + (digest % 800)


async def _device_for_ipv4(ip: str, runner: Runner | None) -> str:
    result = await execute(runner, ["ip", "-o", "-4", "addr", "show"], check=False, timeout=5)
    if not _ok(result):
        return ""
    needle = f" {ip}/"
    for line in _stdout(result).splitlines():
        if needle not in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            return parts[1].split("@", 1)[0]
    return ""


async def ensure_source_address_route(ip: str, *, runner: Runner | None = None) -> dict[str, Any]:
    """Send packets sourced from an extra public IP back out that address.

    This is a from-source rule with the NIC's real gateway. It does not install
    an oif rule, which would blackhole every other client on the same NIC.
    """
    address = str(ip or "").strip()
    if not address:
        return {"ok": False, "skipped": True}
    iface = await _device_for_ipv4(address, runner)
    if not iface:
        return {"ok": False, "skipped": True, "reason": "address is not assigned"}
    gateway = await _main_gateway(iface, runner)
    if not gateway:
        return {"ok": False, "skipped": True, "reason": "nic has no default gateway"}

    table = table_id_for_source(address)
    pref = source_rule_pref(address)
    routed = await execute(
        runner,
        [
            "ip", "route", "replace", "default", "via", gateway,
            "dev", iface, "src", address, "table", str(table),
        ],
        check=False,
        timeout=5,
    )
    if not _ok(routed):
        return {"ok": False, "skipped": True, "reason": "route replace failed"}

    listed = await execute(runner, ["ip", "rule", "show"], check=False, timeout=5)
    text = _stdout(listed)
    marker = f"from {address} "
    if marker not in text or f"lookup {table}" not in text:
        await execute(
            runner,
            ["ip", "rule", "add", "from", address, "lookup", str(table), "pref", str(pref)],
            check=False,
            timeout=5,
        )
    return {"ok": True, "address": address, "interface": iface, "table": table, "pref": pref}


async def reapply_saved_binds(*, runner: Runner | None = None) -> dict[str, Any]:
    applied: list[str] = []
    failed: list[dict[str, str]] = []
    for name in load_bind_ifaces():
        try:
            await ensure_interface_bind_route(name, runner=runner)
            applied.append(name)
        except AgentError as exc:
            failed.append({"interface": name, "error": exc.message})
    return {"ok": not failed, "applied": applied, "failed": failed}
