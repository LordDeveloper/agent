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


async def _primary_ipv4(iface: str, runner: Runner | None) -> str:
    result = await execute(runner, ["ip", "-4", "addr", "show", "dev", iface], check=False, timeout=5)
    if not _ok(result):
        return ""
    match = _INET_RE.search(_stdout(result))
    return match.group(1) if match else ""


async def ensure_interface_bind_route(iface: str, *, runner: Runner | None = None) -> dict[str, Any]:
    name = normalize_exit_interface(iface)
    if not name:
        raise AgentError("VALIDATION_ERROR", f"Invalid exit interface [{iface}]", 422)

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
    pref = bind_pref(name)
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

    await execute(
        runner,
        ["ip", "rule", "del", "oif", name, "lookup", str(table)],
        check=False,
        timeout=5,
    )
    added = await execute(
        runner,
        ["ip", "rule", "add", "oif", name, "lookup", str(table), "pref", str(pref)],
        check=False,
        timeout=5,
    )
    if not _ok(added):
        detail = str(getattr(added, "stderr", "") or _stdout(added)).strip()
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
