"""Wipe the node agent's stored state back to an empty install.

The systemd unit, binaries, and /etc/agent/.env (listen address and auth token)
stay in place so the panel can reach the node again. Everything the agent
learned from a server transfer — database, WireGuard/Amnezia configs, egress
rules, certificates under the data directory, and the Xray config — is removed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from agent.config import AgentSettings, load_settings
from agent.db import Store

CONFIRM_TEXT = "CONFIRM"

RESET_WARNING = (
    "This permanently erases the agent database, WireGuard and Amnezia configs "
    "stored by the agent, peer-egress rules, TLS files under the data directory, "
    "and resets the Xray config to an empty API config.\n"
    "The auth token in /etc/agent/.env is kept.\n"
    "Type CONFIRM to continue."
)

_IFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_PREF_MIN = 15000
_PREF_MAX = 19999

Runner = Callable[..., Any]


def confirmation_accepted(typed: str | None) -> bool:
    return str(typed or "").strip() == CONFIRM_TEXT


async def factory_reset(
    settings: AgentSettings | None = None,
    *,
    runner: Runner | None = None,
    stop_service: bool = True,
) -> dict[str, Any]:
    """Blank the agent database and the settings derived from it."""
    from agent.ops import run_cmd, which

    cfg = settings or load_settings()
    execute = runner or run_cmd
    removed: list[str] = []
    masked = False
    result: dict[str, Any] | None = None

    managed = await _managed_configs(cfg)
    try:
        if stop_service and which("systemctl"):
            _run(execute, ["systemctl", "mask", "agent"])
            masked = True
            _run(execute, ["systemctl", "kill", "-s", "SIGKILL", "agent"])
            _run(execute, ["systemctl", "reset-failed", "agent"])
        result = _wipe(cfg, execute, managed, removed)
        return result
    finally:
        if masked:
            _run(execute, ["systemctl", "unmask", "agent"])
            start = _run(execute, ["systemctl", "start", "agent"])
            if result is not None:
                result["service_restarted"] = getattr(start, "returncode", 1) == 0


def _wipe(
    cfg: AgentSettings,
    execute: Runner,
    managed: list[tuple[str, Path, str]],
    removed: list[str],
) -> dict[str, Any]:
    for quick, conf, name in managed:
        quick_bin = shutil.which(quick)
        if quick_bin and conf.is_file():
            _run(execute, [quick_bin, "down", str(conf)])
        _run(execute, ["ip", "link", "delete", "dev", name])
        if conf.is_file() or conf.is_symlink():
            conf.unlink()
            removed.append(str(conf))

    rules_removed = _clear_agent_policy_rules(execute)
    _run(execute, ["nft", "delete", "table", "inet", "netinja_egress"])

    from agent.support.peer_egress import apply_script_path

    script = apply_script_path(cfg.data_dir)
    for path in (script, Path(str(script) + ".lock")):
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(str(path))

    db_removed = _delete_database(cfg.resolve_db_path())
    removed.extend(db_removed)

    certs = Path(cfg.data_dir) / "certs"
    if _inside(certs, Path(cfg.data_dir)) and (certs.is_dir() or certs.is_symlink()):
        _remove_path(certs)
        removed.append(str(certs))

    xray_reset = _reset_xray_config(cfg, execute)

    return {
        "ok": True,
        "removed": removed,
        "policy_rules_removed": rules_removed,
        "xray_reset": xray_reset,
        "service_restarted": False,
    }


async def _managed_configs(settings: AgentSettings) -> list[tuple[str, Path, str]]:
    db_path = settings.resolve_db_path()
    if not db_path.is_file():
        return []
    store = Store(db_path)
    try:
        await store.open()
        rows: list[tuple[str, Path, str]] = []
        for core, config_dir, quick in (
            ("wireguard", settings.wireguard.config_dir, "wg-quick"),
            ("amnezia", settings.amnezia.config_dir, "awg-quick"),
        ):
            root = Path(config_dir)
            for doc in await store.list_docs(core, "interface"):
                name = str(doc.get("name") or "").strip()
                if not _IFACE_NAME.match(name):
                    continue
                conf = root / f"{name}.conf"
                if not _inside(conf, root):
                    continue
                rows.append((quick, conf, name))
        return rows
    finally:
        await store.close()


def _delete_database(db_path: Path) -> list[str]:
    removed: list[str] = []
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(str(db_path) + suffix) if suffix else db_path
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(str(path))
    return removed


def _reset_xray_config(settings: AgentSettings, runner: Runner) -> bool:
    config_path = Path(settings.xray_config)
    if not config_path.is_file():
        return False
    from agent.xray_service import default_xray_config

    payload = default_xray_config(
        api_base=settings.xray_api_base,
        username=settings.xray_username,
        password=settings.xray_password,
        config_path=str(config_path),
    )
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _run(runner, ["systemctl", "restart", "xray"])
    return True


def _clear_agent_policy_rules(runner: Runner) -> list[int]:
    proc = _run(runner, ["ip", "-4", "rule", "show"])
    text = str(getattr(proc, "stdout", "") or "")
    prefs: list[int] = []
    for line in text.splitlines():
        head = line.split(":", 1)[0].strip()
        if not head.isdigit():
            continue
        pref = int(head)
        if _PREF_MIN <= pref <= _PREF_MAX:
            prefs.append(pref)
    removed: list[int] = []
    for pref in prefs:
        _run(runner, ["ip", "rule", "del", "pref", str(pref)])
        removed.append(pref)
    return removed


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    if path.is_dir():
        shutil.rmtree(path)


def _run(runner: Runner, args: list[str]) -> Any:
    try:
        return runner(args, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
