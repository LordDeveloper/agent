from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import httpx

from agent import __version__
from agent.errors import AgentError
from agent.ops import KNOWN_CORES, generate_token, install_core, service_action, which, write_env_file
from agent.tui import (
    BLUE,
    CYAN,
    Choice,
    DIM,
    GREEN,
    MAGENTA,
    RED,
    TAGLINE,
    WHITE,
    YELLOW,
    clear_screen,
    confirm,
    double_line,
    enable_ansi,
    is_interactive,
    kv,
    logo,
    multi_select,
    paint,
    pause,
    prompt_text,
    select,
    show_cursor,
)

GITHUB_REPO = "LordDeveloper/agent"

_host_cache: dict[str, str] | None = None


def _print(text: str = "") -> None:
    print(text)


def _dump(data: Any) -> None:
    _print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _host_info() -> dict[str, str]:
    global _host_cache
    if _host_cache is not None:
        return _host_cache
    info = {
        "ip": "unavailable",
        "location": "unavailable",
        "org": "unavailable",
    }
    try:
        response = httpx.get("https://ipinfo.io/json", timeout=2.5)
        payload = response.json()
        city = str(payload.get("city") or "").strip()
        country = str(payload.get("country") or "").strip()
        location = ", ".join(part for part in (city, country) if part) or "unavailable"
        info = {
            "ip": str(payload.get("ip") or "unavailable"),
            "location": location,
            "org": str(payload.get("org") or "unavailable"),
        }
    except Exception:
        pass
    _host_cache = info
    return info


def _service_state() -> tuple[str, str]:
    try:
        result = service_action("status")
        if result.get("ok"):
            return "Running", GREEN
        return "Stopped", RED
    except AgentError:
        return "Unavailable", YELLOW


def _core_state(name: str) -> tuple[str, str]:
    if name == "xray":
        binary = Path("/usr/local/bin/xray")
        installed = binary.is_file() or which("xray") is not None
    elif name == "wireguard":
        installed = which("wg") is not None
    else:
        installed = which("awg") is not None or which("wg") is not None
    if installed:
        return "Installed", GREEN
    return "Not installed", RED


def render_header(subtitle: str | None = None) -> None:
    clear_screen()
    _print(paint(logo(), CYAN))
    _print()
    _print(paint(f"  {TAGLINE}", WHITE))
    if subtitle:
        _print(paint(f"  {subtitle}", DIM))
    _print()
    _print(double_line())
    _print(kv("Script Version", f"v{__version__}", GREEN))
    _print(kv("GitHub", GITHUB_REPO, GREEN))
    _print(double_line())

    host = _host_info()
    _print(kv("IP Address", host["ip"], MAGENTA))
    _print(kv("Location", host["location"], WHITE))
    _print(kv("Datacenter", host["org"], WHITE))
    svc, svc_color = _service_state()
    _print(kv("Agent service", svc, svc_color))
    for core in KNOWN_CORES:
        state, color = _core_state(core)
        _print(kv(core.capitalize(), state, color))
    _print(double_line())
    _print()


def _run_action(title: str, fn: Callable[[], None]) -> None:
    render_header(title)
    try:
        fn()
    except AgentError as exc:
        _print(paint(f"\n  {exc.message}", RED))
    except KeyboardInterrupt:
        _print(paint("\n  Cancelled.", YELLOW))
    pause()


def _wizard() -> None:
    render_header("Setup wizard")
    env_path = Path(prompt_text("Env file", "/etc/agent/.env") or "/etc/agent/.env")
    listen = prompt_text("Listen", "0.0.0.0:8443")
    data_dir = prompt_text("Data dir", "/var/lib/agent")
    token_in = prompt_text("Auth token (empty = auto)", "")
    token = token_in or generate_token()

    _print(paint("\n  Enable cores (Space to toggle):", WHITE))
    cores = multi_select(
        [
            Choice("xray", "Xray", CYAN),
            Choice("wireguard", "WireGuard", GREEN),
            Choice("amnezia", "Amnezia", BLUE),
        ],
        selected={"xray"},
    )
    if not cores:
        cores = ["xray"]

    if confirm("Install selected cores now?", default=False):
        for core in cores:
            _print(paint(f"  Installing {core}...", CYAN))
            try:
                result = install_core(core)
                _print(paint(f"  ok: {result.get('message')}", GREEN))
            except AgentError as exc:
                _print(paint(f"  failed: {exc.message}", RED))

    write_env_file(env_path, listen=listen, token=token, data_dir=data_dir, cores=cores)
    _print(paint(f"\n  Wrote {env_path}", GREEN))
    _print(kv("Token", token, YELLOW))

    if confirm("Install and restart systemd service?", default=False):
        try:
            service_action("install")
            service_action("restart")
            _print(paint("  Service installed and restarted.", GREEN))
        except AgentError as exc:
            _print(paint(f"  Service setup failed: {exc.message}", RED))


def _cores_menu() -> None:
    while True:
        render_header("Cores")
        picked = select(
            [
                Choice("list", "List cores", CYAN, "1"),
                Choice("xray", "Install Xray", GREEN, "2"),
                Choice("wireguard", "Install WireGuard", GREEN, "3"),
                Choice("amnezia", "Install Amnezia", GREEN, "4"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "list":
            from agent.cli import cmd_core_list

            _run_action("Core list", lambda: cmd_core_list(SimpleNamespace(env_file=None)))
            continue
        if not confirm(f"Install {picked} on this host?", default=True):
            continue

        def _install(name: str = picked) -> None:
            result = install_core(name)
            _dump({"success": True, **result})

        _run_action(f"Install {picked}", _install)


def _service_menu() -> None:
    while True:
        render_header("Service")
        picked = select(
            [
                Choice("status", "Status", CYAN, "1"),
                Choice("install", "Install unit", GREEN, "2"),
                Choice("start", "Start", GREEN, "3"),
                Choice("stop", "Stop", RED, "4"),
                Choice("restart", "Restart", YELLOW, "5"),
                Choice("enable", "Enable on boot", WHITE, "6"),
                Choice("disable", "Disable on boot", WHITE, "7"),
                Choice("uninstall", "Remove unit", RED, "8"),
                Choice("serve", "Start API (foreground)", BLUE, "9"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "serve":
            from agent.cli import cmd_serve

            _run_action("API server", lambda: cmd_serve(SimpleNamespace(env_file=None, host=None, port=None)))
            continue
        if picked in {"uninstall", "stop"} and not confirm(f"{picked.capitalize()} agent service?", default=False):
            continue
        _run_action(f"Service {picked}", lambda action=picked: _dump(service_action(action)))


def _stats_menu() -> None:
    while True:
        render_header("Stats")
        picked = select(
            [
                Choice("snapshot", "Usage snapshot", CYAN, "1"),
                Choice("online", "Online users", GREEN, "2"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        from agent.cli import cmd_stats

        _run_action(
            "Online users" if picked == "online" else "Usage snapshot",
            lambda online=picked == "online": cmd_stats(
                SimpleNamespace(env_file=None, core=None, online_only=online)
            ),
        )


def _update_menu() -> None:
    while True:
        render_header("Update")
        picked = select(
            [
                Choice("check", "Check for update", CYAN, "1"),
                Choice("update", "Update now", GREEN, "2"),
                Choice("force", "Force reinstall latest", YELLOW, "3"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        from agent.cli import cmd_update

        args = SimpleNamespace(
            env_file=None,
            token=None,
            check=picked == "check",
            repo=None,
            asset=None,
            force=picked == "force",
            no_restart=False,
        )
        if picked != "check" and not confirm("Download and install the latest agent release?", default=True):
            continue
        _run_action("Update agent", lambda ns=args: cmd_update(ns))


def _token_menu() -> None:
    while True:
        render_header("Token")
        picked = select(
            [
                Choice("print", "Generate token", CYAN, "1"),
                Choice("write", "Generate and write to .env", GREEN, "2"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        from agent.cli import cmd_token

        _run_action(
            "Auth token",
            lambda write=picked == "write": cmd_token(
                SimpleNamespace(bytes=32, write=write, env_file=None, json=True)
            ),
        )


def _status() -> None:
    from agent.cli import cmd_status

    _run_action("Status", lambda: cmd_status(SimpleNamespace(env_file=None)))


def run_interactive() -> int:
    if not is_interactive():
        print("Interactive menu needs a TTY. Use: agent -h", file=sys.stderr)
        return 2

    enable_ansi()
    columns = shutil.get_terminal_size((80, 24)).columns
    if columns < 48:
        print("Widen the terminal a bit, then run agent again.", file=sys.stderr)
        return 2

    try:
        while True:
            render_header()
            picked = select(
                [
                    Choice("wizard", "Setup wizard", GREEN, "1"),
                    Choice("cores", "Cores", RED, "2"),
                    Choice("service", "Service", CYAN, "3"),
                    Choice("status", "Check status", WHITE, "4"),
                    Choice("stats", "Stats", WHITE, "5"),
                    Choice("update", "Update agent", WHITE, "6"),
                    Choice("token", "Auth token", WHITE, "7"),
                    Choice("exit", "Exit", WHITE, "0"),
                ]
            )
            if picked in {None, "exit"}:
                clear_screen()
                _print(paint(logo(), CYAN))
                _print(paint("\n  Goodbye.\n", DIM))
                return 0
            if picked == "wizard":
                render_header("Setup wizard")
                _wizard()
                pause()
            elif picked == "cores":
                _cores_menu()
            elif picked == "service":
                _service_menu()
            elif picked == "status":
                _status()
            elif picked == "stats":
                _stats_menu()
            elif picked == "update":
                _update_menu()
            elif picked == "token":
                _token_menu()
    except KeyboardInterrupt:
        show_cursor()
        _print(paint("\n  Goodbye.\n", DIM))
        return 130
    finally:
        show_cursor()
