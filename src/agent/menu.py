from __future__ import annotations

import shutil
import sys
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import httpx

from agent import __version__
from agent.errors import AgentError
from agent.ops import (
    KNOWN_CORES,
    generate_token,
    install_core,
    run_cmd,
    service_action,
    service_is_active,
    service_logs,
    which,
    write_env_file,
)
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


def _print_block(text: str, *, max_lines: int = 20, color: str = WHITE) -> None:
    lines = [line.rstrip() for line in str(text).splitlines() if line.strip()]
    for line in lines[:max_lines]:
        _print(paint(f"  {line}", color))


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
        if service_is_active():
            return "Running", GREEN
        return "Stopped", RED
    except AgentError:
        return "Unavailable", YELLOW


def _core_installed(name: str) -> bool:
    if name == "xray":
        return Path("/usr/local/bin/xray").is_file() or which("xray") is not None
    if name == "wireguard":
        return which("wg") is not None
    return which("awg") is not None


def _enabled_cores() -> set[str]:
    try:
        from agent.config import load_settings

        return set(load_settings().cores())
    except Exception:
        return set()


def _core_state(name: str) -> tuple[str, str]:
    enabled = name in _enabled_cores()
    installed = _core_installed(name)
    if enabled and installed:
        return "Enabled", GREEN
    if enabled:
        return "Enabled (missing binary)", YELLOW
    if installed:
        return "Installed (disabled)", YELLOW
    return "Disabled", DIM


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


def _show_agent_status() -> None:
    from agent.runtime import open_runtime

    runtime = open_runtime()
    try:
        enabled = ", ".join(runtime.settings.cores()) or "-"
        _print(kv("Listen", runtime.settings.listen, CYAN))
        _print(kv("Enabled cores", enabled, GREEN))
        _print()
        for info in runtime.registry.list_cores():
            bits = [
                "installed" if info.installed else "missing",
                "running" if info.running else "stopped",
            ]
            version = info.version or "-"
            color = GREEN if info.running else YELLOW
            _print(paint(f"  {info.label:<12} {version}  ({', '.join(bits)})", color))
    finally:
        runtime.close()


def _show_core_list() -> None:
    _show_agent_status()


def _show_service_action(action: str) -> None:
    if action == "status":
        active = service_is_active()
        _print(kv("Active", "running" if active else "stopped", GREEN if active else RED))
        logs = service_logs(12)
        if logs:
            _print()
            _print(paint("  Recent logs:", DIM))
            for line in logs:
                _print(paint(f"  {line}", WHITE))
        return

    result = service_action(action)
    ok = bool(result.get("ok", True))
    _print(kv("Result", "ok" if ok else "failed", GREEN if ok else RED))
    if result.get("unit"):
        _print(kv("Unit", str(result["unit"]), CYAN))
    if result.get("stdout"):
        _print()
        _print_block(str(result["stdout"]), max_lines=16)
    if result.get("stderr"):
        _print()
        _print_block(str(result["stderr"]), max_lines=8, color=RED)


def _show_install(name: str, *, force: bool = False, tag: str | None = None) -> None:
    result = install_core(name, force=force, tag=tag)
    _print(kv("Core", str(result.get("core") or name), CYAN))
    _print(kv("Installed", "yes" if result.get("installed") else "no", GREEN))
    if result.get("release_tag") or result.get("tag"):
        _print(kv("Release", str(result.get("release_tag") or result.get("tag")), CYAN))
    if result.get("asset"):
        _print(kv("Asset", str(result["asset"]), DIM))
    if result.get("version"):
        _print(kv("Version", str(result["version"]), WHITE))
    if result.get("message"):
        _print(kv("Message", str(result["message"]), WHITE))
    if result.get("binary"):
        _print(kv("Binary", str(result["binary"]), DIM))


def _show_xray_status() -> None:
    from agent.xray_service import binary_has_httpapi

    binary = Path(os.environ.get("XRAY_BINARY", "/usr/local/bin/xray"))
    path = binary if binary.is_file() else Path(which("xray") or "")
    if not path.is_file():
        _print(paint("  Xray binary not installed.", YELLOW))
        return

    _print(kv("Binary", str(path), CYAN))
    capable = binary_has_httpapi(path)
    _print(kv("HTTP API", "yes" if capable else "no", GREEN if capable else RED))
    try:
        proc = run_cmd([str(path), "version"], check=False, timeout=15)
        version = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or "-"
    except OSError:
        version = "-"
    _print(kv("Version", version, WHITE))


def _xray_menu() -> None:
    while True:
        render_header("Xray")
        picked = select(
            [
                Choice("latest", "Install / update latest release", GREEN, "1"),
                Choice("tag", "Install custom tag", CYAN, "2"),
                Choice("status", "Show binary status", WHITE, "3"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "status":
            _run_action("Xray status", _show_xray_status)
            continue
        if picked == "latest":
            if not confirm("Download latest LordDeveloper/xray release for this host?", default=True):
                continue
            _run_action(
                "Install Xray (latest)",
                lambda: _show_install("xray", force=True),
            )
            continue

        tag = prompt_text("Release tag (e.g. v1.0.7)", default="")
        tag = (tag or "").strip()
        if not tag:
            _print(paint("  Tag is required.", YELLOW))
            pause()
            continue
        if not confirm(f"Install Xray release [{tag}]?", default=True):
            continue
        _run_action(
            f"Install Xray ({tag})",
            lambda t=tag: _show_install("xray", force=True, tag=t),
        )


def _cores_menu() -> None:
    while True:
        render_header("Cores")
        picked = select(
            [
                Choice("list", "List cores", CYAN, "1"),
                Choice("xray", "Xray", GREEN, "2"),
                Choice("wireguard", "Install WireGuard", GREEN, "3"),
                Choice("amnezia", "Install Amnezia", GREEN, "4"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "list":
            _run_action("Core list", _show_core_list)
            continue
        if picked == "xray":
            _xray_menu()
            continue
        if not confirm(f"Install {picked} on this host?", default=True):
            continue
        _run_action(f"Install {picked}", lambda name=picked: _show_install(name))


def _show_stats(*, online_only: bool) -> None:
    from agent.runtime import open_runtime

    runtime = open_runtime()
    try:
        if online_only:
            users = runtime.registry.online_traffic()
            _print(kv("Online", str(len(users)), GREEN))
            _print()
            if not users:
                _print(paint("  No online users.", DIM))
                return
            for email, traffic in sorted(users.items()):
                up = int(traffic.get("uplink") or 0)
                down = int(traffic.get("downlink") or 0)
                sessions = traffic.get("sessions")
                line = f"  • {email}  up={up}  down={down}"
                if sessions is not None:
                    line += f"  sessions={sessions}"
                _print(paint(line, WHITE))
            return

        snapshot = runtime.registry.usage_snapshot()
        if not snapshot.inbounds:
            _print(paint("  No usage data.", DIM))
            return
        for inbound in snapshot.inbounds:
            _print(paint(f"  {inbound.tag}  in={inbound.incoming}  out={inbound.outgoing}", CYAN))
            for client in inbound.clients:
                label = client.email or client.id or "-"
                _print(paint(f"    {label}  in={client.incoming}  out={client.outgoing}", WHITE))
    finally:
        runtime.close()


def _show_update(*, check: bool, force: bool) -> None:
    from agent.update import check_for_update, perform_update

    if check:
        payload = check_for_update()
        _print(kv("Current", f"v{payload.get('current_version')}", CYAN))
        _print(kv("Latest", f"v{payload.get('latest_version')}", GREEN))
        if payload.get("update_available"):
            _print(paint("  A newer release is available.", YELLOW))
        else:
            _print(paint("  Already up to date.", GREEN))
        return

    payload = perform_update(force=force, restart=True)
    _print(kv("Current", f"v{payload.get('previous_version') or payload.get('current_version')}", CYAN))
    _print(kv("Latest", f"v{payload.get('installed_version') or payload.get('latest_version')}", GREEN))
    if payload.get("updated"):
        _print(paint("  Agent binary updated.", GREEN))
    else:
        _print(paint(f"  {payload.get('message') or 'Already up to date.'}", GREEN))


def _show_token(*, write: bool) -> None:
    from agent.ops import set_env_value

    token = generate_token()
    _print(kv("Token", token, YELLOW))
    if not write:
        return
    env_path = Path("/etc/agent/.env")
    written = set_env_value(env_path, "AUTH_TOKEN", token)
    _print(kv("Wrote", str(written.get("path") or env_path), GREEN))
    _print(paint("  Restart service to apply: Service → Restart", DIM))


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
        _run_action(f"Service {picked}", lambda action=picked: _show_service_action(action))


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
        _run_action(
            "Online users" if picked == "online" else "Usage snapshot",
            lambda online=picked == "online": _show_stats(online_only=online),
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
        if picked != "check" and not confirm("Download and install the latest agent release?", default=True):
            continue
        _run_action(
            "Update agent",
            lambda check=picked == "check", force=picked == "force": _show_update(check=check, force=force),
        )


def _tls_menu() -> None:
    while True:
        render_header("TLS Certificates")
        picked = select(
            [
                Choice("status", "Status", CYAN, "1"),
                Choice("install_acme", "Install acme.sh", GREEN, "2"),
                Choice("install_certbot", "Install certbot", GREEN, "3"),
                Choice("issue", "Issue certificate", YELLOW, "4"),
                Choice("renew", "Renew certificate", YELLOW, "5"),
                Choice("list", "List certificates", WHITE, "6"),
                Choice("revoke", "Revoke certificate", RED, "7"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "status":
            _run_action("TLS Status", _show_tls_status)
        elif picked == "install_acme":
            _run_action("Install acme.sh", _show_tls_install_acme)
        elif picked == "install_certbot":
            _run_action("Install certbot", _show_tls_install_certbot)
        elif picked == "issue":
            _tls_issue_flow()
        elif picked == "renew":
            _tls_renew_flow()
        elif picked == "list":
            _run_action("Certificates", _show_tls_list)
        elif picked == "revoke":
            _tls_revoke_flow()


def _show_tls_status() -> None:
    from agent.tls import acme_installed, certbot_installed
    _print(kv("acme.sh", "installed" if acme_installed() else "not installed", GREEN if acme_installed() else RED))
    _print(kv("certbot", "installed" if certbot_installed() else "not installed", GREEN if certbot_installed() else RED))


def _show_tls_install_acme() -> None:
    from agent.tls import ensure_acme
    email = prompt_text("Email (optional)", "")
    result = ensure_acme(email=email)
    _print(kv("Path", str(result.get('path', '-')), GREEN))
    _print(kv("Downloaded", "yes" if result.get('downloaded') else "already present", CYAN))


def _show_tls_install_certbot() -> None:
    from agent.tls import ensure_certbot
    result = ensure_certbot()
    _print(kv("Path", str(result.get('path', '-')), GREEN))
    _print(kv("Downloaded", "yes" if result.get('downloaded') else "already present", CYAN))


def _tls_issue_flow() -> None:
    render_header("Issue TLS Certificate")
    domain = prompt_text("Domain", "")
    if not domain:
        _print(paint("  Domain is required.", RED))
        pause()
        return

    tool = select(
        [
            Choice("acme", "acme.sh", CYAN, "1"),
            Choice("certbot", "certbot", GREEN, "2"),
        ]
    ) or "acme"

    method = select(
        [
            Choice("standalone", "Standalone (port 80)", CYAN, "1"),
            Choice("dns_cloudflare", "DNS Cloudflare", GREEN, "2"),
        ]
    ) or "standalone"

    cf_token = None
    if method == "dns_cloudflare":
        cf_token = prompt_text("Cloudflare API Token", "")

    force = confirm("Force re-issue?", default=False)

    def _do():
        from agent.tls import issue_cert
        result = issue_cert(domain=domain, method=method, cf_token=cf_token, force=force, tool=tool)
        _print(kv("Domain", result.get('domain', '-'), CYAN))
        _print(kv("Tool", result.get('tool', '-'), WHITE))
        _print(kv("Issued", "yes" if result.get('issued') else "cached", GREEN))
        _print(kv("Cert", result.get('cert_file', '-'), DIM))
        _print(kv("Key", result.get('key_file', '-'), DIM))

    _run_action("Issue certificate", _do)


def _tls_renew_flow() -> None:
    render_header("Renew TLS Certificate")
    domain = prompt_text("Domain", "")
    if not domain:
        _print(paint("  Domain is required.", RED))
        pause()
        return

    tool = select(
        [
            Choice("acme", "acme.sh", CYAN, "1"),
            Choice("certbot", "certbot", GREEN, "2"),
        ]
    ) or "acme"

    force = confirm("Force renewal?", default=False)

    def _do():
        from agent.tls import renew_cert
        result = renew_cert(domain=domain, force=force, tool=tool)
        _print(kv("Domain", result.get('domain', '-'), CYAN))
        _print(kv("Renewed", "yes" if result.get('renewed') else "no", GREEN))

    _run_action("Renew certificate", _do)


def _show_tls_list() -> None:
    from agent.tls import list_certs
    certs = list_certs()
    if not certs:
        _print(paint("  No certificates found.", DIM))
        return
    for cert in certs:
        _print(paint(f"  {cert['domain']}", CYAN))
        _print(paint(f"    cert: {cert['cert_file']}", DIM))
        if cert.get('modified_at'):
            _print(paint(f"    modified: {cert['modified_at']}", DIM))


def _tls_revoke_flow() -> None:
    render_header("Revoke TLS Certificate")
    domain = prompt_text("Domain", "")
    if not domain:
        _print(paint("  Domain is required.", RED))
        pause()
        return
    if not confirm(f"Revoke certificate for {domain}?", default=False):
        return

    def _do():
        from agent.tls import revoke_cert
        result = revoke_cert(domain=domain)
        _print(kv("Revoked", "yes" if result.get('revoked') else "no", GREEN if result.get('revoked') else RED))
        _print(kv("Files removed", "yes" if result.get('removed') else "no", DIM))

    _run_action("Revoke certificate", _do)


def _bbr_menu() -> None:
    while True:
        render_header("BBR")
        picked = select(
            [
                Choice("status", "Status", CYAN, "1"),
                Choice("install", "Install (module + sysctl)", GREEN, "2"),
                Choice("enable", "Enable BBR", GREEN, "3"),
                Choice("disable", "Disable BBR", YELLOW, "4"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "status":
            _run_action("BBR Status", _show_bbr_status)
        elif picked == "install":
            apply = confirm("Apply BBR settings immediately after install?", default=True)
            _run_action("Install BBR", lambda: _show_bbr_install(apply=apply))
        elif picked == "enable":
            if confirm("Enable BBR on this host?", default=True):
                _run_action("Enable BBR", _show_bbr_enable)
        elif picked == "disable":
            remove = confirm("Remove persisted sysctl/module files?", default=False)
            if confirm("Disable BBR and revert to cubic?", default=True):
                _run_action("Disable BBR", lambda: _show_bbr_disable(remove_persistence=remove))


def _show_bbr_status() -> None:
    from agent.bbr import bbr_status

    payload = bbr_status()
    supported = bool(payload.get("supported"))
    enabled = bool(payload.get("enabled"))
    _print(kv("Supported", "yes" if supported else "no", GREEN if supported else RED))
    _print(kv("Enabled", "yes" if enabled else "no", GREEN if enabled else YELLOW))
    _print(kv("Module loaded", "yes" if payload.get("module_loaded") else "no", CYAN))
    current = payload.get("current") or {}
    _print(kv("Congestion control", str(current.get("tcp_congestion_control") or "-"), WHITE))
    _print(kv("Default qdisc", str(current.get("default_qdisc") or "-"), WHITE))


def _show_bbr_install(*, apply: bool) -> None:
    from agent.bbr import bbr_install

    result = bbr_install(apply=apply)
    _print(kv("Installed", "yes", GREEN))
    if result.get("applied"):
        _print(kv("Applied", "yes", GREEN))
    module = result.get("module") or {}
    _print(kv("Module loaded", "yes" if module.get("loaded") else "no", CYAN))


def _show_bbr_enable() -> None:
    from agent.bbr import bbr_enable

    result = bbr_enable()
    _print(kv("Enabled", "yes" if result.get("enabled") else "no", GREEN if result.get("enabled") else YELLOW))


def _show_bbr_disable(*, remove_persistence: bool) -> None:
    from agent.bbr import bbr_disable

    result = bbr_disable(remove_persistence=remove_persistence)
    _print(kv("Enabled", "yes" if result.get("enabled") else "no", GREEN if result.get("enabled") else YELLOW))
    _print(kv("Congestion control", str(result.get("tcp_congestion_control") or "-"), WHITE))


def _dns_leak_menu() -> None:
    while True:
        render_header("DNS leak & ads blocker")
        picked = select(
            [
                Choice("dns_status", "DNS leak — status", CYAN, "1"),
                Choice("dns_apply", "DNS leak — apply", GREEN, "2"),
                Choice("dns_remove", "DNS leak — remove", RED, "3"),
                Choice("ads_prereq", "Ads blocker — prerequisites", CYAN, "4"),
                Choice("ads_install", "Ads blocker — install packages", GREEN, "5"),
                Choice("ads_status", "Ads blocker — status", CYAN, "6"),
                Choice("ads_enable", "Ads blocker — enable", GREEN, "7"),
                Choice("ads_repair", "Ads blocker — start dnsmasq", YELLOW, "8"),
                Choice("ads_disable", "Ads blocker — disable", RED, "9"),
                Choice("ads_test", "Ads blocker — test query", YELLOW, "10"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        if picked == "dns_status":
            _run_action("DNS leak status", _show_dns_leak_status)
        elif picked == "dns_apply":
            if confirm("Apply DNS leak protection for VPN interfaces?", default=True):
                _run_action("Apply DNS leak protection", _show_dns_leak_apply)
        elif picked == "dns_remove":
            if confirm("Remove DNS leak protection rules?", default=False):
                _run_action("Remove DNS leak protection", _show_dns_leak_remove)
        elif picked == "ads_prereq":
            _run_action("Ads blocker prerequisites", _show_ads_block_prerequisites)
        elif picked == "ads_install":
            if confirm("Install dnsmasq and dnsutils (apt)?", default=True):
                _run_action("Install ads blocker prerequisites", _show_ads_block_install)
        elif picked == "ads_status":
            _run_action("Ads blocker status", _show_ads_block_status)
        elif picked == "ads_enable":
            if confirm("Enable ads DNS filter for WireGuard/Amnezia clients?", default=True):
                _run_action("Enable ads blocker", _show_ads_block_enable)
        elif picked == "ads_repair":
            if confirm("Start dnsmasq and fix port-53 conflicts?", default=True):
                _run_action("Repair ads blocker dnsmasq", _show_ads_block_repair)
        elif picked == "ads_disable":
            if confirm("Disable ads DNS filter?", default=False):
                _run_action("Disable ads blocker", _show_ads_block_disable)
        elif picked == "ads_test":
            domain = prompt_text("Domain to test", default="doubleclick.net")
            if str(domain or "").strip():
                _run_action(
                    "Ads blocker test",
                    lambda host=str(domain).strip(): _show_ads_block_test(host),
                )


def _show_dns_leak_status() -> None:
    from agent.dns_leak import dns_leak_status

    payload = dns_leak_status()
    active = bool(payload.get("active"))
    _print(kv("Active", "yes" if active else "no", GREEN if active else YELLOW))
    _print(kv("Backend", str(payload.get("backend") or "-"), CYAN))
    interfaces = payload.get("interfaces") or []
    _print(kv("VPN interfaces", str(len(interfaces)), WHITE))
    for row in interfaces:
        _print(paint(f"  • {row.get('name')}  gateway={row.get('gateway')}", DIM))


def _show_dns_leak_apply() -> None:
    from agent.dns_leak import dns_leak_apply

    result = dns_leak_apply()
    _print(kv("Applied", "yes" if result.get("applied") else "no", GREEN if result.get("applied") else RED))
    _print(kv("Backend", str(result.get("backend") or "-"), CYAN))
    for row in result.get("interfaces") or []:
        _print(paint(f"  • {row.get('name')}  gateway={row.get('gateway')}", WHITE))


def _show_dns_leak_remove() -> None:
    from agent.dns_leak import dns_leak_remove

    result = dns_leak_remove()
    _print(kv("Removed", "yes" if result.get("removed") else "no", GREEN))


def _show_ads_block_prerequisites() -> None:
    from agent.ads_block import ads_block_prerequisites

    payload = ads_block_prerequisites()
    _print(kv("Linux", "yes" if payload.get("linux") else "no", GREEN if payload.get("linux") else RED))
    _print(kv("Root", "yes" if payload.get("root") else "no", GREEN if payload.get("root") else YELLOW))
    _print(kv("dnsmasq installed", "yes" if payload.get("dnsmasq_installed") else "no", GREEN if payload.get("dnsmasq_installed") else RED))
    _print(kv("dnsmasq active", "yes" if payload.get("dnsmasq_active") else "no", GREEN if payload.get("dnsmasq_active") else YELLOW))
    _print(kv("Firewall backend", str(payload.get("firewall_backend") or "-"), CYAN))
    _print(kv("VPN resolver drop-in", "yes" if payload.get("dnsmasq_dropin") else "no", GREEN if payload.get("dnsmasq_dropin") else YELLOW))
    _print(kv("Ads drop-in", "yes" if payload.get("ads_dropin") else "no", GREEN if payload.get("ads_dropin") else YELLOW))
    _print(kv("VPN interfaces", str(payload.get("vpn_interface_count") or 0), WHITE))
    _print(kv("Ready", "yes" if payload.get("ready") else "no", GREEN if payload.get("ready") else RED))
    error = str(payload.get("dnsmasq_error") or "").strip()
    if error:
        _print(paint("  dnsmasq: " + error.splitlines()[0], RED))


def _show_ads_block_repair() -> None:
    from agent.ads_block import ads_block_repair_service

    result = ads_block_repair_service()
    service = result.get("service") or {}
    _print(kv("dnsmasq active", "yes" if result.get("dnsmasq_active") else "no", GREEN if result.get("dnsmasq_active") else RED))
    actions = service.get("actions") or []
    if actions:
        _print(kv("Actions", ", ".join(str(item) for item in actions), CYAN))
    _print(kv("Ready", "yes" if result.get("ready") else "no", GREEN if result.get("ready") else RED))


def _show_ads_block_install() -> None:
    from agent.ads_block import ads_block_install_prerequisites

    result = ads_block_install_prerequisites()
    installed = result.get("installed") or []
    _print(kv("Installed", ", ".join(installed) if installed else "already present", GREEN))
    _print(kv("dnsmasq active", "yes" if result.get("dnsmasq_active") else "no", GREEN if result.get("dnsmasq_active") else YELLOW))
    _print(kv("Ready", "yes" if result.get("ready") else "no", GREEN if result.get("ready") else RED))


def _show_ads_block_status() -> None:
    from agent.ads_block import ads_block_status

    payload = ads_block_status()
    enabled = bool(payload.get("enabled"))
    _print(kv("Enabled", "yes" if enabled else "no", GREEN if enabled else YELLOW))
    _print(kv("Blocked domains", str(payload.get("domains") or 0), WHITE))
    _print(kv("Client DNS", str(payload.get("dns") or "-"), CYAN))
    _print(kv("dnsmasq", "yes" if payload.get("dnsmasq") else "no", GREEN if payload.get("dnsmasq") else RED))
    _print(kv("dnsmasq active", "yes" if payload.get("dnsmasq_active") else "no", GREEN if payload.get("dnsmasq_active") else YELLOW))
    _print(kv("VPN resolver drop-in", "yes" if payload.get("dnsmasq_dropin") else "no", GREEN if payload.get("dnsmasq_dropin") else YELLOW))
    _print(kv("Ready", "yes" if payload.get("ready") else "no", GREEN if payload.get("ready") else RED))
    for row in payload.get("dns_candidates") or []:
        _print(paint(f"  • candidate DNS {row}", DIM))


def _show_ads_block_enable() -> None:
    from agent.ads_block import ads_block_ensure

    result = ads_block_ensure()
    _print(kv("Enabled", "yes" if result.get("enabled") else "no", GREEN if result.get("enabled") else YELLOW))
    _print(kv("Domains", str(result.get("domains") or 0), WHITE))
    _print(kv("Client DNS", str(result.get("dns") or "-"), CYAN))
    resolver = result.get("resolver") or {}
    if resolver:
        listen = ((resolver.get("resolver") or {}).get("listen_addresses") or [])
        if listen:
            _print(kv("Resolver listen", ", ".join(str(item) for item in listen), WHITE))


def _show_ads_block_disable() -> None:
    from agent.ads_block import ads_block_disable

    result = ads_block_disable()
    _print(kv("Removed", "yes" if result.get("removed") else "no", GREEN))


def _show_ads_block_test(domain: str) -> None:
    from agent.ads_block import ads_block_test

    result = ads_block_test(domain)
    blocked = bool(result.get("blocked"))
    _print(kv("Domain", str(result.get("domain") or domain), WHITE))
    _print(kv("DNS", str(result.get("dns") or "-"), CYAN))
    _print(kv("Answer", str(result.get("answer") or "-"), WHITE))
    _print(kv("Blocked", "yes" if blocked else "no", GREEN if blocked else RED))


def _peer_diagnose_menu() -> None:
    while True:
        render_header("Peer diagnose")
        picked = select(
            [
                Choice("wireguard", "WireGuard peer", CYAN, "1"),
                Choice("amnezia", "Amnezia peer", BLUE, "2"),
                Choice("back", "Back", WHITE, "0"),
            ]
        )
        if picked in {None, "back"}:
            return
        address = prompt_text("Peer address (e.g. 10.80.0.5)")
        if not str(address or "").strip():
            continue
        core = "amnezia" if picked == "amnezia" else "wireguard"
        _run_action(
            f"Diagnose {core} peer",
            lambda addr=str(address).strip(), selected_core=core: _show_peer_diagnose(selected_core, addr),
        )


def _show_peer_diagnose(core: str, address: str) -> None:
    from agent.cli import cmd_peer_diagnose

    code = cmd_peer_diagnose(SimpleNamespace(env_file=None, core=core, address=address))
    if code == 0:
        _print(paint("  healthy: yes", GREEN))
    elif code == 2:
        _print(paint("  peer not found", YELLOW))
    else:
        _print(paint("  issues detected — see JSON above", RED))


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
        _run_action(
            "Auth token",
            lambda write=picked == "write": _show_token(write=write),
        )


def _status() -> None:
    _run_action("Status", _show_agent_status)


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
                    Choice("tls", "TLS Certificates", YELLOW, "4"),
                    Choice("bbr", "BBR", MAGENTA, "5"),
                    Choice("dns_leak", "DNS leak & ads blocker", MAGENTA, "6"),
                    Choice("peer_diagnose", "Peer diagnose", CYAN, "7"),
                    Choice("status", "Check status", WHITE, "8"),
                    Choice("stats", "Stats", WHITE, "9"),
                    Choice("update", "Update agent", WHITE, "10"),
                    Choice("token", "Auth token", WHITE, "11"),
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
            elif picked == "tls":
                _tls_menu()
            elif picked == "bbr":
                _bbr_menu()
            elif picked == "dns_leak":
                _dns_leak_menu()
            elif picked == "peer_diagnose":
                _peer_diagnose_menu()
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
