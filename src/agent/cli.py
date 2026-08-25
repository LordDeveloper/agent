from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agent import __version__
from agent.errors import AgentError
from agent.ops import (
    KNOWN_CORES,
    generate_token,
    install_core,
    service_action,
    set_env_value,
    which,
    write_env_file,
)
from agent.runtime import open_runtime
from agent.update import check_for_update, perform_update, resolve_token


def _print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _env_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env",
        dest="env_file",
        default=None,
        help="Path to .env (default: ENV_FILE / /etc/agent/.env / ./.env)",
    )


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from agent.main import create_app

    runtime = open_runtime(args.env_file)
    host, port = runtime.settings.listen_host_port()
    if args.host:
        host = args.host
    if args.port:
        port = args.port
    runtime.close()
    uvicorn.run(create_app(args.env_file), host=host, port=port, factory=False)
    return 0


def cmd_menu(_: argparse.Namespace) -> int:
    from agent.menu import run_interactive

    return run_interactive()


def cmd_version(_: argparse.Namespace) -> int:
    print(f"agent {__version__}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        cores = [c.model_dump() for c in runtime.registry.list_cores()]
        _print_json(
            {
                "success": True,
                "version": __version__,
                "listen": runtime.settings.listen,
                "db": str(runtime.settings.resolve_db_path()),
                "enabled_cores": runtime.settings.cores(),
                "cores": cores,
            }
        )
    finally:
        runtime.close()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        payload = {
            "success": True,
            "online": runtime.registry.online_users(args.core),
            "snapshot": runtime.registry.usage_snapshot(args.core).model_dump(by_alias=True),
        }
        if getattr(args, "online_traffic", False):
            payload = {"success": True, "users": runtime.registry.online_traffic(args.core)}
        elif args.online_only:
            payload = {"success": True, "users": payload["online"]}
        _print_json(payload)
    finally:
        runtime.close()
    return 0


def cmd_core_list(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        enabled = set(runtime.settings.cores())
        rows = []
        for key in KNOWN_CORES:
            if key in enabled:
                info = runtime.registry.get(key)
                rows.append(
                    {
                        "key": key,
                        "enabled": True,
                        "installed": info.installed(),
                        "running": info.running(),
                        "version": info.version(),
                        "capabilities": info.capabilities(),
                    }
                )
            else:
                rows.append({"key": key, "enabled": False})
        _print_json({"success": True, "cores": rows})
    finally:
        runtime.close()
    return 0


def cmd_core_install(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = install_core(
        args.name,
        force=bool(getattr(args, "force", False)),
        tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
    )
    _print_json({"success": True, **result})
    return 0


def cmd_xray_install(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = install_core(
        "xray",
        force=bool(getattr(args, "force", False)) or bool(tag),
        tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
    )
    _print_json({"success": True, **result})
    return 0


def cmd_xray_update(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = install_core(
        "xray",
        force=True,
        tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
    )
    _print_json({"success": True, **result})
    return 0


def cmd_xray_status(_: argparse.Namespace) -> int:
    from agent.xray_service import binary_has_httpapi

    binary = Path(os.environ.get("XRAY_BINARY", "/usr/local/bin/xray"))
    path = binary if binary.is_file() else Path(which("xray") or "")
    payload: dict = {
        "success": True,
        "core": "xray",
        "installed": path.is_file(),
        "binary": str(path) if path.is_file() else None,
        "httpapi_capable": bool(path.is_file() and binary_has_httpapi(path)),
        "version": None,
    }
    if path.is_file():
        try:
            from agent.ops import run_cmd

            proc = run_cmd([str(path), "version"], check=False, timeout=15)
            payload["version"] = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or None
        except OSError:
            pass
    _print_json(payload)
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    result = service_action(args.action)
    _print_json({"success": bool(result.get("ok", True)), **result})
    return 0 if result.get("ok", True) else 1


def cmd_wizard(args: argparse.Namespace) -> int:
    env_path = Path(args.env_path or "/etc/agent/.env")
    print("Agent setup wizard")
    print(f"Env file: {env_path}")

    listen = input("Listen [0.0.0.0:8443]: ").strip() or "0.0.0.0:8443"
    data_dir = input("Data dir [/var/lib/agent]: ").strip() or "/var/lib/agent"
    token_in = input("Auth token [auto-generate]: ").strip()
    token = token_in or generate_token()

    print("Available cores: xray, wireguard, amnezia")
    cores_in = input("Enable cores [xray]: ").strip() or "xray"
    cores = [c.strip() for c in cores_in.split(",") if c.strip()]
    unknown = [c for c in cores if c not in KNOWN_CORES]
    if unknown:
        print(f"Unknown cores: {', '.join(unknown)}", file=sys.stderr)
        return 2

    install_now = input("Install selected cores now? [y/N]: ").strip().lower() in {"y", "yes"}
    if install_now:
        for core in cores:
            print(f"Installing {core}...")
            try:
                result = install_core(core)
                print(f"  ok: {result.get('message')}")
            except AgentError as exc:
                print(f"  failed: {exc.message}", file=sys.stderr)

    write_env_file(env_path, listen=listen, token=token, data_dir=data_dir, cores=cores)
    print(f"Wrote {env_path}")
    print(f"Token: {token}")

    svc = input("Install/enable systemd service? [y/N]: ").strip().lower() in {"y", "yes"}
    if svc:
        try:
            service_action("install")
            service_action("restart")
            print("Service installed and restarted.")
        except AgentError as exc:
            print(f"Service setup failed: {exc.message}", file=sys.stderr)
            return 1

    print("Done. Start API with: agent serve")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    token = generate_token(int(args.bytes))
    written = None
    if args.write:
        env_path = Path(args.env_file or os.environ.get("ENV_FILE") or "/etc/agent/.env")
        written = set_env_value(env_path, "AUTH_TOKEN", token)
    if args.json:
        payload = {"success": True, "auth_token": token}
        if written:
            payload["env"] = written
            payload["hint"] = "restart service: agent service restart"
        _print_json(payload)
    else:
        print(token)
        if written:
            print(f"Wrote AUTH_TOKEN to {written['path']}", file=sys.stderr)
            print("Restart service to apply: agent service restart", file=sys.stderr)
    return 0


def cmd_tls_status(_: argparse.Namespace) -> int:
    from agent.tls import acme_installed, certbot_installed
    _print_json({
        'success': True,
        'acme_installed': acme_installed(),
        'certbot_installed': certbot_installed(),
    })
    return 0


def cmd_tls_install_acme(args: argparse.Namespace) -> int:
    from agent.tls import ensure_acme
    result = ensure_acme(email=args.email or '')
    _print_json({'success': True, **result})
    return 0


def cmd_tls_install_certbot(_: argparse.Namespace) -> int:
    from agent.tls import ensure_certbot
    result = ensure_certbot()
    _print_json({'success': True, **result})
    return 0


def cmd_tls_issue(args: argparse.Namespace) -> int:
    from agent.tls import issue_cert
    result = issue_cert(
        domain=args.domain,
        method=args.method,
        cf_token=args.cf_token,
        email=args.email or '',
        force=bool(args.force),
        tool=args.tool,
    )
    _print_json(result)
    return 0


def cmd_tls_renew(args: argparse.Namespace) -> int:
    from agent.tls import renew_cert
    result = renew_cert(domain=args.domain, force=bool(args.force), tool=args.tool)
    _print_json(result)
    return 0


def cmd_tls_list(_: argparse.Namespace) -> int:
    from agent.tls import list_certs
    _print_json({'success': True, 'certs': list_certs()})
    return 0


def cmd_tls_revoke(args: argparse.Namespace) -> int:
    from agent.tls import revoke_cert
    result = revoke_cert(domain=args.domain)
    _print_json(result)
    return 0


def cmd_bbr_status(_: argparse.Namespace) -> int:
    from agent.bbr import bbr_status
    _print_json({'success': True, **bbr_status()})
    return 0


def cmd_bbr_install(args: argparse.Namespace) -> int:
    from agent.bbr import bbr_install
    result = bbr_install(apply=bool(getattr(args, 'apply', False)))
    _print_json({'success': True, **result})
    return 0


def cmd_bbr_enable(_: argparse.Namespace) -> int:
    from agent.bbr import bbr_enable
    _print_json({'success': True, **bbr_enable()})
    return 0


def cmd_bbr_disable(args: argparse.Namespace) -> int:
    from agent.bbr import bbr_disable
    result = bbr_disable(remove_persistence=bool(getattr(args, 'remove_persistence', False)))
    _print_json({'success': True, **result})
    return 0


def cmd_dns_leak_status(_: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_status
    _print_json({'success': True, **dns_leak_status()})
    return 0


def cmd_dns_leak_apply(args: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_apply
    result = dns_leak_apply(
        interfaces=list(args.interface or []),
        block_ipv6=not bool(getattr(args, 'allow_ipv6', False)),
        with_dnsmasq=not bool(getattr(args, 'no_dnsmasq', False)),
        upstream_dns=list(args.upstream or []) or None,
    )
    _print_json({'success': bool(result.get('applied', True)), **result})
    return 0 if result.get('applied', True) else 1


def cmd_dns_leak_remove(_: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_remove
    _print_json({'success': True, **dns_leak_remove()})
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    # Prefer tokens already in the process env; otherwise load /etc/agent/.env.
    from dotenv import load_dotenv

    env_candidates = [
        args.env_file if getattr(args, "env_file", None) else None,
        os.environ.get("ENV_FILE"),
        "/etc/agent/.env",
        ".env",
    ]
    for candidate in env_candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file():
            load_dotenv(path, override=False)
            break

    token = args.token or resolve_token()
    if args.check:
        payload = check_for_update(repo=args.repo, token=token, asset_name=args.asset)
        _print_json({"success": True, **payload})
        return 0

    result = perform_update(
        repo=args.repo,
        token=token,
        asset_name=args.asset,
        force=bool(args.force),
        restart=not bool(args.no_restart),
    )
    _print_json({"success": True, **result})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="Netinja node agent CLI. Run without arguments for the interactive menu.",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="Run HTTP API server")
    _env_flag(p_serve)
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.set_defaults(func=cmd_serve)

    p_menu = sub.add_parser("menu", help="Interactive nested menu (arrow keys)")
    p_menu.set_defaults(func=cmd_menu)

    p_ver = sub.add_parser("version", help="Show version")
    p_ver.set_defaults(func=cmd_version)

    p_status = sub.add_parser("status", help="Show agent + cores status")
    _env_flag(p_status)
    p_status.set_defaults(func=cmd_status)

    p_stats = sub.add_parser("stats", help="Show usage snapshot / online users")
    _env_flag(p_stats)
    p_stats.add_argument("--core", default=None, help="Limit to one core (xray|wireguard|amnezia)")
    p_stats.add_argument("--online-only", action="store_true", help="Only print online users")
    p_stats.add_argument(
        "--online-traffic",
        action="store_true",
        help="Print uplink/downlink for currently online subscriptions",
    )
    p_stats.set_defaults(func=cmd_stats)

    p_core = sub.add_parser("core", help="Manage VPN cores")
    core_sub = p_core.add_subparsers(dest="core_command", required=True)

    p_core_list = core_sub.add_parser("list", help="List cores and capabilities")
    _env_flag(p_core_list)
    p_core_list.set_defaults(func=cmd_core_list)

    p_core_install = core_sub.add_parser("install", help="Install a core on this host")
    p_core_install.add_argument("name", choices=list(KNOWN_CORES))
    p_core_install.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if a customized binary is already present",
    )
    p_core_install.add_argument(
        "--tag",
        default=None,
        help="Xray release tag (e.g. v1.0.7). Default: latest. Ignored for other cores.",
    )
    p_core_install.set_defaults(func=cmd_core_install)

    p_xray = sub.add_parser("xray", help="Install / update Xray from LordDeveloper/xray Releases")
    xray_sub = p_xray.add_subparsers(dest="xray_command", required=True)

    p_xray_install = xray_sub.add_parser("install", help="Install Xray release zip for this host")
    p_xray_install.add_argument("--tag", default=None, help="Release tag (default: latest)")
    p_xray_install.add_argument("--force", action="store_true", help="Re-download even if present")
    p_xray_install.set_defaults(func=cmd_xray_install)

    p_xray_update = xray_sub.add_parser("update", help="Force reinstall latest (or --tag) Xray release")
    p_xray_update.add_argument("--tag", default=None, help="Release tag (default: latest)")
    p_xray_update.set_defaults(func=cmd_xray_update)

    p_xray_status = xray_sub.add_parser("status", help="Show installed Xray binary status")
    p_xray_status.set_defaults(func=cmd_xray_status)

    p_service = sub.add_parser("service", help="Manage systemd service")
    p_service.add_argument(
        "action",
        choices=["install", "uninstall", "start", "stop", "restart", "status", "enable", "disable"],
    )
    p_service.set_defaults(func=cmd_service)

    p_wizard = sub.add_parser("wizard", help="Interactive setup (.env + optional cores/service)")
    p_wizard.add_argument("--env-path", default="/etc/agent/.env")
    p_wizard.set_defaults(func=cmd_wizard)

    p_token = sub.add_parser("token", help="Generate AUTH_TOKEN (optionally write to .env)")
    p_token.add_argument(
        "--bytes",
        type=int,
        default=32,
        help="Random bytes before hex encoding (default: 32 → 64 hex chars)",
    )
    p_token.add_argument(
        "--write",
        action="store_true",
        help="Write AUTH_TOKEN into env file (default path: /etc/agent/.env)",
    )
    p_token.add_argument(
        "--env",
        dest="env_file",
        default=None,
        help="Env file path when using --write (default: ENV_FILE or /etc/agent/.env)",
    )
    p_token.add_argument("--json", action="store_true", help="Print JSON instead of bare token")
    p_token.set_defaults(func=cmd_token)

    p_tls = sub.add_parser("tls", help="TLS certificate management (acme.sh & certbot)")
    tls_sub = p_tls.add_subparsers(dest="tls_command", required=True)

    p_tls_status = tls_sub.add_parser("status", help="Show acme.sh / certbot install status")
    p_tls_status.set_defaults(func=cmd_tls_status)

    p_tls_install_acme = tls_sub.add_parser("install-acme", help="Install acme.sh")
    p_tls_install_acme.add_argument("--email", default="", help="Account email for Let's Encrypt")
    p_tls_install_acme.set_defaults(func=cmd_tls_install_acme)

    p_tls_install_certbot = tls_sub.add_parser("install-certbot", help="Install certbot")
    p_tls_install_certbot.set_defaults(func=cmd_tls_install_certbot)

    p_tls_issue = tls_sub.add_parser("issue", help="Issue a TLS certificate")
    p_tls_issue.add_argument("domain", help="Domain name")
    p_tls_issue.add_argument("--method", default="standalone", choices=["standalone", "dns_cloudflare"])
    p_tls_issue.add_argument("--tool", default="acme", choices=["acme", "certbot"])
    p_tls_issue.add_argument("--cf-token", default=None, dest="cf_token", help="Cloudflare API token")
    p_tls_issue.add_argument("--email", default="", help="Email for registration")
    p_tls_issue.add_argument("--force", action="store_true")
    p_tls_issue.set_defaults(func=cmd_tls_issue)

    p_tls_renew = tls_sub.add_parser("renew", help="Renew a TLS certificate")
    p_tls_renew.add_argument("domain", help="Domain name")
    p_tls_renew.add_argument("--tool", default="acme", choices=["acme", "certbot"])
    p_tls_renew.add_argument("--force", action="store_true")
    p_tls_renew.set_defaults(func=cmd_tls_renew)

    p_tls_list = tls_sub.add_parser("list", help="List issued certificates")
    p_tls_list.set_defaults(func=cmd_tls_list)

    p_tls_revoke = tls_sub.add_parser("revoke", help="Revoke a certificate")
    p_tls_revoke.add_argument("domain", help="Domain name")
    p_tls_revoke.set_defaults(func=cmd_tls_revoke)

    p_bbr = sub.add_parser("bbr", help="BBR congestion-control management")
    bbr_sub = p_bbr.add_subparsers(dest="bbr_command", required=True)

    p_bbr_status = bbr_sub.add_parser("status", help="Show BBR support and active settings")
    p_bbr_status.set_defaults(func=cmd_bbr_status)

    p_bbr_install = bbr_sub.add_parser("install", help="Load tcp_bbr module and persist sysctl drop-in")
    p_bbr_install.add_argument(
        "--apply",
        action="store_true",
        help="Apply BBR sysctl settings immediately after install",
    )
    p_bbr_install.set_defaults(func=cmd_bbr_install)

    p_bbr_enable = bbr_sub.add_parser("enable", help="Enable BBR (install prerequisites if needed)")
    p_bbr_enable.set_defaults(func=cmd_bbr_enable)

    p_bbr_disable = bbr_sub.add_parser("disable", help="Revert to cubic/pfifo_fast")
    p_bbr_disable.add_argument(
        "--remove-persistence",
        action="store_true",
        help="Also remove module-load and sysctl drop-ins",
    )
    p_bbr_disable.set_defaults(func=cmd_bbr_disable)

    p_dns_leak = sub.add_parser("dns-leak", help="Prevent DNS leaks for VPN client subnets")
    dns_sub = p_dns_leak.add_subparsers(dest="dns_leak_command", required=True)

    p_dns_status = dns_sub.add_parser("status", help="Show DNS leak protection status")
    p_dns_status.set_defaults(func=cmd_dns_leak_status)

    p_dns_apply = dns_sub.add_parser("apply", help="Apply DNS redirect + IPv6 leak blocks")
    p_dns_apply.add_argument(
        "--interface",
        action="append",
        default=[],
        help="VPN interface to protect (repeatable; auto-detect WireGuard/Amnezia when omitted)",
    )
    p_dns_apply.add_argument(
        "--allow-ipv6",
        action="store_true",
        help="Do not block IPv6 on VPN interfaces",
    )
    p_dns_apply.add_argument(
        "--no-dnsmasq",
        action="store_true",
        help="Skip dnsmasq resolver setup",
    )
    p_dns_apply.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="Upstream DNS for dnsmasq (repeatable; default: 1.1.1.1 and 8.8.8.8)",
    )
    p_dns_apply.set_defaults(func=cmd_dns_leak_apply)

    p_dns_remove = dns_sub.add_parser("remove", help="Remove DNS leak protection rules")
    p_dns_remove.set_defaults(func=cmd_dns_leak_remove)

    p_update = sub.add_parser("update", help="Update agent binary from GitHub Releases")
    _env_flag(p_update)
    p_update.add_argument("--check", action="store_true", help="Only check for a newer release")
    p_update.add_argument("--force", action="store_true", help="Reinstall latest even if versions match")
    p_update.add_argument("--no-restart", action="store_true", help="Do not restart systemd service")
    p_update.add_argument("--repo", default=None, help="owner/name (default: AGENT_GITHUB_REPO or LordDeveloper/agent)")
    p_update.add_argument("--asset", default=None, help="Release asset name (default: agent-linux-amd64)")
    p_update.add_argument(
        "--token",
        default=None,
        help="GitHub token (default: AGENT_GITHUB_TOKEN / GITHUB_TOKEN / GH_TOKEN)",
    )
    p_update.set_defaults(func=cmd_update)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False) and not getattr(args, "command", None):
        return cmd_version(args)

    if not getattr(args, "command", None):
        from agent.menu import run_interactive
        from agent.tui import is_interactive

        if is_interactive():
            return run_interactive()
        parser.print_help()
        return 0

    try:
        return int(args.func(args))
    except AgentError as exc:
        _print_json({"success": False, "error": {"code": exc.code, "message": exc.message}})
        return 1
    except KeyboardInterrupt:
        return 130


def run() -> None:
    raise SystemExit(main())
