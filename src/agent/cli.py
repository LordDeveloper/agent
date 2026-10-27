from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agent import __version__
from agent.asyncutil import run_sync
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


def _emit_diagnose_report(report: dict, args: argparse.Namespace) -> None:
    if getattr(args, 'json', False):
        _print_json(report)
        return
    from agent.support.diagnose_format import print_diagnose_report

    print_diagnose_report(report)


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
    run_sync(runtime.close())
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
        cores = [c.model_dump() for c in run_sync(runtime.registry.list_cores())]
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
        run_sync(runtime.close())
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        payload = {
            "success": True,
            "online": run_sync(runtime.registry.online_users(args.core)),
            "snapshot": run_sync(runtime.registry.usage_snapshot(args.core)).model_dump(by_alias=True),
        }
        if getattr(args, "online_traffic", False):
            payload = {"success": True, "users": run_sync(runtime.registry.online_traffic(args.core))}
        elif args.online_only:
            payload = {"success": True, "users": payload["online"]}
        _print_json(payload)
    finally:
        run_sync(runtime.close())
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
                        "running": run_sync(info.running()),
                        "version": run_sync(info.version()),
                        "capabilities": info.capabilities(),
                    }
                )
            else:
                rows.append({"key": key, "enabled": False})
        _print_json({"success": True, "cores": rows})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_core_reset(args: argparse.Namespace) -> int:
    from agent.factory_reset import confirmation_accepted

    if args.name != "openvpn":
        _print_json({"success": False, "error": {"code": "VALIDATION_ERROR", "message": "Only openvpn reset is supported"}})
        return 2
    if not bool(getattr(args, "yes", False)):
        print(
            "This stops OpenVPN units and deletes servers, PKI, and /etc/openvpn/server "
            "so the panel can sync from scratch.\nType CONFIRM to continue."
        )
        try:
            typed = input("Type CONFIRM to wipe OpenVPN: ")
        except EOFError:
            typed = ""
        if not confirmation_accepted(typed):
            print("Reset cancelled.")
            return 1

    runtime = open_runtime(args.env_file)
    try:
        driver = runtime.registry.get("openvpn", require_enabled=False)
        result = run_sync(driver.reset_runtime())
    finally:
        run_sync(runtime.close())
    _print_json({"success": bool(result.get("ok")), **result})
    return 0 if result.get("ok") else 1


def cmd_core_install(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = run_sync(
        install_core(
            args.name,
            force=bool(getattr(args, "force", False)),
            tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
        )
    )
    _print_json({"success": True, **result})
    return 0


def cmd_xray_install(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = run_sync(
        install_core(
            "xray",
            force=bool(getattr(args, "force", False)) or bool(tag),
            tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
        )
    )
    _print_json({"success": True, **result})
    return 0


def cmd_xray_update(args: argparse.Namespace) -> int:
    tag = getattr(args, "tag", None)
    result = run_sync(
        install_core(
            "xray",
            force=True,
            tag=tag.strip() if isinstance(tag, str) and tag.strip() else None,
        )
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

            proc = run_sync(run_cmd([str(path), "version"], check=False, timeout=15))
            payload["version"] = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or None
        except OSError:
            pass
    _print_json(payload)
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    if args.action == "reset":
        return cmd_service_reset()
    if args.action == "reload":
        return cmd_service_reload()
    result = run_sync(service_action(args.action))
    _print_json({"success": bool(result.get("ok", True)), **result})
    return 0 if result.get("ok", True) else 1


def cmd_service_reload() -> int:
    """Rewrite VPN runtime from stored data and start anything that is down."""
    from agent.service_reload import reload_stored_services

    runtime = open_runtime()
    try:
        report = run_sync(reload_stored_services(runtime.settings, runtime.store, runtime.registry))
    finally:
        run_sync(runtime.close())
    _print_json({"success": bool(report.get("ok")), **report})
    return 0 if report.get("ok") else 1


def cmd_service_reset() -> int:
    from agent.factory_reset import RESET_WARNING, confirmation_accepted, factory_reset

    print(RESET_WARNING)
    try:
        typed = input("Type CONFIRM to wipe the database and settings: ")
    except EOFError:
        typed = ""
    if not confirmation_accepted(typed):
        print("Reset cancelled.")
        return 1
    result = run_sync(factory_reset())
    _print_json({"success": True, **result})
    return 0


def cmd_wizard(args: argparse.Namespace) -> int:
    env_path = Path(args.env_path or "/etc/agent/.env")
    print("Agent setup wizard")
    print(f"Env file: {env_path}")

    listen = input("Listen [0.0.0.0:8443]: ").strip() or "0.0.0.0:8443"
    data_dir = input("Data dir [/var/lib/agent]: ").strip() or "/var/lib/agent"
    token_in = input("Auth token [auto-generate]: ").strip()
    token = token_in or generate_token()

    print("Available cores: xray, wireguard, amnezia, l2tp, openvpn")
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
                result = run_sync(install_core(core))
                print(f"  ok: {result.get('message')}")
            except AgentError as exc:
                print(f"  failed: {exc.message}", file=sys.stderr)

    write_env_file(env_path, listen=listen, token=token, data_dir=data_dir, cores=cores)
    print(f"Wrote {env_path}")
    print(f"Token: {token}")

    svc = input("Install/enable systemd service? [y/N]: ").strip().lower() in {"y", "yes"}
    if svc:
        try:
            run_sync(service_action("install"))
            run_sync(service_action("restart"))
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
    result = run_sync(ensure_acme(email=args.email or ''))
    _print_json({'success': True, **result})
    return 0


def cmd_tls_install_certbot(_: argparse.Namespace) -> int:
    from agent.tls import ensure_certbot
    result = run_sync(ensure_certbot())
    _print_json({'success': True, **result})
    return 0


def cmd_tls_issue(args: argparse.Namespace) -> int:
    from agent.tls import issue_cert
    result = run_sync(issue_cert(
        domain=args.domain,
        method=args.method,
        cf_token=args.cf_token,
        email=args.email or '',
        force=bool(args.force),
        tool=args.tool,
    ))
    _print_json(result)
    return 0


def cmd_tls_renew(args: argparse.Namespace) -> int:
    from agent.tls import renew_cert
    result = run_sync(renew_cert(domain=args.domain, force=bool(args.force), tool=args.tool))
    _print_json(result)
    return 0


def cmd_tls_list(_: argparse.Namespace) -> int:
    from agent.tls import list_certs
    _print_json({'success': True, 'certs': list_certs()})
    return 0


def cmd_tls_revoke(args: argparse.Namespace) -> int:
    from agent.tls import revoke_cert
    result = run_sync(revoke_cert(domain=args.domain))
    _print_json(result)
    return 0


def cmd_bbr_status(_: argparse.Namespace) -> int:
    from agent.asyncutil import run_sync
    from agent.bbr import bbr_status

    _print_json({'success': True, **run_sync(bbr_status())})
    return 0


def cmd_bbr_install(args: argparse.Namespace) -> int:
    from agent.asyncutil import run_sync
    from agent.bbr import bbr_install

    result = run_sync(bbr_install(apply=bool(getattr(args, 'apply', False))))
    _print_json({'success': True, **result})
    return 0


def cmd_bbr_enable(_: argparse.Namespace) -> int:
    from agent.asyncutil import run_sync
    from agent.bbr import bbr_enable

    _print_json({'success': True, **run_sync(bbr_enable())})
    return 0


def cmd_bbr_disable(args: argparse.Namespace) -> int:
    from agent.asyncutil import run_sync
    from agent.bbr import bbr_disable

    result = run_sync(
        bbr_disable(remove_persistence=bool(getattr(args, 'remove_persistence', False))),
    )
    _print_json({'success': True, **result})
    return 0


def cmd_dns_leak_status(_: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_status
    _print_json({'success': True, **run_sync(dns_leak_status())})
    return 0


def cmd_dns_leak_apply(args: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_apply
    result = run_sync(dns_leak_apply(
        interfaces=list(args.interface or []),
        block_ipv6=bool(getattr(args, 'block_ipv6', False)),
        with_resolver=not bool(getattr(args, 'no_resolver', False)),
        upstream_dns=list(args.upstream or []) or None,
    ))
    _print_json({'success': bool(result.get('applied', True)), **result})
    return 0 if result.get('applied', True) else 1


def cmd_dns_leak_remove(_: argparse.Namespace) -> int:
    from agent.dns_leak import dns_leak_remove
    _print_json({'success': True, **run_sync(dns_leak_remove())})
    return 0


def cmd_ads_block_status(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_status
    _print_json({'success': True, **run_sync(ads_block_status())})
    return 0


def cmd_ads_block_prerequisites(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_prerequisites
    _print_json({'success': True, **run_sync(ads_block_prerequisites())})
    return 0


def cmd_ads_block_install(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_install_prerequisites
    _print_json({'success': True, **run_sync(ads_block_install_prerequisites())})
    return 0


def cmd_ads_block_ensure(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_ensure
    _print_json({'success': True, **run_sync(ads_block_ensure())})
    return 0


def cmd_ads_block_disable(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_disable
    _print_json({'success': True, **run_sync(ads_block_disable())})
    return 0


def cmd_ads_block_repair(_: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_repair_service
    _print_json({'success': True, **run_sync(ads_block_repair_service())})
    return 0


def cmd_ads_block_test(args: argparse.Namespace) -> int:
    from agent.ads_block import ads_block_test
    result = run_sync(ads_block_test(str(getattr(args, 'domain', '') or 'doubleclick.net')))
    _print_json({'success': bool(result.get('blocked')), **result})
    return 0 if result.get('blocked') else 1


def cmd_peer_diagnose(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        core = (args.core or "wireguard").strip().lower()
        driver = runtime.registry.get(core)
        if not hasattr(driver, "diagnose_address"):
            raise AgentError("UNSUPPORTED_CAPABILITY", f"Core [{core}] does not support peer diagnose")
        report = run_sync(driver.diagnose_address(args.address))
        _emit_diagnose_report(report, args)
        healthy = bool((report.get("summary") or {}).get("healthy"))
        if report.get("found") is False:
            return 2
        return 0 if healthy else 1
    finally:
        run_sync(runtime.close())


def cmd_client_diagnose(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        driver = runtime.registry.get("xray")
        if not hasattr(driver, "diagnose_client"):
            raise AgentError("UNSUPPORTED_CAPABILITY", "Xray core does not support client diagnose")
        client_key = str(args.email or args.key or args.client_id or "").strip()
        if not client_key:
            raise AgentError("VALIDATION_ERROR", "email, key, or client_id is required")
        inbound_id = str(getattr(args, "inbound_id", "") or "").strip() or None
        report = run_sync(driver.diagnose_client(client_key, inbound_id=inbound_id))
        _emit_diagnose_report(report, args)
        healthy = bool((report.get("summary") or {}).get("healthy"))
        if report.get("found") is False:
            return 2
        return 0 if healthy else 1
    finally:
        run_sync(runtime.close())


def cmd_peer_trace(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        core = (args.core or "wireguard").strip().lower()
        driver = runtime.registry.get(core)
        if not hasattr(driver, "trace_address"):
            raise AgentError("UNSUPPORTED_CAPABILITY", f"Core [{core}] does not support trace")
        report = run_sync(driver.trace_address(args.address))
        _emit_diagnose_report(report, args)
        if report.get("found") is False:
            return 2
        return 0
    finally:
        run_sync(runtime.close())


def cmd_client_trace(args: argparse.Namespace) -> int:
    runtime = open_runtime(args.env_file)
    try:
        driver = runtime.registry.get("xray")
        if not hasattr(driver, "trace_client"):
            raise AgentError("UNSUPPORTED_CAPABILITY", "Xray core does not support trace")
        client_key = str(args.email or args.key or args.client_id or "").strip()
        if not client_key:
            raise AgentError("VALIDATION_ERROR", "email, key, or client_id is required")
        inbound_id = str(getattr(args, "inbound_id", "") or "").strip() or None
        report = run_sync(driver.trace_client(client_key, inbound_id=inbound_id))
        _emit_diagnose_report(report, args)
        if report.get("found") is False:
            return 2
        return 0
    finally:
        run_sync(runtime.close())


def _mullvad_service(args: argparse.Namespace):
    from agent.support.mullvad import MullvadService

    runtime = open_runtime(getattr(args, "env_file", None))
    service = MullvadService(runtime.store, config_dir=runtime.settings.wireguard_config_dir)
    return runtime, service


def cmd_mullvad_status(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        _print_json({"success": True, **run_sync(service.status(probe=bool(getattr(args, "probe", False))))})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_settings_get(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        settings = service.settings()
        public = {k: v for k, v in settings.items() if k != "private_key"}
        _print_json({"success": True, "settings": public})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_settings_set(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        kwargs: dict = {}
        if getattr(args, "private_key", None) is not None:
            kwargs["private_key"] = str(args.private_key)
        if getattr(args, "address", None) is not None:
            kwargs["address"] = str(args.address)
        if getattr(args, "relay_metric", None) is not None:
            kwargs["relay_metric"] = str(args.relay_metric)
        if getattr(args, "auto_fallback", None) is not None:
            kwargs["auto_fallback"] = bool(args.auto_fallback)
        if not kwargs:
            raise AgentError("VALIDATION_ERROR", "Provide --private-key, --address, --metric, and/or --auto-fallback")
        saved = run_sync(service.save_settings(**kwargs))
        public = {k: v for k, v in saved.items() if k != "private_key"}
        _print_json({"success": True, "settings": public})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_auto_fallback(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        action = str(getattr(args, "auto_fallback_command", "") or "").strip().lower()
        if action in {"status", "show", ""}:
            settings = service.settings()
            _print_json({
                "success": True,
                "auto_fallback": bool(settings.get("auto_fallback", True)),
                "settings": {k: v for k, v in settings.items() if k != "private_key"},
            })
            return 0
        enabled = action in {"on", "enable", "enabled", "true", "1"}
        if action not in {"on", "off", "enable", "disable", "enabled", "disabled", "true", "false", "1", "0"}:
            raise AgentError("VALIDATION_ERROR", "Use: agent mullvad auto-fallback on|off|status")
        if action in {"off", "disable", "disabled", "false", "0"}:
            enabled = False
        saved = run_sync(service.save_settings(auto_fallback=enabled))
        _print_json({
            "success": True,
            "auto_fallback": bool(saved.get("auto_fallback")),
            "message": "auto fallback enabled" if enabled else "auto fallback disabled",
        })
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_service(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        action = str(getattr(args, "service_action", "") or "").strip().lower()
        iface = str(getattr(args, "iface", "") or "").strip()
        if iface:
            payload = run_sync(service.control_tunnel(iface, action))
        else:
            payload = run_sync(service.control_tunnels(action))
        _print_json({"success": True, **payload})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_fallback(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        country = str(getattr(args, "country", "") or "").strip() or None
        payload = run_sync(service.fallback(country, optimize=bool(getattr(args, "optimize", False))))
        _print_json({"success": True, **payload})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_restore(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        _print_json({"success": True, **run_sync(service.restore_interfaces())})
    finally:
        run_sync(runtime.close())
    return 0


def cmd_mullvad_ensure(args: argparse.Namespace) -> int:
    runtime, service = _mullvad_service(args)
    try:
        _print_json({"success": True, **run_sync(service.ensure(str(args.country)))})
    finally:
        run_sync(runtime.close())
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
    p_stats.add_argument("--core", default=None, help="Limit to one core (xray|wireguard|amnezia|l2tp|openvpn)")
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

    p_core_reset = core_sub.add_parser(
        "reset",
        help="Wipe a core's runtime so the panel can sync from scratch",
    )
    _env_flag(p_core_reset)
    p_core_reset.add_argument("name", choices=["openvpn"], help="Core to wipe")
    p_core_reset.add_argument(
        "--yes",
        action="store_true",
        help="Skip CONFIRM prompt",
    )
    p_core_reset.set_defaults(func=cmd_core_reset)

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

    p_service = sub.add_parser("service", help="Manage the agent unit, or reload VPN cores from stored data")
    p_service.add_argument(
        "action",
        choices=["install", "uninstall", "start", "stop", "restart", "status", "enable", "disable", "reset", "reload"],
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

    p_dns_apply = dns_sub.add_parser("apply", help="Apply DNS redirect rules for VPN clients")
    p_dns_apply.add_argument(
        "--interface",
        action="append",
        default=[],
        help="VPN interface to protect (repeatable; auto-detect WireGuard/Amnezia when omitted)",
    )
    p_dns_apply.add_argument(
        "--block-ipv6",
        action="store_true",
        help="Drop IPv6 traffic on VPN interfaces (may break dual-stack sites)",
    )
    p_dns_apply.add_argument(
        "--no-resolver",
        action="store_true",
        help="Skip AdGuard Home resolver setup",
    )
    p_dns_apply.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="Upstream DNS for AdGuard Home (repeatable; default: 1.1.1.1 and 8.8.8.8)",
    )
    p_dns_apply.set_defaults(func=cmd_dns_leak_apply)

    p_dns_remove = dns_sub.add_parser("remove", help="Remove DNS leak protection rules")
    p_dns_remove.set_defaults(func=cmd_dns_leak_remove)

    p_ads_block = sub.add_parser("ads-block", help="WireGuard / Amnezia ads DNS filter")
    ads_sub = p_ads_block.add_subparsers(dest="ads_block_command", required=True)

    p_ads_status = ads_sub.add_parser("status", help="Ads blocker status and prerequisites")
    p_ads_status.set_defaults(func=cmd_ads_block_status)

    p_ads_prereq = ads_sub.add_parser("prerequisites", help="Show ads blocker prerequisites")
    p_ads_prereq.set_defaults(func=cmd_ads_block_prerequisites)

    p_ads_install = ads_sub.add_parser("install", help="Install AdGuard Home and dnsutils")
    p_ads_install.set_defaults(func=cmd_ads_block_install)

    p_ads_ensure = ads_sub.add_parser("ensure", help="Enable ads DNS filter on VPN resolver")
    p_ads_ensure.set_defaults(func=cmd_ads_block_ensure)

    p_ads_disable = ads_sub.add_parser("disable", help="Disable ads DNS filter")
    p_ads_disable.set_defaults(func=cmd_ads_block_disable)

    p_ads_repair = ads_sub.add_parser("repair", help="Start AdGuard Home and fix port-53 conflicts")
    p_ads_repair.set_defaults(func=cmd_ads_block_repair)

    p_ads_test = ads_sub.add_parser("test", help="Query a known ad domain via VPN DNS")
    p_ads_test.add_argument(
        "--domain",
        default="doubleclick.net",
        help="Domain to resolve (default: doubleclick.net)",
    )
    p_ads_test.set_defaults(func=cmd_ads_block_test)

    p_mullvad = sub.add_parser("mullvad", help="Mullvad exit tunnels (account, status, service, fallback)")
    mullvad_sub = p_mullvad.add_subparsers(dest="mullvad_command", required=True)

    p_mv_status = mullvad_sub.add_parser("status", help="Show Mullvad account + tunnel/service status")
    _env_flag(p_mv_status)
    p_mv_status.add_argument("--probe", action="store_true", help="Also run curl egress probes (slower)")
    p_mv_status.set_defaults(func=cmd_mullvad_status)

    p_mv_settings = mullvad_sub.add_parser("settings", help="Show or update Mullvad account settings")
    mv_settings_sub = p_mv_settings.add_subparsers(dest="mullvad_settings_command", required=True)
    p_mv_settings_get = mv_settings_sub.add_parser("get", help="Show current settings (key masked)")
    _env_flag(p_mv_settings_get)
    p_mv_settings_get.set_defaults(func=cmd_mullvad_settings_get)
    p_mv_settings_set = mv_settings_sub.add_parser("set", help="Set private key / address / metric / auto-fallback")
    _env_flag(p_mv_settings_set)
    p_mv_settings_set.add_argument("--private-key", dest="private_key", default=None, help="WireGuard private key")
    p_mv_settings_set.add_argument(
        "--address",
        default=None,
        help="Tunnel Address (e.g. 10.69.169.66/32,fc00:bbbb:bbbb:bb01::6:a941/128)",
    )
    p_mv_settings_set.add_argument("--metric", dest="relay_metric", choices=["ping", "speed"], default=None)
    p_mv_settings_set.add_argument(
        "--auto-fallback",
        dest="auto_fallback",
        choices=["on", "off"],
        default=None,
        help="Enable/disable automatic relay fallback worker",
    )
    def _mv_settings_set(args: argparse.Namespace) -> int:
        if args.auto_fallback is not None:
            args.auto_fallback = args.auto_fallback == "on"
        return cmd_mullvad_settings_set(args)

    p_mv_settings_set.set_defaults(func=_mv_settings_set)

    p_mv_auto = mullvad_sub.add_parser("auto-fallback", help="Enable/disable/show automatic fallback")
    _env_flag(p_mv_auto)
    p_mv_auto.add_argument(
        "auto_fallback_command",
        nargs="?",
        default="status",
        choices=["on", "off", "status", "enable", "disable"],
        help="on|off|status (default: status)",
    )
    p_mv_auto.set_defaults(func=cmd_mullvad_auto_fallback)

    p_mv_service = mullvad_sub.add_parser("service", help="Start/stop/restart Mullvad exit units")
    _env_flag(p_mv_service)
    p_mv_service.add_argument("service_action", choices=["start", "stop", "restart"])
    p_mv_service.add_argument("--iface", default=None, help="Single iface (default: all bound exits)")
    p_mv_service.set_defaults(func=cmd_mullvad_service)

    p_mv_fallback = mullvad_sub.add_parser("fallback", help="Run relay fallback now")
    _env_flag(p_mv_fallback)
    p_mv_fallback.add_argument("--country", default=None, help="Limit to one country code")
    p_mv_fallback.add_argument("--optimize", action="store_true", help="Re-rank even healthy exits")
    p_mv_fallback.set_defaults(func=cmd_mullvad_fallback)

    p_mv_restore = mullvad_sub.add_parser("restore", help="Bring downed Mullvad exits back up")
    _env_flag(p_mv_restore)
    p_mv_restore.set_defaults(func=cmd_mullvad_restore)

    p_mv_ensure = mullvad_sub.add_parser("ensure", help="Ensure a country exit exists")
    _env_flag(p_mv_ensure)
    p_mv_ensure.add_argument("country", help="ISO country code (e.g. de, se, pl)")
    p_mv_ensure.set_defaults(func=cmd_mullvad_ensure)

    p_peer = sub.add_parser("peer", help="WireGuard / Amnezia peer diagnostics")
    peer_sub = p_peer.add_subparsers(dest="peer_command", required=True)

    p_peer_diag = peer_sub.add_parser(
        "diagnose",
        help="Full routing/interface diagnostic for a peer AllowedIP address",
    )
    _env_flag(p_peer_diag)
    p_peer_diag.add_argument("address", help="Peer address (e.g. 10.80.0.5 or 10.80.0.5/32)")
    p_peer_diag.add_argument(
        "--core",
        default="wireguard",
        choices=["wireguard", "amnezia", "l2tp", "openvpn"],
        help="VPN core to inspect (default: wireguard)",
    )
    p_peer_diag.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of a human-readable table",
    )
    p_peer_diag.set_defaults(func=cmd_peer_diagnose)

    p_peer_trace = peer_sub.add_parser(
        "trace",
        help="Read-only traffic path for a peer address",
    )
    _env_flag(p_peer_trace)
    p_peer_trace.add_argument("address", help="Peer address (e.g. 10.80.0.5 or 10.80.0.5/32)")
    p_peer_trace.add_argument(
        "--core",
        default="wireguard",
        choices=["wireguard", "amnezia", "l2tp", "openvpn"],
        help="VPN core to inspect (default: wireguard)",
    )
    p_peer_trace.add_argument("--json", action="store_true", help="Output raw JSON")
    p_peer_trace.set_defaults(func=cmd_peer_trace)

    p_client = sub.add_parser("client", help="Xray client diagnostics")
    client_sub = p_client.add_subparsers(dest="client_command", required=True)

    p_client_diag = client_sub.add_parser(
        "diagnose",
        help="Full config/runtime diagnostic for an Xray client (email, id, or UUID)",
    )
    _env_flag(p_client_diag)
    p_client_diag.add_argument(
        "--email",
        help="Client email / remark (searches all inbounds when --inbound-id is omitted)",
    )
    p_client_diag.add_argument("--key", help="Alias for email or client UUID")
    p_client_diag.add_argument("--client-id", help="Client UUID")
    p_client_diag.add_argument(
        "--inbound-id",
        help="Optional inbound id/tag scope (default: search all inbounds by email/id)",
    )
    p_client_diag.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of a human-readable table",
    )
    p_client_diag.set_defaults(func=cmd_client_diagnose)

    p_client_trace = client_sub.add_parser(
        "trace",
        help="Read-only traffic path for an Xray client (including Shadowsocks)",
    )
    _env_flag(p_client_trace)
    p_client_trace.add_argument("--email", help="Client email / remark")
    p_client_trace.add_argument("--key", help="Alias for email or client UUID")
    p_client_trace.add_argument("--client-id", help="Client UUID")
    p_client_trace.add_argument("--inbound-id", help="Optional inbound id/tag scope")
    p_client_trace.add_argument("--json", action="store_true", help="Output raw JSON")
    p_client_trace.set_defaults(func=cmd_client_trace)

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
