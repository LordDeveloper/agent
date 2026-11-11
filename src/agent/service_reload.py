"""Rebuild VPN runtime from data the agent already stored.

CLI and the text menu call this with ``run_sync`` (no server loop). Stored
interface/server documents and Xray config.json are rewritten onto disk and
pushed into the live core. Runtime-only peers, users, and Xray clients that
are not in the store are removed. Missing unit files and down services are
started. Xray config.json is never invented from an empty default when the
file was deleted but the process still has user inbounds to recover.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent.asyncutil import gather_independent, maybe_await
from agent.errors import AgentError
from agent.logutil import get_logger, report_progress
from agent.auth_scope import filter_visible

log = get_logger("service.reload")

_CORE_ORDER = ("xray", "wireguard", "amnezia", "l2tp", "openvpn")
_TAIL_STEPS = ("mullvad", "peer_egress")

ProgressFn = Callable[[str, int, int], None]


def _planned_steps(registry: Any) -> list[str]:
    enabled = {key for key, _driver in registry.enabled_drivers()}
    steps = [key for key in _CORE_ORDER if key in enabled]
    steps.extend(_TAIL_STEPS)
    return steps or list(_TAIL_STEPS)


def _tick(progress: ProgressFn | None, done: int, total: int, label: str) -> None:
    step = min(max(1, int(done)), max(1, int(total)))
    report_progress(step, total, label)
    if progress is not None:
        progress(label, step, total)


async def reload_stored_services(
    settings: Any,
    store: Any,
    registry: Any,
    *,
    progress: ProgressFn | None = None,
) -> dict[str, Any]:
    """Regenerate stored cores, sync runtime, and start whatever is down."""
    total = max(1, len(_planned_steps(registry)))
    enabled = {key for key, _driver in registry.enabled_drivers()}
    cores: dict[str, Any] = {}
    index = 0
    for key in _CORE_ORDER:
        if key not in enabled:
            cores[key] = {"ok": True, "skipped": True, "reason": "core disabled"}
            continue
        index += 1
        driver = registry.get(key, require_enabled=False)
        _tick(progress, index, total, f"{key}: reloading")
        cores[key] = await _safe(
            key,
            lambda driver=driver, key=key, index=index: _reload_core(
                key,
                driver,
                progress=progress,
                step=index,
                total=total,
            ),
        )
        _tick(progress, index, total, f"{key}: done")

    for key in _TAIL_STEPS:
        index += 1
        _tick(progress, index, total, f"{key}: reloading")
        if key == "mullvad":
            cores[key] = await _safe("mullvad", lambda: _reload_mullvad(settings, store))
        else:
            cores[key] = await _safe("peer_egress", lambda: _reload_peer_egress(settings, store))
        _tick(progress, index, total, f"{key}: done")

    ok = all(bool(row.get("ok")) for row in cores.values())
    log.info("service reload finished ok=%s", ok)
    return {"ok": ok, "cores": cores}


async def _safe(name: str, fn: Any) -> dict[str, Any]:
    try:
        result = await fn()
    except AgentError as exc:
        log.warning("service reload %s failed: %s", name, exc.message)
        return {"ok": False, "error": exc.message}
    except Exception as exc:
        log.warning("service reload %s failed: %s", name, exc)
        return {"ok": False, "error": str(exc)}
    if not isinstance(result, dict):
        return {"ok": True}
    result.setdefault("ok", True)
    return result


async def _reload_core(
    key: str,
    driver: Any,
    *,
    progress: ProgressFn | None,
    step: int,
    total: int,
) -> dict[str, Any]:
    if key == "xray":
        return await _reload_xray(driver)
    if key in {"wireguard", "amnezia"}:
        return await _reload_tunnel_core(driver, key=key, progress=progress, step=step, total=total)
    if key == "l2tp":
        return await _reload_l2tp(driver, store=driver.store)
    if key == "openvpn":
        return await _reload_openvpn(driver)
    return {"ok": True, "skipped": True, "reason": "unsupported core"}


def _xray_file_usable(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("inbounds"), list)


async def _reload_xray(driver: Any) -> dict[str, Any]:
    from agent.xray_service import binary_has_httpapi, ensure_xray_running

    path = Path(driver.settings.xray.config)
    recovered = False
    if not _xray_file_usable(path):
        recovered_result = await _recover_xray_file(driver, path)
        if not recovered_result.get("ok"):
            return recovered_result
        recovered = True

    binary = driver._binary()
    if not binary or not binary_has_httpapi(binary):
        return {
            "ok": False,
            "error": "Xray binary with HTTP API is not installed",
            "recovered_from_runtime": recovered,
        }

    xray = driver.settings.xray
    started = await ensure_xray_running(
        binary=xray.binary,
        config_path=str(path),
        api_base=xray.api_base,
        username=xray.username,
        password=xray.password,
    )
    imported = False
    sync_report: dict[str, Any] = {}
    if not recovered:
        config = await driver._read_config()
        await driver.import_config(config, path=str(path))
        imported = True
        sync_report = await driver.enforce_disk_clients_on_runtime(persist_confirm=False)
    sync_ok = bool(sync_report.get("ok", True)) if sync_report else True
    payload: dict[str, Any] = {
        "ok": sync_ok,
        "config": str(path),
        "started": bool(started.get("started")),
        "already_running": bool(started.get("already_running")),
        "recovered_from_runtime": recovered,
        "imported": imported,
        "added_runtime": int(sync_report.get("added_runtime") or 0),
        "removed_extra": int(sync_report.get("removed_extra") or 0),
        "removed_disabled": int(sync_report.get("removed_disabled") or 0),
    }
    if imported and not sync_ok:
        detail = "; ".join(str(item) for item in (sync_report.get("errors") or [])[:3]).strip()
        payload["error"] = detail or "Xray client sync from stored config failed"
        payload["sync"] = sync_report
    elif not sync_ok:
        payload["sync"] = sync_report
    return payload


async def _recover_xray_file(driver: Any, path: Path) -> dict[str, Any]:
    """Write config.json from the running core. Never invent an empty file."""
    try:
        inbounds = await driver._api_call("list_inbounds")
        outbounds = await driver._api_call("list_outbounds")
        rules = await driver._api_call("list_rules")
    except Exception as exc:
        return {
            "ok": False,
            "error": "Xray config file is missing and the running core could not be read",
            "detail": getattr(exc, "message", None) or str(exc),
        }

    rows = [row for row in (inbounds or []) if isinstance(row, dict)]
    user_rows = [row for row in rows if str(row.get("tag") or "") != "api"]
    if not user_rows:
        return {
            "ok": False,
            "error": "Xray config file is missing and the running core has no user inbounds to save",
        }

    binary = driver._binary()
    if not binary:
        return {
            "ok": False,
            "error": "Xray config file is missing and the binary is not installed to validate a recovered config",
        }

    from agent.support.config_validate import validate_xray_config
    from agent.xray_service import default_xray_config

    xray = driver.settings.xray
    payload = default_xray_config(
        api_base=xray.api_base,
        username=xray.username,
        password=xray.password,
        config_path=str(path),
    )
    payload["inbounds"] = rows
    outbound_rows = [row for row in (outbounds or []) if isinstance(row, dict)]
    if outbound_rows:
        payload["outbounds"] = outbound_rows
    rule_rows = [row for row in (rules or []) if isinstance(row, dict)]
    if rule_rows:
        routing = payload.setdefault("routing", {})
        if isinstance(routing, dict):
            routing["rules"] = rule_rows

    try:
        await validate_xray_config(binary, payload)
    except Exception as exc:
        return {
            "ok": False,
            "error": "Xray config file is missing and the live core could not be saved as a valid config",
            "detail": getattr(exc, "message", None) or str(exc),
        }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "recovered_from_runtime": True, "inbounds": len(user_rows)}


async def _reload_tunnel_core(
    driver: Any,
    *,
    key: str,
    progress: ProgressFn | None,
    step: int,
    total: int,
) -> dict[str, Any]:
    """Rewrite WireGuard/Amnezia confs from sqlite and sync live peers."""
    ifaces = filter_visible(list(await maybe_await(driver.list_interfaces()) or []), key)
    if not ifaces:
        return {"ok": True, "skipped": True, "reason": "no interfaces in store"}

    brought_up: list[str] = []
    synced: list[str] = []
    removed_peers = 0
    failed: list[dict[str, str]] = []
    iface_total = len(ifaces)
    for index, summary in enumerate(ifaces, start=1):
        iface_id = summary.get("id")
        name = str(summary.get("name") or "").strip()
        sub_label = f"{key} {name or iface_id}: {index}/{iface_total}"
        _tick(progress, step, total, sub_label)
        try:
            iface = await driver.get_interface(iface_id if iface_id is not None else name)
        except AgentError as exc:
            failed.append({"name": name, "error": exc.message})
            continue
        name = str(iface.get("name") or "").strip()
        if not name:
            failed.append({"name": "", "error": "interface has no name"})
            continue
        before_keys: set[str] = set()
        if await driver._interface_is_up(name):
            dump = await driver._peer_dump(name)
            if isinstance(dump, dict):
                from agent.drivers.wireguard import _peer_kernel_drift

                before_keys = {
                    row["public_key"]
                    for row in _peer_kernel_drift(iface, dump)
                    if row.get("action") == "remove"
                }
        try:
            if await driver._interface_is_up(name):
                await driver._apply_live(iface)
                synced.append(name)
            else:
                row = await driver._bring_up(iface)
                if isinstance(row, dict) and row.get("ok"):
                    brought_up.append(name)
                else:
                    detail = ""
                    if isinstance(row, dict):
                        detail = str(row.get("stderr") or row.get("message") or "")
                    failed.append({"name": name, "error": detail or "wg-quick up failed"})
                    continue
            if before_keys:
                dump = await driver._peer_dump(name)
                if isinstance(dump, dict):
                    from agent.drivers.wireguard import _peer_kernel_drift

                    after = {
                        row["public_key"]
                        for row in _peer_kernel_drift(iface, dump)
                        if row.get("action") == "remove"
                    }
                    removed_peers += len(before_keys - after)
        except Exception as exc:
            failed.append({"name": name, "error": getattr(exc, "message", None) or str(exc)})
    payload: dict[str, Any] = {
        "ok": not failed,
        "brought_up": brought_up,
        "synced": synced,
        "failed": failed,
    }
    if removed_peers:
        payload["removed_peers"] = removed_peers
    return payload


async def _reload_l2tp(driver: Any, *, store: Any) -> dict[str, Any]:
    from agent.support.l2tp_companion import sync_companions

    servers = filter_visible(list(await maybe_await(driver.list_servers()) or []), driver.key)
    if not servers:
        return {"ok": True, "skipped": True, "reason": "no servers in store"}
    await driver._apply_all_configs()
    companion = await sync_companions(store)
    await driver.reconcile_runtime()
    result = await driver.enable()
    payload: dict[str, Any] = {
        "ok": True,
        "servers": len(servers),
        "companions_removed": int(companion.get("removed") or 0),
        "companions_updated": int(companion.get("updated") or 0),
    }
    if isinstance(result, dict):
        payload.update({k: v for k, v in result.items() if k not in payload})
    return payload


async def _reload_openvpn(driver: Any) -> dict[str, Any]:
    """Rewrite server configs. Start units that are down; leave active ones up."""
    from agent.support.process import run

    servers = filter_visible(
        [row for row in (await maybe_await(driver.list_servers()) or []) if isinstance(row, dict)],
        driver.key,
    )
    if not servers:
        return {"ok": True, "skipped": True, "reason": "no servers in store"}

    await driver._apply_all_configs()
    await driver._stop_orphan_units()
    await driver.reconcile_runtime()
    driver._install_unit_dropin()
    await run(["systemctl", "daemon-reload"], check=False, timeout=30)

    async def _one(server: dict[str, Any]) -> dict[str, Any]:
        unit = driver._unit_name(server)
        server_dir = driver._server_dir(server)
        conf = server_dir.parent / f"{server_dir.name}.conf"
        if await driver._unit_active(unit):
            return {"unit": unit, "action": "kept", "ok": True}
        if not conf.is_file():
            return {"unit": unit, "action": "start", "ok": False, "error": f"missing config {conf}"}
        await run(["systemctl", "unmask", unit], check=False, timeout=15)
        await run(["systemctl", "enable", unit], check=False, timeout=30)
        action = await run(["systemctl", "start", unit], check=False, timeout=60)
        if await driver._unit_active(unit):
            return {"unit": unit, "action": "started", "ok": True}
        detail = ((getattr(action, "stderr", "") or "") + (getattr(action, "stdout", "") or "")).strip()
        return {"unit": unit, "action": "start", "ok": False, "error": detail or "unit not active"}

    rows = await gather_independent(*(_one(server) for server in servers), return_exceptions=True)
    started: list[str] = []
    kept: list[str] = []
    failed: list[dict[str, str]] = []
    for row in rows:
        if isinstance(row, BaseException):
            failed.append({"unit": "", "error": str(row)})
            continue
        if not isinstance(row, dict):
            failed.append({"unit": "", "error": str(row)})
            continue
        if row.get("action") == "kept":
            kept.append(str(row.get("unit") or ""))
        elif row.get("ok"):
            started.append(str(row.get("unit") or ""))
        else:
            failed.append({"unit": str(row.get("unit") or ""), "error": str(row.get("error") or "start failed")})
    return {
        "ok": not failed,
        "servers": len(servers),
        "started": started,
        "kept": kept,
        "failed": failed,
        "orphan_units_stopped": True,
    }


async def _reload_mullvad(settings: Any, store: Any) -> dict[str, Any]:
    from agent.support.mullvad import MullvadService

    service = MullvadService(store, config_dir=settings.wireguard_config_dir)
    result = await service.reload_bindings()
    if not isinstance(result, dict):
        return {"ok": True}
    result.setdefault("ok", True)
    return result


async def _reload_peer_egress(settings: Any, store: Any) -> dict[str, Any]:
    from agent.support.peer_egress import repair_peer_egress

    result = await repair_peer_egress(
        store,
        data_dir=settings.data_dir,
        force=True,
    )
    if not isinstance(result, dict):
        return {"ok": True}
    ok = bool(result.get("ok", True))
    payload: dict[str, Any] = {
        "ok": ok,
        "rules": result.get("rules"),
        "sysctl_persist": result.get("sysctl_persist"),
    }
    if not ok:
        payload["error"] = "peer egress repair did not apply"
    return payload
