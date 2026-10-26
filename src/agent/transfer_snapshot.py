"""Move a whole agent onto another host in one snapshot, then one reload.

The panel only carries the snapshot. Routing, inbounds, outbounds, Mullvad
bindings, and exit tunnels are materialized on the destination by
``reload_stored_services`` after the files and database rows are in place.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

from agent.errors import AgentError
from agent.logutil import get_logger, report_progress

log = get_logger("transfer")

SNAPSHOT_VERSION = 1
_KNOWN_CORES = ("xray", "wireguard", "amnezia", "l2tp", "openvpn")
_CERT_KEYS = {"certificateFile", "keyFile"}
_STEPS = 6

ReloadFn = Callable[..., Awaitable[dict[str, Any]]]


def _cert_paths(node: Any, found: list[str]) -> None:
    if not isinstance(node, dict) and not isinstance(node, list):
        return
    if isinstance(node, list):
        for item in node:
            _cert_paths(item, found)
        return
    for key, value in node.items():
        if key in _CERT_KEYS and isinstance(value, str):
            path = value.strip()
            if path.startswith("/") and ".." not in path:
                found.append(path)
            continue
        if isinstance(value, (dict, list)):
            _cert_paths(value, found)


def _read_xray_config(settings: Any) -> dict[str, Any] | None:
    path = Path(str(getattr(getattr(settings, "xray", None), "config", "") or settings.xray_config))
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError("VALIDATION_ERROR", f"Xray config could not be read: {exc}", 422) from exc
    if not isinstance(data, dict):
        raise AgentError("VALIDATION_ERROR", "Xray config must be a JSON object", 422)
    return data


def _write_xray_config(settings: Any, config: dict[str, Any]) -> str:
    raw = str(getattr(getattr(settings, "xray", None), "config", "") or settings.xray_config)
    path = Path(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return str(path)


def cores_to_enable(snapshot: dict[str, Any]) -> list[str]:
    found: list[str] = []
    config = snapshot.get("xray_config")
    if isinstance(config, dict) and config:
        found.append("xray")
    for row in snapshot.get("documents") or []:
        if not isinstance(row, dict):
            continue
        core = str(row.get("core") or "").strip().lower()
        if core in _KNOWN_CORES and core not in found:
            found.append(core)
    return found


def _env_file() -> Path | None:
    explicit = os.environ.get("ENV_FILE")
    if explicit and Path(explicit).is_file():
        return Path(explicit)
    default = Path("/etc/agent/.env")
    if default.is_file():
        return default
    return None


def _persist_enabled_cores(cores: list[str]) -> None:
    path = _env_file()
    if path is None:
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        log.warning("could not read env file for ENABLED_CORES: %s", exc)
        return
    replacement = "ENABLED_CORES=" + ",".join(cores)
    written = False
    updated: list[str] = []
    for line in lines:
        if line.startswith("ENABLED_CORES="):
            updated.append(replacement)
            written = True
        else:
            updated.append(line)
    if not written:
        updated.append(replacement)
    try:
        path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    except OSError as exc:
        log.warning("could not persist ENABLED_CORES: %s", exc)


def remember_cores(settings: Any, cores: list[str]) -> list[str]:
    current = [part.strip() for part in str(getattr(settings, "enabled_cores", "") or "").split(",") if part.strip()]
    merged = list(dict.fromkeys([*current, *cores]))
    settings.enabled_cores = ",".join(merged)
    _persist_enabled_cores(merged)
    return merged


def _require_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AgentError("VALIDATION_ERROR", "transfer snapshot must be an object", 422)
    try:
        version = int(payload.get("version") or 0)
    except (TypeError, ValueError) as exc:
        raise AgentError("VALIDATION_ERROR", "transfer snapshot version is invalid", 422) from exc
    if version != SNAPSHOT_VERSION:
        raise AgentError("VALIDATION_ERROR", "transfer snapshot version is not supported", 422)
    return payload


async def export_snapshot(settings: Any, store: Any) -> dict[str, Any]:
    """Full copy of agent state. Traffic counters and the audit log stay behind."""
    from agent.tls import acme_installed, export_acme_store, export_files, list_certs
    from agent.xray_release import export_geodata

    report_progress(0, _STEPS, "Reading agent database")
    documents = await store.dump_documents()
    meta = await store.dump_meta()

    report_progress(1, _STEPS, "Reading Xray config")
    config = _read_xray_config(settings)

    paths: list[str] = []
    _cert_paths(config, paths)
    for row in list_certs():
        if not isinstance(row, dict):
            continue
        for key in ("cert_file", "key_file"):
            value = str(row.get(key) or "").strip()
            if value:
                paths.append(value)
    unique_paths = list(dict.fromkeys(paths))

    report_progress(2, _STEPS, "Reading TLS files")
    tls_files: list[dict[str, str]] = []
    tls_missing: list[str] = []
    if unique_paths:
        exported = export_files(unique_paths)
        tls_files = list(exported.get("files") or [])
        tls_missing = [str(item) for item in (exported.get("missing") or [])]

    report_progress(3, _STEPS, "Reading acme store")
    acme_files: list[dict[str, str]] = []
    if acme_installed():
        acme_files = list((export_acme_store().get("files") or []))

    report_progress(4, _STEPS, "Reading geodata")
    geodata = list((export_geodata().get("files") or []))

    report_progress(_STEPS, _STEPS, "Snapshot ready")
    log.info(
        "transfer snapshot exported documents=%s tls=%s acme=%s geodata=%s xray=%s",
        len(documents),
        len(tls_files),
        len(acme_files),
        len(geodata),
        config is not None,
    )
    return {
        "version": SNAPSHOT_VERSION,
        "documents": documents,
        "meta": meta,
        "xray_config": config,
        "tls_files": tls_files,
        "tls_missing": tls_missing,
        "acme_files": acme_files,
        "geodata": geodata,
    }


async def import_snapshot(settings: Any, store: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Write the snapshot onto disk and into sqlite. Does not start services."""
    from agent.tls import import_acme_store, import_files
    from agent.xray_release import import_geodata

    snapshot = _require_snapshot(payload)
    report_progress(0, _STEPS, "Writing TLS files")
    tls_files = [row for row in (snapshot.get("tls_files") or []) if isinstance(row, dict)]
    tls_written = import_files(tls_files)["count"] if tls_files else 0

    report_progress(1, _STEPS, "Writing acme store")
    acme_files = [row for row in (snapshot.get("acme_files") or []) if isinstance(row, dict)]
    acme_written = import_acme_store(acme_files)["count"] if acme_files else 0

    report_progress(2, _STEPS, "Writing geodata")
    geodata = [row for row in (snapshot.get("geodata") or []) if isinstance(row, dict)]
    geodata_written = import_geodata(geodata)["count"] if geodata else 0

    report_progress(3, _STEPS, "Writing agent database")
    documents = [row for row in (snapshot.get("documents") or []) if isinstance(row, dict)]
    meta = [row for row in (snapshot.get("meta") or []) if isinstance(row, dict)]
    document_count = await store.replace_all_documents(documents)
    meta_count = await store.replace_all_meta(meta)

    report_progress(4, _STEPS, "Writing Xray config")
    config = snapshot.get("xray_config")
    config_path = None
    if isinstance(config, dict) and config:
        config_path = _write_xray_config(settings, config)

    log.info(
        "transfer snapshot imported documents=%s meta=%s tls=%s geodata=%s xray=%s",
        document_count,
        meta_count,
        tls_written,
        geodata_written,
        config_path or "-",
    )
    return {
        "documents": document_count,
        "meta": meta_count,
        "tls_files": tls_written,
        "acme_files": acme_written,
        "geodata": geodata_written,
        "xray_config": config_path,
        "tls_missing": [str(item) for item in (snapshot.get("tls_missing") or []) if str(item).strip()],
        "cores": cores_to_enable(snapshot),
    }


async def apply_snapshot(
    settings: Any,
    store: Any,
    registry: Any,
    payload: dict[str, Any],
    *,
    reload: ReloadFn | None = None,
) -> dict[str, Any]:
    """Install the snapshot, then reload once so the destination builds runtime state."""
    from agent.service_reload import reload_stored_services

    imported = await import_snapshot(settings, store, payload)
    enabled = remember_cores(settings, list(imported.get("cores") or []))
    report_progress(5, _STEPS, "Reloading services on this server")
    reload_fn = reload or reload_stored_services
    reloaded = await reload_fn(settings, store, registry)
    if not isinstance(reloaded, dict):
        reloaded = {"ok": True}
    reloaded.setdefault("ok", True)
    report_progress(_STEPS, _STEPS, "Reload finished")
    return {
        "ok": bool(reloaded.get("ok")),
        "enabled_cores": enabled,
        "imported": imported,
        "reload": reloaded,
    }
