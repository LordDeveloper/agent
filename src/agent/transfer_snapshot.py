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
_CERT_KEYS = {
    "certificateFile",
    "keyFile",
    "certFile",
    "certPath",
    "keyPath",
    "caFile",
    "dhFile",
}
_OPENVPN_PKI_FILES = (
    ("ca.crt", "ca_crt"),
    ("ca.key", "ca_key"),
    ("server.crt", "server_crt"),
    ("server.key", "server_key"),
    ("tc.key", "tls_crypt"),
    ("dh.pem", "dh_pem"),
)
_MATERIAL_SUFFIXES = {".pem", ".crt", ".cer", ".key", ".csr"}
_MATERIAL_NAMES = {"tc.key", "dh.pem", "ca.srl"}
_MAX_MATERIAL_BYTES = 512_000
_MAX_MATERIAL_FILES = 2000
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
            candidate = Path(value.strip())
            if candidate.is_absolute() and ".." not in candidate.parts:
                found.append(str(candidate))
            continue
        if isinstance(value, (dict, list)):
            _cert_paths(value, found)


def _read_text(path: Path) -> str:
    try:
        if not path.is_file() or path.is_symlink():
            return ""
        if path.stat().st_size > _MAX_MATERIAL_BYTES:
            return ""
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _openvpn_roots(settings: Any) -> list[Path]:
    configured = str(getattr(getattr(settings, "openvpn", None), "config_dir", "") or "/etc/agent/bin/openvpn")
    return [Path("/etc/openvpn/server"), Path(configured) / "pki"]


def _material_roots(settings: Any) -> list[Path]:
    roots = [
        Path("/etc/openvpn"),
        Path("/etc/letsencrypt/live"),
        Path("/etc/letsencrypt/archive"),
        Path("/var/lib/agent/certs"),
        Path("/usr/local/etc/xray"),
        Path("/etc/xray"),
        Path("/etc/ipsec.d"),
        *_openvpn_roots(settings),
    ]
    raw = str(getattr(getattr(settings, "xray", None), "config", "") or getattr(settings, "xray_config", "") or "")
    if raw.strip():
        roots.append(Path(raw).parent)
    l2tp = str(getattr(getattr(settings, "l2tp", None), "config_dir", "") or "")
    if l2tp.strip():
        roots.append(Path(l2tp))
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def _under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.expanduser().resolve(strict=False))
    except (OSError, ValueError):
        return False
    return True


def _safe_material_path(raw: str, settings: Any) -> Path | None:
    text = str(raw or "").strip()
    if text == "" or "\x00" in text:
        return None
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        return None
    if not any(_under_root(path, root) for root in _material_roots(settings)):
        return None
    return path


def _material_file(path: Path) -> bool:
    name = path.name.lower()
    return name in _MATERIAL_NAMES or path.suffix.lower() in _MATERIAL_SUFFIXES


def _walk_material(settings: Any) -> list[str]:
    found: list[str] = []
    for root in _material_roots(settings):
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if len(found) >= _MAX_MATERIAL_FILES:
                return found
            if not path.is_file() or path.is_symlink() or not _material_file(path):
                continue
            safe = _safe_material_path(str(path), settings)
            if safe is not None:
                found.append(str(safe))
    return found


def _absorb_openvpn_pki(documents: list[dict[str, Any]], settings: Any) -> None:
    from agent.support.openvpn_config import instance_name_for_server, normalize_tls_crypt

    for row in documents:
        if str(row.get("core") or "") != "openvpn" or str(row.get("kind") or "") != "server":
            continue
        data = row.get("data")
        if not isinstance(data, dict):
            continue
        instance = instance_name_for_server(data)
        for root in _openvpn_roots(settings):
            for filename, key in _OPENVPN_PKI_FILES:
                text = _read_text(root / instance / filename)
                if key == "tls_crypt":
                    text = normalize_tls_crypt(text)
                if text:
                    data[key] = text


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


def _split_material_paths(paths: list[str], settings: Any) -> tuple[list[str], list[str], list[str]]:
    from agent.tls import _allowed_cert_path

    tls_paths: list[str] = []
    dependency_paths: list[str] = []
    rejected: list[str] = []
    for raw in paths:
        text = str(raw or "").strip()
        if text == "":
            continue
        try:
            _allowed_cert_path(text)
        except AgentError:
            safe = _safe_material_path(text, settings)
            if safe is None:
                rejected.append(text)
            else:
                dependency_paths.append(str(safe))
            continue
        tls_paths.append(text)
    return (
        list(dict.fromkeys(tls_paths)),
        list(dict.fromkeys(dependency_paths)),
        list(dict.fromkeys(rejected)),
    )


def _material_content_ok(content: str) -> bool:
    if content.strip() == "" or "\x00" in content:
        return False
    if "-----BEGIN " in content:
        return True
    return len(content) <= 8192 and all(ch in "\r\n\t" or 32 <= ord(ch) < 127 for ch in content)


def _read_dependency_files(paths: list[str], settings: Any) -> dict[str, list[Any]]:
    files: list[dict[str, str]] = []
    missing: list[str] = []
    for raw in paths:
        path = _safe_material_path(raw, settings)
        if path is None:
            missing.append(str(raw))
            continue
        if not path.is_file():
            missing.append(str(path))
            continue
        try:
            size = path.stat().st_size
        except OSError:
            missing.append(str(path))
            continue
        if size > _MAX_MATERIAL_BYTES:
            missing.append(str(path))
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            missing.append(str(path))
            continue
        if not _material_content_ok(content):
            missing.append(str(path))
            continue
        files.append({"path": str(path), "content": content})
    return {"files": files, "missing": missing}


def _write_dependency_files(files: list[dict[str, Any]], settings: Any) -> int:
    written = 0
    for item in files:
        if not isinstance(item, dict):
            continue
        path = _safe_material_path(str(item.get("path") or ""), settings)
        content = item.get("content")
        if path is None or not isinstance(content, str) or not _material_content_ok(content):
            continue
        if len(content.encode("utf-8")) > _MAX_MATERIAL_BYTES:
            continue
        if path.is_symlink():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        name = path.name.lower()
        if name.endswith(".key") or "privkey" in name or "private" in name:
            try:
                path.chmod(0o600)
            except OSError:
                pass
        written += 1
    return written


async def export_snapshot(settings: Any, store: Any) -> dict[str, Any]:
    """Full copy of agent state. Traffic counters and the audit log stay behind."""
    from agent.tls import acme_installed, export_acme_store, export_files, list_certs
    from agent.xray_release import export_geodata

    report_progress(0, _STEPS, "Reading agent database")
    documents = await store.dump_documents()
    meta = await store.dump_meta()
    _absorb_openvpn_pki(documents, settings)
    from agent.support.openvpn_certificates import attach_document_certificates

    attach_document_certificates(documents, settings)

    report_progress(1, _STEPS, "Reading Xray config")
    config = _read_xray_config(settings)

    paths: list[str] = []
    _cert_paths(config, paths)
    _cert_paths(documents, paths)
    for row in list_certs():
        if not isinstance(row, dict):
            continue
        for key in ("cert_file", "key_file"):
            value = str(row.get(key) or "").strip()
            if value:
                paths.append(value)
                parent = Path(value).parent
                for extra in ("fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"):
                    sibling = parent / extra
                    if sibling.is_file():
                        paths.append(str(sibling))
    paths.extend(_walk_material(settings))
    unique_paths = list(dict.fromkeys(paths))
    tls_paths, dependency_paths, rejected = _split_material_paths(unique_paths, settings)

    report_progress(2, _STEPS, "Reading TLS files")
    tls_files: list[dict[str, str]] = []
    tls_missing: list[str] = list(rejected)
    if tls_paths:
        exported = export_files(tls_paths)
        tls_files = list(exported.get("files") or [])
        tls_missing.extend(str(item) for item in (exported.get("missing") or []))
    dependency_files = _read_dependency_files(dependency_paths, settings)
    tls_missing.extend(str(item) for item in dependency_files["missing"])

    report_progress(3, _STEPS, "Reading acme store")
    acme_files: list[dict[str, str]] = []
    if acme_installed():
        acme_files = list((export_acme_store().get("files") or []))

    report_progress(4, _STEPS, "Reading geodata")
    geodata = list((export_geodata().get("files") or []))

    report_progress(_STEPS, _STEPS, "Snapshot ready")
    log.info(
        "transfer snapshot exported documents=%s tls=%s deps=%s acme=%s geodata=%s xray=%s",
        len(documents),
        len(tls_files),
        len(dependency_files["files"]),
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
        "dependency_files": dependency_files["files"],
        "acme_files": acme_files,
        "geodata": geodata,
    }


async def import_snapshot(settings: Any, store: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Write the snapshot onto disk and into sqlite. Does not start services."""
    from agent.tls import import_acme_store, import_files
    from agent.xray_release import import_geodata

    snapshot = _require_snapshot(payload)
    report_progress(0, _STEPS, "Writing TLS files")
    dependency_files = [row for row in (snapshot.get("dependency_files") or []) if isinstance(row, dict)]
    dependency_written = _write_dependency_files(dependency_files, settings)
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

    from agent.support.openvpn_certificates import install_certificates

    openvpn_certificates = install_certificates(documents, settings, rewrite=True, with_keys=True)

    log.info(
        "transfer snapshot imported documents=%s meta=%s tls=%s deps=%s geodata=%s xray=%s",
        document_count,
        meta_count,
        tls_written,
        dependency_written,
        geodata_written,
        config_path or "-",
    )
    return {
        "documents": document_count,
        "meta": meta_count,
        "tls_files": tls_written,
        "dependency_files": dependency_written,
        "acme_files": acme_written,
        "geodata": geodata_written,
        "xray_config": config_path,
        "openvpn_certificates": openvpn_certificates["written"],
        "tls_missing": [str(item) for item in (snapshot.get("tls_missing") or []) if str(item).strip()],
        "cores": cores_to_enable(snapshot),
    }


async def import_dependencies(settings: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Write certificate and core dependency files without replacing the database."""
    from agent.tls import import_acme_store, import_files

    if not isinstance(payload, dict):
        raise AgentError("VALIDATION_ERROR", "dependency payload must be an object", 422)
    dependency_files = [row for row in (payload.get("dependency_files") or []) if isinstance(row, dict)]
    tls_files = [row for row in (payload.get("tls_files") or []) if isinstance(row, dict)]
    acme_files = [row for row in (payload.get("acme_files") or []) if isinstance(row, dict)]
    return {
        "dependency_files": _write_dependency_files(dependency_files, settings),
        "tls_files": import_files(tls_files)["count"] if tls_files else 0,
        "acme_files": import_acme_store(acme_files)["count"] if acme_files else 0,
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
