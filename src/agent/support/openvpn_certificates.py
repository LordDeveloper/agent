"""Export and import the OpenVPN certificate set as one gzip archive."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from agent.errors import AgentError
from agent.support.openvpn_config import instance_name_for_server

BUNDLE_VERSION = 1
BUNDLE_KIND = "openvpn-certificates"
EXPORT_NAME = "openvpn-certificates.tar.gz"
_CERT_FILES = (
    ("ca.crt", "ca_crt"),
    ("server.crt", "server_crt"),
)
_KEY_FILES = (
    ("ca.key", "ca_key"),
    ("server.key", "server_key"),
    ("tc.key", "tls_crypt"),
)
_MATERIAL_FILES = _CERT_FILES + _KEY_FILES
_MAX_BYTES = 512_000
_MAX_ARCHIVE_BYTES = 8_000_000


def certificate_roots(settings: Any) -> list[Path]:
    configured = str(getattr(getattr(settings, "openvpn", None), "config_dir", "") or "/etc/agent/bin/openvpn")
    return [Path("/etc/openvpn/server"), Path(configured) / "pki"]


def resolve_export_path(raw: str | None) -> Path:
    text = str(raw or "").strip() or "~"
    path = Path(text).expanduser()
    if text.endswith(("/", "\\")) or text == "~" or path.is_dir():
        return path / EXPORT_NAME
    if path.suffix == "":
        return path / EXPORT_NAME
    return path


def _pem_certificate(value: Any) -> str:
    text = str(value or "").strip()
    if "BEGIN CERTIFICATE" not in text or "END CERTIFICATE" not in text:
        return ""
    if len(text.encode("utf-8")) > _MAX_BYTES:
        return ""
    return text if text.endswith("\n") else text + "\n"


def _read_cert(path: Path) -> str:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_BYTES:
            return ""
        return _pem_certificate(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return ""


def _instance_dirs(settings: Any) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {}
    for root in certificate_roots(settings):
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir() or child.is_symlink():
                continue
            found.setdefault(child.name, []).append(child)
    return found


def _material_text(value: Any, field: str) -> str:
    if field in {"ca_crt", "server_crt"}:
        return _pem_certificate(value)
    raw = str(value or "").strip()
    if not raw or len(raw.encode("utf-8")) > _MAX_BYTES:
        return ""
    if field == "tls_crypt":
        from agent.support.openvpn_config import normalize_tls_crypt

        raw = normalize_tls_crypt(raw).strip()
        if not raw:
            return ""
    elif "PRIVATE KEY" not in raw:
        return ""
    return raw if raw.endswith("\n") else raw + "\n"


def _read_material(path: Path, field: str) -> str:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_BYTES:
            return ""
        return _material_text(path.read_text(encoding="utf-8"), field)
    except (OSError, UnicodeDecodeError):
        return ""


def _material_in_dir(directory: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for name, field in _MATERIAL_FILES:
        text = _read_material(directory / name, field)
        if text:
            files[name] = text
    return files


def _dirs_for_server(settings: Any, server: dict[str, Any], discovered: dict[str, list[Path]]) -> list[Path]:
    instance = instance_name_for_server(server)
    sid = str(server.get("id") or "")
    names = {instance}
    if sid:
        names.add(f"openvpn-{sid}")
    explicit = str(server.get("name") or "").strip()
    if explicit:
        names.add(explicit)
    dirs: list[Path] = []
    seen: set[str] = set()

    def add(directory: Path) -> None:
        key = str(directory)
        if key in seen:
            return
        seen.add(key)
        dirs.append(directory)

    for name in names:
        for directory in discovered.get(name, []):
            add(directory)
    for root in certificate_roots(settings):
        if not root.is_dir() and root != certificate_roots(settings)[-1]:
            continue
        add(root / instance)
        if sid:
            alias = root / f"openvpn-{sid}"
            if alias.is_dir():
                add(alias)
    return dirs


def _server_files(server: dict[str, Any], directories: list[Path], *, prefer_disk: bool) -> dict[str, str]:
    from_doc: dict[str, str] = {}
    for name, field in _MATERIAL_FILES:
        text = _material_text(server.get(field), field)
        if text:
            from_doc[name] = text
    from_disk: dict[str, str] = {}
    for directory in directories:
        for name, text in _material_in_dir(directory).items():
            from_disk.setdefault(name, text)
    if prefer_disk:
        return {**from_doc, **from_disk}
    return {**from_disk, **from_doc}


def _openvpn_documents(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for row in documents:
        if str(row.get("core") or "") != "openvpn" or str(row.get("kind") or "") != "server":
            continue
        data = row.get("data")
        if isinstance(data, dict):
            rows.append(data)
    return rows


def attach_document_certificates(documents: list[dict[str, Any]], settings: Any) -> None:
    """Fill ca_crt / server_crt on snapshot rows from certificate files on disk."""
    discovered = _instance_dirs(settings)
    servers = _openvpn_documents(documents)
    for server in servers:
        files = _server_files(server, _dirs_for_server(settings, server, discovered), prefer_disk=True)
        for name, key in _CERT_FILES:
            text = _pem_certificate(files.get(name))
            if text:
                server[key] = text.strip()


def collect_bundle(documents: list[dict[str, Any]], settings: Any) -> dict[str, Any]:
    discovered = _instance_dirs(settings)
    servers = []
    for server in _openvpn_documents(documents):
        files = _server_files(server, _dirs_for_server(settings, server, discovered), prefer_disk=True)
        if not files:
            continue
        servers.append(
            {
                "id": server.get("id"),
                "instance": instance_name_for_server(server),
                "files": files,
            }
        )
    return {"version": BUNDLE_VERSION, "kind": BUNDLE_KIND, "servers": servers}


def _write_cert(path: Path, content: str, *, rewrite: bool) -> bool:
    if path.is_file() and not rewrite:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        path.chmod(0o644)
    except OSError:
        return False
    return True


def _private_material(server: dict[str, Any]) -> dict[str, str]:
    from agent.support.openvpn_config import normalize_tls_crypt

    files: dict[str, str] = {}
    for name, key in _KEY_FILES:
        raw = str(server.get(key) or "").strip()
        if key == "tls_crypt":
            raw = normalize_tls_crypt(raw)
        if raw:
            files[name] = raw if raw.endswith("\n") else raw + "\n"
    return files


def install_certificates(
    documents: list[dict[str, Any]],
    settings: Any,
    *,
    rewrite: bool,
    with_keys: bool = False,
) -> dict[str, int]:
    """Write ca.crt and server.crt into each OpenVPN instance directory.

    Server transfer also writes the matching private key and tls-crypt material
    so the certificate is not paired with a key generated on the new host.
    """
    discovered = _instance_dirs(settings)
    written = 0
    skipped = 0
    for server in _openvpn_documents(documents):
        targets = _dirs_for_server(settings, server, discovered)
        files = _server_files(server, targets, prefer_disk=False)
        secrets = _private_material(server) if with_keys else {}
        for directory in targets:
            for name, _key in _CERT_FILES:
                content = _pem_certificate(files.get(name))
                if not content:
                    continue
                if _write_cert(directory / name, content, rewrite=rewrite):
                    written += 1
                elif (directory / name).is_file():
                    skipped += 1
            for name, content in secrets.items():
                path = directory / name
                if _write_cert(path, content, rewrite=rewrite):
                    try:
                        path.chmod(0o600)
                    except OSError:
                        pass
                    written += 1
                elif path.is_file():
                    skipped += 1
        for name, key in _CERT_FILES:
            text = _pem_certificate(files.get(name))
            if text:
                server[key] = text.strip()
    return {"written": written, "skipped": skipped}


def _remember_store(store: Any, documents: list[dict[str, Any]]) -> None:
    from agent.asyncutil import run_sync

    async def _save() -> None:
        for row in documents:
            if str(row.get("core") or "") != "openvpn" or str(row.get("kind") or "") != "server":
                continue
            data = row.get("data")
            if not isinstance(data, dict) or data.get("id") is None:
                continue
            await store.put_doc("openvpn", "server", str(data.get("id")), data)

    run_sync(_save())


def _restart_instances(instances: list[str]) -> list[str]:
    if os.name != "posix" or shutil.which("systemctl") is None:
        return []
    restarted: list[str] = []
    for instance in instances:
        unit = f"openvpn-server@{instance}.service"
        try:
            proc = subprocess.run(
                ["systemctl", "restart", unit],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            restarted.append(instance)
    return restarted


def _archive_add(tar: tarfile.TarFile, name: str, content: str) -> None:
    payload = content.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o600 if name.endswith((".key",)) else 0o644
    tar.addfile(info, io.BytesIO(payload))


def _write_archive(path: Path, bundle: dict[str, Any]) -> None:
    allowed = {name for name, _field in _MATERIAL_FILES}
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        manifest = {
            "version": BUNDLE_VERSION,
            "kind": BUNDLE_KIND,
            "servers": [
                {"id": server.get("id"), "instance": server.get("instance")}
                for server in bundle["servers"]
            ],
        }
        _archive_add(tar, "manifest.json", json.dumps(manifest) + "\n")
        for server in bundle["servers"]:
            instance = str(server.get("instance") or "").strip()
            files = server.get("files") if isinstance(server.get("files"), dict) else {}
            for name, content in files.items():
                if name not in allowed or not str(content or "").strip():
                    continue
                _archive_add(tar, f"{instance}/{name}", str(content))
    path.chmod(0o600)


def _member_parts(name: str) -> tuple[str, str] | None:
    text = str(name or "").replace("\\", "/").lstrip("./")
    if not text or text.startswith("/") or ".." in text.split("/"):
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) != 2:
        return None
    instance, filename = parts
    allowed = {item for item, _field in _MATERIAL_FILES}
    if filename not in allowed:
        return None
    return instance, filename


def _read_archive(path: Path) -> dict[str, Any]:
    grouped: dict[str, dict[str, str]] = {}
    manifest: dict[str, Any] | None = None
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile() or member.size > _MAX_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                raw = handle.read(_MAX_BYTES + 1)
                if len(raw) > _MAX_BYTES:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if member.name.replace("\\", "/").endswith("manifest.json") and "/" not in member.name.replace("\\", "/").strip("/"):
                    parsed = json.loads(text)
                    if isinstance(parsed, dict):
                        manifest = parsed
                    continue
                parts = _member_parts(member.name)
                if parts is None:
                    continue
                instance, filename = parts
                grouped.setdefault(instance, {})[filename] = text
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise AgentError("VALIDATION_ERROR", f"Certificate archive could not be read: {exc}", 422) from exc
    if path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise AgentError("VALIDATION_ERROR", "Certificate archive is too large", 422)
    servers = []
    listed = manifest.get("servers") if isinstance(manifest, dict) else None
    if isinstance(listed, list) and listed:
        for item in listed:
            if not isinstance(item, dict):
                continue
            instance = str(item.get("instance") or "").strip()
            row = dict(item)
            row["files"] = grouped.get(instance, {})
            servers.append(row)
    else:
        for instance, files in grouped.items():
            servers.append({"instance": instance, "files": files})
    return {"version": BUNDLE_VERSION, "kind": BUNDLE_KIND, "servers": servers}


def export_bundle(store: Any, settings: Any, raw_path: str | None, *, rewrite: bool) -> dict[str, Any]:
    from agent.asyncutil import run_sync

    documents = run_sync(store.dump_documents())
    if not isinstance(documents, list):
        documents = []
    attach_document_certificates(documents, settings)
    bundle = collect_bundle(documents, settings)
    if not bundle["servers"]:
        raise AgentError("CONFIG_NOT_FOUND", "No OpenVPN certificates found to export", 404)
    path = resolve_export_path(raw_path)
    if path.exists() and not rewrite:
        raise AgentError("VALIDATION_ERROR", f"Refusing to overwrite {path}", 422)
    try:
        _write_archive(path, bundle)
    except OSError as exc:
        raise AgentError("EXEC_ERROR", f"Could not write {path}: {exc}", 500) from exc
    return {"path": str(path), "servers": len(bundle["servers"])}


def _bundle_documents(payload: dict[str, Any], existing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_instance: dict[str, dict[str, Any]] = {}
    for row in existing:
        if str(row.get("core") or "") != "openvpn" or str(row.get("kind") or "") != "server":
            continue
        data = row.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("id") is not None:
            by_id[str(data.get("id"))] = row
        by_instance[instance_name_for_server(data)] = row

    documents: list[dict[str, Any]] = []
    for item in payload.get("servers") or []:
        if not isinstance(item, dict):
            continue
        files = item.get("files") if isinstance(item.get("files"), dict) else {}
        material = {
            name: _material_text(files.get(name), field)
            for name, field in _MATERIAL_FILES
        }
        material = {name: text for name, text in material.items() if text}
        if not any(name.endswith(".crt") for name in material):
            continue
        sid = item.get("id")
        instance = str(item.get("instance") or "").strip()
        row = by_id.get(str(sid)) if sid is not None else None
        if row is None and instance:
            row = by_instance.get(instance)
        if row is None:
            data = {"id": sid, "instance": instance or (f"openvpn-{sid}" if sid is not None else "ovpn")}
            row = {"core": "openvpn", "kind": "server", "data": data}
        data = row["data"]
        if instance and not data.get("instance"):
            data["instance"] = instance
        for name, field in _MATERIAL_FILES:
            text = material.get(name)
            if text:
                data[field] = text.strip()
        if row not in documents and row not in existing:
            documents.append(row)
        elif row not in documents:
            documents.append(row)
    if not documents:
        raise AgentError("VALIDATION_ERROR", "Certificate bundle has no ca.crt or server.crt", 422)
    return documents


def import_bundle(store: Any, settings: Any, raw_path: str, *, rewrite: bool) -> dict[str, Any]:
    from agent.asyncutil import run_sync

    path = Path(str(raw_path or "").strip()).expanduser()
    if not path.is_file():
        raise AgentError("CONFIG_NOT_FOUND", f"Certificate bundle not found: {path}", 404)
    if path.name.endswith(".json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentError("VALIDATION_ERROR", f"Certificate bundle could not be read: {exc}", 422) from exc
    else:
        payload = _read_archive(path)
    if not isinstance(payload, dict) or payload.get("kind") != BUNDLE_KIND:
        raise AgentError("VALIDATION_ERROR", "File is not an OpenVPN certificate bundle", 422)
    try:
        version = int(payload.get("version") or 0)
    except (TypeError, ValueError) as exc:
        raise AgentError("VALIDATION_ERROR", "Certificate bundle version is invalid", 422) from exc
    if version != BUNDLE_VERSION:
        raise AgentError("VALIDATION_ERROR", "Certificate bundle version is not supported", 422)

    existing = run_sync(store.dump_documents())
    if not isinstance(existing, list):
        existing = []
    documents = _bundle_documents(payload, existing)
    result = install_certificates(documents, settings, rewrite=rewrite, with_keys=True)
    _remember_store(store, documents)
    instances = []
    for row in documents:
        data = row.get("data")
        if isinstance(data, dict):
            instances.append(instance_name_for_server(data))
    restarted = _restart_instances(instances)
    return {
        "path": str(path),
        "servers": len(documents),
        "written": result["written"],
        "skipped": result["skipped"],
        "restarted": restarted,
    }
