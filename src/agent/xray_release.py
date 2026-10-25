"""Download Xray release zips from LordDeveloper/xray GitHub Releases."""

from __future__ import annotations

import base64
import os
import tempfile
import zipfile
from pathlib import Path

import aiofiles
import aiofiles.os
import httpx

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.support import aiofs
from agent.update import (
    ReleaseInfo,
    detect_arch,
    detect_host_platform,
    fetch_release_for_asset,
    resolve_token,
)

DEFAULT_XRAY_REPO = "LordDeveloper/xray"
DEFAULT_GEO_DIR = Path("/usr/local/share/xray")
GEODATA_NAMES = ("geosite.dat", "geoip.dat")
GEODATA_URLS = {
    "geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    "geoip.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
}
_GEODATA_MAX_BYTES = 40_000_000

# Matches LordDeveloper/xray release asset names (friendly-filenames / Actions output).
ASSET_BY_ARCH = {
    "amd64": "Xray-linux-64.zip",
    "arm64": "Xray-linux-arm64-v8a.zip",
    "386": "Xray-linux-32.zip",
}


def resolve_xray_repo(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("XRAY_GITHUB_REPO")
        or DEFAULT_XRAY_REPO
    ).strip().strip("/")


def resolve_xray_tag(explicit: str | None = None) -> str | None:
    """None means GitHub /releases/latest."""
    raw = (
        explicit
        if explicit is not None
        else (os.environ.get("XRAY_GITHUB_TAG") or os.environ.get("XRAY_RELEASE_TAG") or "")
    )
    tag = str(raw or "").strip()
    if not tag or tag.lower() in {"latest", "default"}:
        return None
    if tag.lower().startswith("tags/"):
        tag = tag.split("/", 1)[1].strip()
    return tag or None


def resolve_xray_asset_name(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip()
    env_asset = (os.environ.get("XRAY_GITHUB_ASSET") or "").strip()
    if env_asset:
        return env_asset

    host = detect_host_platform()
    asset = ASSET_BY_ARCH.get(host.arch)
    if asset is None:
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"No Xray release zip mapped for arch [{host.arch}]. "
            "Set XRAY_GITHUB_ASSET (e.g. Xray-linux-64.zip).",
        )
    return asset


def fetch_xray_release(
    *,
    repo: str | None = None,
    token: str | None = None,
    tag: str | None = None,
    asset_name: str | None = None,
    timeout: float = 60.0,
) -> ReleaseInfo:
    wanted = resolve_xray_asset_name(asset_name)
    repo_id = resolve_xray_repo(repo)
    release_tag = resolve_xray_tag(tag)
    return fetch_release_for_asset(
        repo=repo_id,
        asset_name=wanted,
        prefix="Xray",
        token=token,
        tag=release_tag,
        timeout=timeout,
    )


def _pick_zip_member(names: list[str], filename: str) -> str | None:
    exact = [name for name in names if Path(name).name == filename and not name.endswith("/")]
    if not exact:
        return None
    # Prefer shallowest path (root of zip).
    exact.sort(key=lambda name: name.count("/"))
    return exact[0]


async def _download_release_asset(
    release: ReleaseInfo,
    dest: Path,
    *,
    token: str | None = None,
    timeout: float = 300.0,
) -> Path:
    auth = resolve_token(token)
    headers = {"Accept": "application/octet-stream", "User-Agent": "netinja-agent"}
    if auth:
        headers["Authorization"] = f"Bearer {auth}"

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            async with client.stream("GET", release.asset_url, headers=headers) as response:
                if response.status_code >= 400:
                    body = (await response.aread()).decode("utf-8", errors="replace")[:300]
                    raise AgentError(
                        "UPSTREAM_ERROR",
                        f"Asset download failed HTTP {response.status_code}: {body}",
                    )
                async with aiofiles.open(tmp, "wb") as handle:
                    async for chunk in response.aiter_bytes():
                        await handle.write(chunk)
    except AgentError:
        tmp.unlink(missing_ok=True)
        raise
    except httpx.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise AgentError("UPSTREAM_ERROR", f"Asset download failed: {exc}") from exc

    await aiofs.chmod(tmp, 0o755)
    await aiofiles.os.replace(tmp, dest)
    return dest


async def _extract_xray_zip(archive: Path, dest_binary: Path, geo_dir: Path) -> list[str]:
    written: list[str] = []
    with zipfile.ZipFile(archive, "r") as zf:
        names = zf.namelist()
        binary_member = _pick_zip_member(names, "xray")
        if binary_member is None:
            raise AgentError(
                "CONFIG_NOT_FOUND",
                f"Xray zip [{archive.name}] has no 'xray' binary. Members: {', '.join(names[:12]) or 'none'}",
            )

        dest_binary.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest_binary.with_suffix(dest_binary.suffix + ".partial")
        with zf.open(binary_member) as src:
            data = src.read()
        await aiofs.write_bytes(tmp, data)
        await aiofs.chmod(tmp, 0o755)
        await aiofiles.os.replace(tmp, dest_binary)
        written.append(str(dest_binary))

        geo_dir.mkdir(parents=True, exist_ok=True)
        for geo_name in ("geoip.dat", "geosite.dat"):
            member = _pick_zip_member(names, geo_name)
            if member is None:
                continue
            target = geo_dir / geo_name
            with zf.open(member) as src:
                geo_data = src.read()
            await aiofs.write_bytes(target, geo_data)
            written.append(str(target))

    return written


async def install_xray_binary(
    dest: Path,
    *,
    repo: str | None = None,
    token: str | None = None,
    tag: str | None = None,
    asset_name: str | None = None,
    timeout: float = 300.0,
) -> dict:
    """
    Download the host-matched Xray-linux-*.zip from LordDeveloper/xray Releases
    and install the binary (+ geodata when present in the zip).
    """
    detect_host_platform()
    dest = Path(dest)
    release = fetch_xray_release(
        repo=repo,
        token=token,
        tag=tag,
        asset_name=asset_name,
    )

    with tempfile.TemporaryDirectory(prefix="xray-release-") as tmp:
        archive = Path(tmp) / release.asset_name
        await _download_release_asset(release, archive, token=resolve_token(token), timeout=timeout)
        geo_dir = Path(os.environ.get("XRAY_GEO_DIR") or DEFAULT_GEO_DIR)
        extracted = await _extract_xray_zip(archive, dest, geo_dir)

    placed = await ensure_xray_geodata(dest, download=True)
    if placed:
        extracted.extend(str(placed / name) for name in GEODATA_NAMES if (placed / name).is_file())

    if dest != Path("/usr/local/bin/xray") and not which("xray"):
        bin_dir = Path("/usr/local/bin")
        if bin_dir.is_dir():
            link = bin_dir / "xray"
            try:
                if link.is_symlink() or link.is_file():
                    link.unlink()
                link.symlink_to(dest.resolve())
            except OSError:
                pass

    version: str | None = None
    try:
        proc = await run_cmd([str(dest), "version"], check=False, timeout=30)
        version = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or None
    except OSError:
        version = release.version

    return {
        "core": "xray",
        "installed": True,
        "downloaded": True,
        "binary": str(dest),
        "version": version,
        "release_tag": release.tag,
        "release_version": release.version,
        "asset": release.asset_name,
        "release_url": release.html_url,
        "repo": resolve_xray_repo(repo),
        "tag": release.tag,
        "extracted": extracted,
        "arch": detect_arch(),
        "api_base": os.environ.get("XRAY_API_BASE", "http://127.0.0.1:8080"),
        "source": "release",
    }


def xray_binary_present(binary: str | None = None) -> bool:
    path = binary or os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")
    return bool(which("xray") or Path(path).is_file())


def xray_binary_path() -> Path:
    return Path(os.environ.get("XRAY_BINARY", "/usr/local/bin/xray"))


def _unique_dirs(directories: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for directory in directories:
        key = str(directory)
        if key in seen:
            continue
        seen.add(key)
        unique.append(directory)
    return unique


def geodata_dirs(binary: Path | None = None) -> list[Path]:
    """Directories Xray or a previous install may already keep geodata in."""
    binary = binary or xray_binary_path()
    configured = Path(os.environ.get("XRAY_GEO_DIR") or DEFAULT_GEO_DIR)
    return _unique_dirs([binary.parent, configured, DEFAULT_GEO_DIR, Path("/usr/share/xray")])


def geodata_write_dirs(binary: Path | None = None) -> list[Path]:
    """Where a transfer or install is allowed to create geodata files."""
    binary = binary or xray_binary_path()
    configured = Path(os.environ.get("XRAY_GEO_DIR") or DEFAULT_GEO_DIR)
    return _unique_dirs([binary.parent, configured])


async def _copy_geodata(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    await aiofs.write_bytes(tmp, await aiofs.read_bytes(src))
    await aiofiles.os.replace(tmp, dest)


def _find_geodata(name: str, binary: Path) -> Path | None:
    for directory in geodata_dirs(binary):
        path = directory / name
        if path.is_file() and path.stat().st_size > 0:
            return path
    return None


async def _download_geodata(name: str, dest: Path) -> bool:
    url = GEODATA_URLS.get(name)
    if not url:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            async with client.stream("GET", url, headers={"User-Agent": "netinja-agent"}) as response:
                if response.status_code >= 400:
                    return False
                async with aiofiles.open(tmp, "wb") as handle:
                    async for chunk in response.aiter_bytes():
                        await handle.write(chunk)
        size = (await aiofiles.os.stat(str(tmp))).st_size
        if size <= 0 or size > _GEODATA_MAX_BYTES:
            tmp.unlink(missing_ok=True)
            return False
        await aiofiles.os.replace(tmp, dest)
        return True
    except (OSError, httpx.HTTPError):
        tmp.unlink(missing_ok=True)
        return False


async def ensure_xray_geodata(binary: Path | None = None, *, download: bool = True) -> Path | None:
    """Put geosite.dat and geoip.dat next to the Xray binary.

    Xray's config test looks beside the executable (/usr/local/bin), while the
    release zip is extracted to /usr/local/share/xray.
    """
    binary = Path(binary or xray_binary_path())
    if not binary.is_file():
        resolved = which(binary.name) or which("xray")
        if not resolved:
            return None
        binary = Path(resolved)

    asset = binary.parent
    for name in GEODATA_NAMES:
        target = asset / name
        if target.is_file() and target.stat().st_size > 0:
            continue
        found = _find_geodata(name, binary)
        if found is not None and found.resolve() != target.resolve():
            await _copy_geodata(found, target)
            continue
        if download:
            await _download_geodata(name, target)

    for name in GEODATA_NAMES:
        src = asset / name
        if not src.is_file():
            continue
        for directory in geodata_write_dirs(binary):
            if directory == asset:
                continue
            dest = directory / name
            if dest.is_file() and dest.stat().st_size > 0:
                continue
            try:
                await _copy_geodata(src, dest)
            except OSError:
                continue

    if any((asset / name).is_file() for name in GEODATA_NAMES):
        return asset
    return None


def export_geodata() -> dict:
    files: list[dict[str, str]] = []
    seen: set[str] = set()
    for directory in geodata_dirs():
        for name in GEODATA_NAMES:
            if name in seen:
                continue
            path = directory / name
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size <= 0 or size > _GEODATA_MAX_BYTES:
                continue
            files.append({
                "name": name,
                "content_b64": base64.b64encode(path.read_bytes()).decode("ascii"),
            })
            seen.add(name)
    return {"files": files}


def import_geodata(files: list[dict]) -> dict:
    written: list[str] = []
    asset = xray_binary_path().parent
    for item in files:
        if not isinstance(item, dict):
            raise AgentError("VALIDATION_ERROR", "geodata entries must be objects")
        name = str(item.get("name") or "").strip()
        if name not in GEODATA_NAMES:
            raise AgentError("VALIDATION_ERROR", f"geodata name is not allowed: {name}")
        raw = item.get("content_b64")
        if not isinstance(raw, str) or raw.strip() == "":
            raise AgentError("VALIDATION_ERROR", f"geodata content is empty: {name}")
        try:
            content = base64.b64decode(raw, validate=True)
        except (ValueError, TypeError) as exc:
            raise AgentError("VALIDATION_ERROR", f"geodata content is not base64: {name}") from exc
        if not content or len(content) > _GEODATA_MAX_BYTES:
            raise AgentError("VALIDATION_ERROR", f"geodata file is empty or too large: {name}")
        for directory in geodata_write_dirs():
            try:
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(target.suffix + ".partial")
                tmp.write_bytes(content)
                os.replace(tmp, target)
                written.append(str(target))
            except OSError:
                if directory == asset:
                    raise
    return {"written": written, "count": len({Path(path).name for path in written})}
