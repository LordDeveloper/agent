"""Download Xray release zips from LordDeveloper/xray GitHub Releases."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.update import (
    ReleaseInfo,
    detect_arch,
    detect_host_platform,
    download_release_asset,
    fetch_release_for_asset,
    resolve_token,
)

DEFAULT_XRAY_REPO = "LordDeveloper/xray"
DEFAULT_GEO_DIR = Path("/usr/local/share/xray")

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


def _extract_xray_zip(archive: Path, dest_binary: Path, geo_dir: Path) -> list[str]:
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
        with zf.open(binary_member) as src, tmp.open("wb") as out:
            shutil.copyfileobj(src, out)
        tmp.chmod(0o755)
        os.replace(tmp, dest_binary)
        written.append(str(dest_binary))

        geo_dir.mkdir(parents=True, exist_ok=True)
        for geo_name in ("geoip.dat", "geosite.dat"):
            member = _pick_zip_member(names, geo_name)
            if member is None:
                continue
            target = geo_dir / geo_name
            with zf.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            written.append(str(target))

    return written


def install_xray_binary(
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
        download_release_asset(release, archive, token=resolve_token(token), timeout=timeout)
        geo_dir = Path(os.environ.get("XRAY_GEO_DIR") or DEFAULT_GEO_DIR)
        extracted = _extract_xray_zip(archive, dest, geo_dir)

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
        proc = run_cmd([str(dest), "version"], check=False, timeout=30)
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
