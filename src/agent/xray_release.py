"""Download customized Xray-core binary from private GitHub Releases."""

from __future__ import annotations

import os
from pathlib import Path

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.update import (
    ReleaseInfo,
    detect_host_platform,
    download_release_asset,
    fetch_release_for_asset,
    resolve_repo,
)

DEFAULT_XRAY_REPO = "LordDeveloper/agent"
LEGACY_XRAY_REPO = "LordDeveloper/xray"

def resolve_xray_repo(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("XRAY_GITHUB_REPO")
        or DEFAULT_XRAY_REPO
    ).strip().strip("/")


def resolve_xray_asset_name(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip()
    env_asset = (os.environ.get("XRAY_GITHUB_ASSET") or "").strip()
    if env_asset:
        return env_asset
    host = detect_host_platform()
    return f"xray-linux-{host.libc}-{host.arch}"


def fetch_xray_release(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    timeout: float = 60.0,
) -> ReleaseInfo:
    wanted = resolve_xray_asset_name(asset_name)
    primary = resolve_xray_repo(repo)
    candidates = [primary]
    if primary == DEFAULT_XRAY_REPO and LEGACY_XRAY_REPO not in candidates:
        candidates.append(LEGACY_XRAY_REPO)

    last_error: AgentError | None = None
    for repo_id in candidates:
        try:
            return fetch_release_for_asset(
                repo=repo_id,
                asset_name=wanted,
                prefix="xray",
                token=token,
                timeout=timeout,
            )
        except AgentError as exc:
            last_error = exc
            if exc.code == "CONFIG_NOT_FOUND" and repo_id != candidates[-1]:
                continue
            raise

    if last_error is not None:
        raise last_error
    raise AgentError(
        "CONFIG_NOT_FOUND",
        f"No xray release asset [{wanted}] found in {', '.join(candidates)}.",
    )


def install_xray_binary(
    dest: Path,
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    timeout: float = 300.0,
) -> dict:
    """Download latest Xray release asset and install to dest (default: /usr/local/bin/xray)."""
    detect_host_platform()
    dest = Path(dest)
    release = fetch_xray_release(repo=repo, token=token, asset_name=asset_name)
    download_release_asset(release, dest, token=token, timeout=timeout)

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
        proc = run_cmd([str(dest), "version"], check=False)
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
        "api_base": os.environ.get("XRAY_API_BASE", "http://127.0.0.1:8080"),
    }


def xray_binary_present(binary: str | None = None) -> bool:
    path = binary or os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")
    return bool(which("xray") or Path(path).is_file())
