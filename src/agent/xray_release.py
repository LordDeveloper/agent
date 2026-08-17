"""Download customized Xray-core binary from private GitHub Releases."""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from agent import __version__
from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.update import (
    ReleaseInfo,
    detect_host_platform,
    download_release_asset,
    normalize_version,
    pick_release_asset,
    resolve_token,
)

DEFAULT_XRAY_REPO = "LordDeveloper/xray"
GITHUB_API = "https://api.github.com"


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


def _auth_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"netinja-agent/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_xray_release(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    timeout: float = 60.0,
) -> ReleaseInfo:
    repo_id = resolve_xray_repo(repo)
    auth = resolve_token(token)
    wanted = resolve_xray_asset_name(asset_name)
    url = f"{GITHUB_API}/repos/{repo_id}/releases/latest"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url, headers=_auth_headers(auth))
    except httpx.HTTPError as exc:
        raise AgentError("UPSTREAM_ERROR", f"GitHub request failed: {exc}") from exc

    if response.status_code == 401:
        raise AgentError(
            "UNAUTHORIZED",
            "GitHub rejected credentials. Set GITHUB_TOKEN (classic PAT with repo scope, "
            "or fine-grained token with Contents: Read on LordDeveloper/xray).",
        )
    if response.status_code == 404:
        raise AgentError(
            "CONFIG_NOT_FOUND",
            f"Release not found for [{repo_id}]. Private repo requires GITHUB_TOKEN; "
            f"ensure a published release includes asset [{wanted}].",
        )
    if response.status_code >= 400:
        raise AgentError(
            "UPSTREAM_ERROR",
            f"GitHub API error HTTP {response.status_code}: {response.text[:300]}",
        )

    payload = response.json()
    tag = str(payload.get("tag_name") or "")
    assets = payload.get("assets") or []
    match = pick_release_asset(assets, wanted, prefix="xray")

    asset_id = int(match["id"])
    chosen_name = str(match.get("name") or wanted)
    return ReleaseInfo(
        tag=tag,
        version=normalize_version(tag),
        asset_name=chosen_name,
        asset_id=asset_id,
        asset_url=f"{GITHUB_API}/repos/{repo_id}/releases/assets/{asset_id}",
        html_url=str(payload.get("html_url") or ""),
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
