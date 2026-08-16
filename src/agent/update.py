"""Self-update from GitHub Releases (public or private)."""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from agent import __version__
from agent.errors import AgentError
from agent.ops import run_cmd, service_action, which

DEFAULT_REPO = "LordDeveloper/agent"
GITHUB_API = "https://api.github.com"


@dataclass(frozen=True)
class HostPlatform:
    arch: str  # amd64 | arm64
    libc: str  # gnu | musl

    @property
    def asset_name(self) -> str:
        return f"agent-linux-{self.libc}-{self.arch}"

    @property
    def alias_asset_name(self) -> str | None:
        # Legacy aliases only for glibc builds.
        if self.libc == "gnu":
            return f"agent-linux-{self.arch}"
        return None


def detect_arch(machine: str | None = None) -> str:
    value = (machine or platform.machine()).lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = mapping.get(value)
    if arch is None:
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"Unsupported CPU architecture [{value}]. Supported: amd64, arm64",
        )
    return arch


def detect_libc() -> str:
    # Prefer explicit override for testing / special images.
    forced = (os.environ.get("AGENT_LIBC") or "").strip().lower()
    if forced in {"gnu", "musl"}:
        return forced

    try:
        proc = run_cmd(["ldd", "--version"], check=False)
        blob = f"{proc.stdout or ''}\n{proc.stderr or ''}".lower()
        if "musl" in blob:
            return "musl"
    except OSError:
        pass

    # Alpine / musl loader paths
    lib = Path("/lib")
    if lib.is_dir():
        for path in lib.iterdir():
            name = path.name.lower()
            if name.startswith("ld-musl-") or name.startswith("libc.musl-"):
                return "musl"

    return "gnu"


def detect_host_platform() -> HostPlatform:
    if platform.system().lower() != "linux":
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"Self-update / release binaries support Linux only (got {platform.system()})",
        )
    return HostPlatform(arch=detect_arch(), libc=detect_libc())


def resolve_repo(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("AGENT_GITHUB_REPO")
        or DEFAULT_REPO
    ).strip().strip("/")


def resolve_token(explicit: str | None = None) -> str | None:
    token = (
        explicit
        or os.environ.get("AGENT_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or ""
    ).strip()
    return token or None


def resolve_asset_name(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip()
    env_asset = (os.environ.get("AGENT_GITHUB_ASSET") or "").strip()
    if env_asset:
        return env_asset
    return detect_host_platform().asset_name


def pick_release_asset(assets: list[dict], wanted: str) -> dict:
    by_name = {str(a.get("name")): a for a in assets}
    if wanted in by_name:
        return by_name[wanted]

    # Fallback: gnu alias ↔ canonical name
    fallbacks: list[str] = []
    if wanted.startswith("agent-linux-gnu-"):
        fallbacks.append(wanted.replace("agent-linux-gnu-", "agent-linux-", 1))
    elif wanted in {"agent-linux-amd64", "agent-linux-arm64"}:
        fallbacks.append(wanted.replace("agent-linux-", "agent-linux-gnu-", 1))

    for name in fallbacks:
        if name in by_name:
            return by_name[name]

    names = ", ".join(by_name) or "none"
    raise AgentError(
        "CONFIG_NOT_FOUND",
        f"Asset [{wanted}] missing from release. Available: {names}",
    )


@dataclass(frozen=True)
class ReleaseInfo:
    tag: str
    version: str
    asset_name: str
    asset_id: int
    asset_url: str
    html_url: str


def normalize_version(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    return text


def parse_version_tuple(value: str) -> tuple[int, ...]:
    cleaned = normalize_version(value).split("+", 1)[0].split("-", 1)[0]
    parts: list[int] = []
    for chunk in cleaned.split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def version_is_newer(candidate: str, current: str) -> bool:
    return parse_version_tuple(candidate) > parse_version_tuple(current)


def current_binary_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()

    packaged = Path("/opt/agent/bin/agent")
    if packaged.is_file():
        return packaged.resolve()

    raise AgentError(
        "UNSUPPORTED_CAPABILITY",
        "Self-update only works for the packaged binary (/opt/agent/bin/agent). "
        "Install a release build first, then run: agent update",
    )


def _auth_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"netinja-agent/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_latest_release(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    timeout: float = 60.0,
) -> ReleaseInfo:
    repo_id = resolve_repo(repo)
    auth = resolve_token(token)
    wanted = resolve_asset_name(asset_name)
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
            "or fine-grained token with Contents: Read on this repository).",
        )
    if response.status_code == 404:
        raise AgentError(
            "CONFIG_NOT_FOUND",
            f"Release not found for [{repo_id}]. Private repos require GITHUB_TOKEN; "
            "also ensure at least one published release with asset "
            f"[{wanted}].",
        )
    if response.status_code >= 400:
        raise AgentError(
            "UPSTREAM_ERROR",
            f"GitHub API error HTTP {response.status_code}: {response.text[:300]}",
        )

    payload = response.json()
    tag = str(payload.get("tag_name") or "")
    assets = payload.get("assets") or []
    match = pick_release_asset(assets, wanted)

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


def download_release_asset(
    release: ReleaseInfo,
    dest: Path,
    *,
    token: str | None = None,
    timeout: float = 300.0,
) -> Path:
    auth = resolve_token(token)
    headers = _auth_headers(auth)
    headers["Accept"] = "application/octet-stream"

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            with client.stream("GET", release.asset_url, headers=headers) as response:
                if response.status_code >= 400:
                    body = response.read().decode("utf-8", errors="replace")[:300]
                    raise AgentError(
                        "UPSTREAM_ERROR",
                        f"Asset download failed HTTP {response.status_code}: {body}",
                    )
                with tmp.open("wb") as fh:
                    for chunk in response.iter_bytes():
                        fh.write(chunk)
    except AgentError:
        tmp.unlink(missing_ok=True)
        raise
    except httpx.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise AgentError("UPSTREAM_ERROR", f"Asset download failed: {exc}") from exc

    tmp.chmod(0o755)
    os.replace(tmp, dest)
    return dest


def _assert_supported_host() -> HostPlatform:
    return detect_host_platform()


def apply_binary(new_binary: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_suffix(target.suffix + ".bak")
    if target.exists():
        shutil.copy2(target, backup)
    os.replace(new_binary, target)
    target.chmod(0o755)


def maybe_restart_service() -> dict | None:
    if not which("systemctl"):
        return None
    status = run_cmd(["systemctl", "is-active", "agent"], check=False)
    if (status.stdout or "").strip() != "active":
        return {"restarted": False, "reason": "service not active"}
    result = service_action("restart")
    return {"restarted": bool(result.get("ok")), **result}


def check_for_update(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    current: str | None = None,
) -> dict:
    host = detect_host_platform()
    release = fetch_latest_release(repo=repo, token=token, asset_name=asset_name)
    current_version = normalize_version(current or __version__)
    newer = version_is_newer(release.version, current_version)
    return {
        "current_version": current_version,
        "latest_version": release.version,
        "latest_tag": release.tag,
        "update_available": newer,
        "asset": release.asset_name,
        "platform": {"arch": host.arch, "libc": host.libc},
        "release_url": release.html_url,
        "repo": resolve_repo(repo),
    }


def perform_update(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    force: bool = False,
    restart: bool = True,
) -> dict:
    host = _assert_supported_host()
    binary = current_binary_path()
    release = fetch_latest_release(repo=repo, token=token, asset_name=asset_name)
    current_version = normalize_version(__version__)
    newer = version_is_newer(release.version, current_version)

    if not newer and not force:
        return {
            "updated": False,
            "current_version": current_version,
            "latest_version": release.version,
            "latest_tag": release.tag,
            "message": "Already up to date",
            "binary": str(binary),
            "platform": {"arch": host.arch, "libc": host.libc},
            "asset": release.asset_name,
        }

    with tempfile.TemporaryDirectory(prefix="agent-update-") as tmp:
        download_path = Path(tmp) / release.asset_name
        download_release_asset(release, download_path, token=token)
        apply_binary(download_path, binary)

    result: dict = {
        "updated": True,
        "previous_version": current_version,
        "installed_version": release.version,
        "installed_tag": release.tag,
        "binary": str(binary),
        "release_url": release.html_url,
        "forced": bool(force and not newer),
        "platform": {"arch": host.arch, "libc": host.libc},
        "asset": release.asset_name,
    }
    if restart:
        result["service"] = maybe_restart_service()
    return result
