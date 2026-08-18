"""Download AmneziaWG bundle (awg, awg-quick, amneziawg-go) from agent GitHub Releases."""

from __future__ import annotations

import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.update import (
    detect_host_platform,
    download_release_asset,
    fetch_release_for_asset,
    resolve_repo,
    resolve_token,
)

DEFAULT_AMNEZIAWG_GO_TAG = "v3.1.20260814"
BIN_NAMES = ("awg", "awg-quick", "amneziawg-go")
DEFAULT_BIN_DIR = Path("/usr/local/bin")


def resolve_amnezia_asset_name(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip()
    env_asset = (os.environ.get("AMNEZIAWG_GITHUB_ASSET") or "").strip()
    if env_asset:
        return env_asset
    host = detect_host_platform()
    return f"amneziawg-linux-{host.libc}-{host.arch}.tar.gz"


def _bin_path(name: str, bin_dir: Path) -> Path | None:
    direct = bin_dir / name
    if direct.is_file():
        return direct
    resolved = which(name)
    return Path(resolved) if resolved else None


def amnezia_bundle_present(bin_dir: Path | None = None) -> bool:
    target = bin_dir or DEFAULT_BIN_DIR
    return all(_bin_path(name, target) is not None for name in BIN_NAMES)


def install_amnezia_bundle(
    *,
    repo: str | None = None,
    token: str | None = None,
    asset_name: str | None = None,
    bin_dir: Path | None = None,
    force: bool = False,
    timeout: float = 300.0,
) -> dict:
    """Download amneziawg-linux-*.tar.gz from agent release and install CLI binaries."""
    detect_host_platform()
    dest_dir = Path(bin_dir or os.environ.get("AMNEZIAWG_BIN_DIR", str(DEFAULT_BIN_DIR)))

    if amnezia_bundle_present(dest_dir) and not force:
        return {
            "core": "amnezia",
            "installed": True,
            "downloaded": False,
            "message": "amneziawg bundle already present",
            "bin_dir": str(dest_dir),
        }

    release = fetch_release_for_asset(
        repo=resolve_repo(repo),
        asset_name=resolve_amnezia_asset_name(asset_name),
        prefix="amneziawg",
        token=token,
    )

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AgentError(
            "VALIDATION_ERROR",
            f"Cannot create AmneziaWG bin directory [{dest_dir}]: {exc}",
        ) from exc

    installed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="amneziawg-install-") as tmp:
        archive = Path(tmp) / release.asset_name
        download_release_asset(release, archive, token=resolve_token(token), timeout=timeout)

        with tarfile.open(archive, "r:gz") as tar:
            names = {member.name for member in tar.getmembers() if member.isfile()}
            missing = [name for name in BIN_NAMES if name not in names]
            if missing:
                raise AgentError(
                    "CONFIG_NOT_FOUND",
                    f"AmneziaWG archive [{release.asset_name}] missing: {', '.join(missing)}",
                )
            extract_kw: dict = {}
            if sys.version_info >= (3, 12):
                extract_kw["filter"] = "data"
            for name in BIN_NAMES:
                tar.extract(name, path=tmp, **extract_kw)
                src = Path(tmp) / name
                target = dest_dir / name
                shutil.copy2(src, target)
                target.chmod(0o755)
                installed.append(str(target))

    link = dest_dir / "amneziawg"
    if not link.exists():
        try:
            link.symlink_to("amneziawg-go")
        except OSError:
            pass

    version: str | None = None
    awg = dest_dir / "awg"
    if awg.is_file():
        try:
            proc = run_cmd([str(awg), "--version"], check=False)
            version = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or None
        except OSError:
            version = None

    return {
        "core": "amnezia",
        "installed": True,
        "downloaded": True,
        "bin_dir": str(dest_dir),
        "binaries": installed,
        "version": version,
        "release_tag": release.tag,
        "release_version": release.version,
        "asset": release.asset_name,
        "release_url": release.html_url,
        "repo": resolve_repo(repo),
        "amneziawg_go_tag": os.environ.get("AMNEZIAWG_GO_TAG", DEFAULT_AMNEZIAWG_GO_TAG),
    }
