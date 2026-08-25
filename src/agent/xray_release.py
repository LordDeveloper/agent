"""Build customized Xray-core from LordDeveloper/xray source (no GitHub Releases / Actions assets)."""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

import httpx

from agent.errors import AgentError
from agent.ops import run_cmd, which
from agent.update import detect_arch, detect_host_platform, resolve_token

DEFAULT_XRAY_REPO = "LordDeveloper/xray"
DEFAULT_XRAY_REF = "main"
DEFAULT_SRC_DIR = Path("/opt/agent/src/xray")
DEFAULT_GO_ROOT = Path("/usr/local/go")
GEO_BASE = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release"
GEO_FILES = ("geoip.dat", "geosite.dat")
DEFAULT_GEO_DIR = Path("/usr/local/share/xray")


def resolve_xray_repo(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("XRAY_GITHUB_REPO")
        or DEFAULT_XRAY_REPO
    ).strip().strip("/")


def resolve_xray_ref(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("XRAY_GITHUB_REF")
        or os.environ.get("XRAY_GIT_REF")
        or DEFAULT_XRAY_REF
    ).strip() or DEFAULT_XRAY_REF


def resolve_xray_src_dir(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env = (os.environ.get("XRAY_SRC_DIR") or "").strip()
    if env:
        return Path(env)
    return DEFAULT_SRC_DIR


def _github_clone_url(repo: str, token: str | None) -> str:
    repo_id = repo.strip().strip("/")
    if token:
        return f"https://x-access-token:{token}@github.com/{repo_id}.git"
    return f"https://github.com/{repo_id}.git"


def _public_repo_url(repo: str) -> str:
    return f"https://github.com/{repo.strip().strip('/')}"


def _ensure_linux() -> None:
    detect_host_platform()


def _ensure_git() -> str:
    path = which("git")
    if path:
        return path
    if which("apt-get"):
        run_cmd(["apt-get", "update", "-y"], check=False, timeout=120)
        run_cmd(["apt-get", "install", "-y", "git", "ca-certificates"], check=False, timeout=300)
        path = which("git")
        if path:
            return path
    raise AgentError(
        "VALIDATION_ERROR",
        "git is required to build Xray from source. Install git and retry.",
    )


def _parse_go_mod_version(go_mod: Path) -> str | None:
    if not go_mod.is_file():
        return None
    try:
        text = go_mod.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"(?m)^go\s+(\d+(?:\.\d+)*)\s*$", text)
    return match.group(1) if match else None


def _go_version_tuple(value: str) -> tuple[int, ...]:
    cleaned = value.strip().lstrip("go")
    parts: list[int] = []
    for chunk in cleaned.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _installed_go_version(go_bin: str) -> str | None:
    try:
        proc = run_cmd([go_bin, "version"], check=False, timeout=30)
    except OSError:
        return None
    blob = f"{proc.stdout or ''} {proc.stderr or ''}"
    match = re.search(r"go(\d+(?:\.\d+)*)", blob)
    return match.group(1) if match else None


def _go_bin_candidates() -> list[str]:
    found: list[str] = []
    for candidate in (
        which("go"),
        str(DEFAULT_GO_ROOT / "bin" / "go"),
        "/usr/local/go/bin/go",
    ):
        if candidate and candidate not in found and Path(candidate).is_file():
            found.append(candidate)
    return found


def _download_go_toolchain(version: str, arch: str, dest_root: Path = DEFAULT_GO_ROOT) -> str:
    """Install official Go toolchain under /usr/local/go and return go binary path."""
    go_arch = "arm64" if arch == "arm64" else "amd64"
    if arch not in {"amd64", "arm64"}:
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            f"Automatic Go install supports amd64/arm64 only (got {arch}). Install Go manually.",
        )

    url = f"https://go.dev/dl/go{version}.linux-{go_arch}.tar.gz"
    dest_root.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="go-toolchain-") as tmp:
        archive = Path(tmp) / f"go{version}.linux-{go_arch}.tar.gz"
        try:
            with httpx.Client(timeout=300.0, follow_redirects=True) as client:
                with client.stream("GET", url) as response:
                    if response.status_code >= 400:
                        body = response.read().decode("utf-8", errors="replace")[:200]
                        raise AgentError(
                            "UPSTREAM_ERROR",
                            f"Go download failed HTTP {response.status_code} from {url}: {body}",
                        )
                    with archive.open("wb") as handle:
                        for chunk in response.iter_bytes():
                            handle.write(chunk)
        except AgentError:
            raise
        except httpx.HTTPError as exc:
            raise AgentError("UPSTREAM_ERROR", f"Go download failed: {exc}") from exc

        extract_dir = Path(tmp) / "extract"
        extract_dir.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(extract_dir)

        extracted = extract_dir / "go"
        if not extracted.is_dir():
            raise AgentError("UPSTREAM_ERROR", f"Go archive from {url} did not contain go/")

        if dest_root.exists():
            shutil.rmtree(dest_root)
        shutil.move(str(extracted), str(dest_root))

    go_bin = dest_root / "bin" / "go"
    if not go_bin.is_file():
        raise AgentError("UPSTREAM_ERROR", f"Go binary missing after install: {go_bin}")
    return str(go_bin)


def ensure_go(*, required: str | None = None) -> str:
    """
    Return a usable `go` binary path.
    If missing/too old, install official toolchain from go.dev (not GitHub Actions).
    """
    wanted = (required or os.environ.get("XRAY_GO_VERSION") or "").strip() or None
    host_arch = detect_arch()

    for candidate in _go_bin_candidates():
        installed = _installed_go_version(candidate)
        if installed is None:
            continue
        if wanted is None or _go_version_tuple(installed) >= _go_version_tuple(wanted):
            return candidate

    # Prefer exact go.mod version; if unavailable, try major.minor with latest patch via go.dev.
    version = wanted or "1.22.0"
    try:
        return _download_go_toolchain(version, host_arch)
    except AgentError:
        # go.mod may list a toolchain not yet on go.dev mirrors as X.Y (need X.Y.Z).
        if re.fullmatch(r"\d+\.\d+", version):
            return _download_go_toolchain(f"{version}.0", host_arch)
        raise


def sync_xray_repo(
    src_dir: Path,
    *,
    repo: str | None = None,
    ref: str | None = None,
    token: str | None = None,
) -> dict:
    """Clone or update LordDeveloper/xray source tree."""
    _ensure_linux()
    git = _ensure_git()
    repo_id = resolve_xray_repo(repo)
    git_ref = resolve_xray_ref(ref)
    auth = resolve_token(token)
    clone_url = _github_clone_url(repo_id, auth)

    src_dir = Path(src_dir)
    src_dir.parent.mkdir(parents=True, exist_ok=True)
    git_dir = src_dir / ".git"

    env = os.environ.copy()
    # Avoid interactive prompts; token is already in URL when present.
    env["GIT_TERMINAL_PROMPT"] = "0"

    if git_dir.is_dir():
        # Refresh existing checkout.
        run_cmd(
            [git, "-C", str(src_dir), "remote", "set-url", "origin", clone_url],
            check=False,
            timeout=60,
            env=env,
        )
        proc = run_cmd(
            [git, "-C", str(src_dir), "fetch", "--depth", "1", "origin", git_ref],
            check=False,
            timeout=300,
            env=env,
        )
        if proc.returncode != 0:
            # Fall back to full fetch of ref (tag/branch).
            proc = run_cmd(
                [git, "-C", str(src_dir), "fetch", "origin", git_ref],
                check=False,
                timeout=600,
                env=env,
            )
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()[:500]
                raise AgentError(
                    "UPSTREAM_ERROR",
                    f"git fetch failed for [{repo_id}@{git_ref}]: {detail or 'unknown error'}",
                )
        checkout = None
        for target in ("FETCH_HEAD", f"origin/{git_ref}", git_ref):
            checkout = run_cmd(
                [git, "-C", str(src_dir), "checkout", "-f", target],
                check=False,
                timeout=60,
                env=env,
            )
            if checkout.returncode == 0:
                break
        if checkout is None or checkout.returncode != 0:
            detail = ((checkout.stderr if checkout else None) or (checkout.stdout if checkout else None) or "").strip()[:500]
            raise AgentError(
                "UPSTREAM_ERROR",
                f"git checkout failed for [{repo_id}@{git_ref}]: {detail or 'unknown error'}",
            )
        run_cmd(
            [git, "-C", str(src_dir), "reset", "--hard", "HEAD"],
            check=False,
            timeout=60,
            env=env,
        )
        action = "updated"
    else:
        if src_dir.exists():
            shutil.rmtree(src_dir)
        proc = run_cmd(
            [git, "clone", "--depth", "1", "--branch", git_ref, clone_url, str(src_dir)],
            check=False,
            timeout=600,
            env=env,
        )
        if proc.returncode != 0:
            # branch flag fails for bare SHAs — clone default then checkout.
            if src_dir.exists():
                shutil.rmtree(src_dir)
            proc = run_cmd(
                [git, "clone", clone_url, str(src_dir)],
                check=False,
                timeout=900,
                env=env,
            )
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()[:500]
                hint = ""
                if not auth:
                    hint = " Private repos require GITHUB_TOKEN (Contents: Read)."
                raise AgentError(
                    "UPSTREAM_ERROR",
                    f"git clone failed for [{repo_id}]: {detail or 'unknown error'}.{hint}",
                )
            checkout = run_cmd(
                [git, "-C", str(src_dir), "checkout", "-f", git_ref],
                check=False,
                timeout=60,
                env=env,
            )
            if checkout.returncode != 0:
                detail = (checkout.stderr or checkout.stdout or "").strip()[:500]
                raise AgentError(
                    "UPSTREAM_ERROR",
                    f"git checkout [{git_ref}] failed: {detail or 'unknown error'}",
                )
        action = "cloned"

    # Drop credentials from remote URL after sync.
    run_cmd(
        [git, "-C", str(src_dir), "remote", "set-url", "origin", _public_repo_url(repo_id) + ".git"],
        check=False,
        timeout=30,
        env=env,
    )

    head = run_cmd([git, "-C", str(src_dir), "rev-parse", "--short", "HEAD"], check=False, timeout=30)
    commit = (head.stdout or "").strip() or None
    return {
        "repo": repo_id,
        "ref": git_ref,
        "src_dir": str(src_dir),
        "commit": commit,
        "action": action,
        "url": _public_repo_url(repo_id),
    }


def _build_commit_id(src_dir: Path) -> str:
    git = which("git")
    if not git:
        return "unknown"
    proc = run_cmd(
        [git, "-C", str(src_dir), "describe", "--always", "--dirty"],
        check=False,
        timeout=30,
    )
    return (proc.stdout or "").strip() or "unknown"


def build_xray_binary(src_dir: Path, output: Path, *, go_bin: str | None = None) -> Path:
    """Compile ./main into output (same flags as LordDeveloper/xray release workflow, locally)."""
    src_dir = Path(src_dir)
    if not (src_dir / "main").is_dir() or not (src_dir / "go.mod").is_file():
        raise AgentError(
            "CONFIG_NOT_FOUND",
            f"Xray source tree incomplete at [{src_dir}] (expected go.mod and main/).",
        )

    required = _parse_go_mod_version(src_dir / "go.mod")
    go = go_bin or ensure_go(required=required)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    commit = _build_commit_id(src_dir)
    ldflags = (
        f"-X github.com/xtls/xray-core/core.build={commit} "
        f"-s -w -buildid="
    )
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    # Prefer the toolchain we resolved.
    go_path = Path(go)
    if go_path.parent.is_dir():
        env["PATH"] = f"{go_path.parent}{os.pathsep}{env.get('PATH', '')}"

    proc = run_cmd(
        [
            go,
            "build",
            "-o",
            str(output),
            "-trimpath",
            "-buildvcs=false",
            "-gcflags=all=-l=4",
            f"-ldflags={ldflags}",
            "-v",
            "./main",
        ],
        check=False,
        timeout=float(os.environ.get("XRAY_BUILD_TIMEOUT", "900")),
        cwd=str(src_dir),
        env=env,
    )
    if proc.returncode != 0 or not output.is_file():
        detail = (proc.stderr or proc.stdout or "").strip()[:800]
        raise AgentError(
            "UPSTREAM_ERROR",
            f"go build failed for Xray: {detail or 'unknown error'}",
        )

    output.chmod(0o755)
    return output


def ensure_xray_geodata(geo_dir: Path | None = None, *, timeout: float = 120.0) -> list[str]:
    """Best-effort download of geoip/geosite into Xray share dir."""
    target = Path(geo_dir or os.environ.get("XRAY_GEO_DIR") or DEFAULT_GEO_DIR)
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for name in GEO_FILES:
                dest = target / name
                if dest.is_file() and dest.stat().st_size > 0:
                    written.append(str(dest))
                    continue
                response = client.get(f"{GEO_BASE}/{name}")
                if response.status_code >= 400:
                    continue
                dest.write_bytes(response.content)
                written.append(str(dest))
    except httpx.HTTPError:
        return written
    return written


def install_xray_binary(
    dest: Path,
    *,
    repo: str | None = None,
    token: str | None = None,
    ref: str | None = None,
    src_dir: str | Path | None = None,
    timeout: float = 900.0,
) -> dict:
    """
    Clone LordDeveloper/xray and build the binary on this host.
    Does not download GitHub Release / Actions artifacts.
    """
    _ensure_linux()
    dest = Path(dest)
    source = resolve_xray_src_dir(src_dir)
    # Allow callers / env to stretch build budget (first go mod download is slow).
    os.environ.setdefault("XRAY_BUILD_TIMEOUT", str(int(timeout)))
    sync = sync_xray_repo(source, repo=repo, ref=ref, token=token)

    with tempfile.TemporaryDirectory(prefix="xray-build-") as tmp:
        built = Path(tmp) / "xray"
        build_xray_binary(source, built)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp_dest = dest.with_suffix(dest.suffix + ".partial")
        shutil.copy2(built, tmp_dest)
        tmp_dest.chmod(0o755)
        os.replace(tmp_dest, dest)

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

    geodata = ensure_xray_geodata()

    version: str | None = None
    try:
        proc = run_cmd([str(dest), "version"], check=False, timeout=30)
        version = (proc.stdout or proc.stderr or "").strip().split("\n")[0] or None
    except OSError:
        version = sync.get("commit")

    return {
        "core": "xray",
        "installed": True,
        "downloaded": True,
        "built_from_source": True,
        "binary": str(dest),
        "version": version,
        "release_tag": sync.get("ref"),
        "release_version": sync.get("commit"),
        "commit": sync.get("commit"),
        "ref": sync.get("ref"),
        "src_dir": sync.get("src_dir"),
        "repo": sync.get("repo"),
        "repo_url": sync.get("url"),
        "geodata": geodata,
        "api_base": os.environ.get("XRAY_API_BASE", "http://127.0.0.1:8080"),
        "source": "git",
    }


def xray_binary_present(binary: str | None = None) -> bool:
    path = binary or os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")
    return bool(which("xray") or Path(path).is_file())
