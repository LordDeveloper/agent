from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from pathlib import Path

from agent.errors import AgentError

KNOWN_CORES = ("xray", "wireguard", "amnezia")


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_cmd(
    args: list[str],
    check: bool = True,
    *,
    timeout: float = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )


def _prepare_xray_service(result: dict) -> dict:
    try:
        from agent.xray_service import ensure_xray_running

        # Keep-alive semantics: start only when inactive (never bounce a live unit).
        result["service"] = ensure_xray_running(
            binary=str(result.get("binary") or os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")),
            api_base=str(result.get("api_base") or os.environ.get("XRAY_API_BASE", "http://127.0.0.1:8080")),
        )
    except AgentError as exc:
        result["service_error"] = exc.message
    return result


def install_xray(
    *,
    github_token: str | None = None,
    force: bool = False,
    tag: str | None = None,
) -> dict:
    """
    Install customized Xray from LordDeveloper/xray GitHub Releases
    (host-matched Xray-linux-*.zip). Optional tag installs that release instead of latest.
    """
    from agent.xray_release import install_xray_binary
    from agent.xray_service import binary_has_httpapi, stop_xray_service

    binary = os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")
    dest = Path(binary)
    ready = dest.is_file() and binary_has_httpapi(dest)
    had_stock = dest.is_file() and not ready
    if ready and not force and not tag:
        return _prepare_xray_service({
            "core": "xray",
            "installed": True,
            "downloaded": False,
            "httpapi_capable": True,
            "message": "customized xray binary present",
            "binary": str(dest),
            "api_base": os.environ.get("XRAY_API_BASE", "http://127.0.0.1:8080"),
        })

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AgentError(
            "VALIDATION_ERROR",
            f"Cannot create directory for XRAY_BINARY [{dest.parent}]: {exc}",
        ) from exc

    if dest.is_file():
        try:
            stop_xray_service()
        except AgentError:
            pass

    result = install_xray_binary(dest, token=github_token, tag=tag)
    result["replaced_stock"] = had_stock
    result["httpapi_capable"] = binary_has_httpapi(dest)
    if dest.is_file() and not result["httpapi_capable"]:
        raise AgentError(
            "UNSUPPORTED_CAPABILITY",
            "Downloaded Xray binary still has no HTTP API. "
            "Confirm LordDeveloper/xray release zip is the customized fork "
            "(not stock XTLS), and GITHUB_TOKEN can read that repo if private.",
        )
    result = _prepare_xray_service(result)
    return result


def install_wireguard() -> dict:
    if which("wg"):
        return {"core": "wireguard", "installed": True, "message": "already installed"}
    if which("apt-get"):
        run_cmd(["apt-get", "update", "-y"], check=False)
        run_cmd(["apt-get", "install", "-y", "wireguard"], check=False)
    if not which("wg"):
        raise AgentError("VALIDATION_ERROR", "wireguard tools (wg) not available after install")
    return {"core": "wireguard", "installed": True, "message": "installed"}


def install_amnezia(*, github_token: str | None = None, force: bool = False) -> dict:
    from agent.amnezia_release import amnezia_bundle_present, install_amnezia_bundle

    if amnezia_bundle_present() and not force:
        return {
            "core": "amnezia",
            "installed": True,
            "downloaded": False,
            "message": "amneziawg bundle present",
        }

    return install_amnezia_bundle(token=github_token, force=force)


INSTALLERS = {
    "xray": install_xray,
    "wireguard": install_wireguard,
    "amnezia": install_amnezia,
}


def install_core(
    name: str,
    *,
    github_token: str | None = None,
    force: bool = False,
    tag: str | None = None,
) -> dict:
    key = name.strip().lower()
    installer = INSTALLERS.get(key)
    if installer is None:
        raise AgentError("CONFIG_NOT_FOUND", f"Unknown core [{name}]. Known: {', '.join(KNOWN_CORES)}")
    if key == "xray":
        return installer(github_token=github_token, force=force, tag=tag)
    if key == "amnezia":
        return installer(github_token=github_token, force=force)
    return installer()


def write_env_file(
    path: Path,
    *,
    listen: str,
    token: str,
    data_dir: str,
    cores: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        [
            f"LISTEN={listen}",
            f"AUTH_TOKEN={token}",
            f"DATA_DIR={data_dir}",
            f"DB_PATH={Path(data_dir) / 'agent.db'}",
            f"ENABLED_CORES={','.join(cores)}",
            "XRAY_API_BASE=http://127.0.0.1:8080",
            "XRAY_BINARY=/usr/local/bin/xray",
            "XRAY_CONFIG=/usr/local/etc/xray/config.json",
            "WIREGUARD_CONFIG_DIR=/etc/wireguard",
            "AMNEZIA_CONFIG_DIR=/etc/amneziawg",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def generate_token(nbytes: int = 32) -> str:
    if nbytes < 16 or nbytes > 128:
        raise AgentError("VALIDATION_ERROR", "token size must be between 16 and 128 bytes")
    return secrets.token_hex(nbytes)


def set_env_value(path: Path, key: str, value: str) -> dict:
    """Create or update a KEY=value line in an env file. Preserves other lines."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()

    prefix = f"{key}="
    replaced = False
    out: list[str] = []
    for line in lines:
        if line.startswith(prefix) or line.startswith(f"export {prefix}"):
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        if out and out[-1].strip() != "":
            out.append("")
        out.append(f"{key}={value}")

    text = "\n".join(out).rstrip() + "\n"
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return {"path": str(path), "key": key, "updated": replaced, "created": not replaced}


def systemd_unit_path() -> Path:
    return Path("/etc/systemd/system/agent.service")


def default_unit_text() -> str:
    return """[Unit]
Description=Netinja node agent API
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/agent/.env
WorkingDirectory=/opt/agent
ExecStart=/opt/agent/bin/agent serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def service_action(action: str) -> dict:
    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not found (Linux systemd required)")
    if action == "install":
        unit = systemd_unit_path()
        unit.write_text(default_unit_text(), encoding="utf-8")
        run_cmd(["systemctl", "daemon-reload"], check=False)
        run_cmd(["systemctl", "enable", "agent"], check=False)
        return {"action": "install", "unit": str(unit), "ok": True}
    if action == "uninstall":
        run_cmd(["systemctl", "stop", "agent"], check=False)
        run_cmd(["systemctl", "disable", "agent"], check=False)
        unit = systemd_unit_path()
        if unit.exists():
            unit.unlink()
        run_cmd(["systemctl", "daemon-reload"], check=False)
        return {"action": "uninstall", "ok": True}

    allowed = {"start", "stop", "restart", "status", "enable", "disable"}
    if action not in allowed:
        raise AgentError("VALIDATION_ERROR", f"Unknown service action [{action}]")
    proc = run_cmd(["systemctl", action, "agent"], check=False)
    return {
        "action": action,
        "ok": proc.returncode == 0,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
        "code": proc.returncode,
    }


def service_is_active() -> bool:
    if not which("systemctl"):
        return False
    proc = run_cmd(["systemctl", "is-active", "agent"], check=False)
    return (proc.stdout or "").strip() == "active"


def service_logs(limit: int = 16) -> list[str]:
    if not which("journalctl"):
        return []
    proc = run_cmd(
        ["journalctl", "-u", "agent", "-n", str(max(1, limit)), "--no-pager", "-o", "short-iso"],
        check=False,
    )
    return [line.rstrip() for line in (proc.stdout or "").splitlines() if line.strip()]
