"""Manage pp-forward sidecar for Xray inbounds with acceptProxyProtocol."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.config import AgentSettings, load_settings
from agent.logutil import get_logger

log = get_logger("pp-forward")

_PROXY_STREAM_KEYS = (
    "tcpSettings",
    "wsSettings",
    "httpSettings",
    "grpcSettings",
    "kcpSettings",
    "quicSettings",
)


@dataclass(frozen=True)
class ForwardRule:
    listen: str
    target: str
    tag: str = ""

    def as_dict(self) -> dict[str, str]:
        row = {"listen": self.listen, "target": self.target}
        if self.tag:
            row["tag"] = self.tag
        return row


def inbound_accepts_proxy_protocol(inbound: dict[str, Any]) -> bool:
    stream = inbound.get("streamSettings")
    if not isinstance(stream, dict):
        return False
    for key in _PROXY_STREAM_KEYS:
        settings = stream.get(key)
        if isinstance(settings, dict) and settings.get("acceptProxyProtocol"):
            return True
    return False


def _bind_host(listen: str) -> str:
    value = str(listen or "").strip() or "0.0.0.0"
    if value in {"::", "[::]"}:
        return "0.0.0.0"
    return value


def _target_host(listen: str) -> str:
    value = _bind_host(listen)
    if value in {"0.0.0.0", ""}:
        return "127.0.0.1"
    if value.startswith("127."):
        return value
    return "127.0.0.1"


def rules_from_inbounds(inbounds: list[dict[str, Any]]) -> list[ForwardRule]:
    rules: list[ForwardRule] = []
    seen_listen: set[str] = set()

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if not inbound_accepts_proxy_protocol(inbound):
            continue

        try:
            port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port <= 1 or port > 65535:
            continue

        listen_host = _bind_host(str(inbound.get("listen") or "0.0.0.0"))
        listen_port = port - 1
        listen = f"{listen_host}:{listen_port}"
        if listen in seen_listen:
            tag = str(inbound.get("tag") or "")
            log.warning("skip duplicate proxy forward listen=%s tag=%s", listen, tag)
            continue
        seen_listen.add(listen)

        target = f"{_target_host(listen_host)}:{port}"
        rules.append(
            ForwardRule(
                listen=listen,
                target=target,
                tag=str(inbound.get("tag") or ""),
            )
        )

    return rules


def resolve_pp_forward_binary(settings: AgentSettings | None = None) -> Path | None:
    settings = settings or load_settings()

    explicit = str(getattr(settings, "proxy_protocol_forwarder_binary", "") or "").strip()
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return path

    if getattr(sys, "frozen", False):
        bundled = Path(getattr(sys, "_MEIPASS", "")) / "pp-forward"
        if bundled.is_file():
            return bundled

    argv0 = Path(sys.argv[0]).resolve()
    sibling = argv0.parent / "pp-forward"
    if sibling.is_file():
        return sibling

    for candidate in (
        Path("/opt/agent/bin/pp-forward"),
        Path.cwd() / "dist" / "pp-forward",
        Path(__file__).resolve().parents[3] / "dist" / "pp-forward",
    ):
        if candidate.is_file():
            return candidate

    return None


class ProxyProtocolForwarderManager:
    def __init__(self, settings: AgentSettings | None = None):
        self.settings = settings or load_settings()
        self._proc: subprocess.Popen[str] | None = None
        self._config_path = Path(self.settings.data_dir) / "pp-forward.json"
        self._lock_path = Path(self.settings.data_dir) / "pp-forward.lock"

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.settings, "proxy_protocol_forwarder_enabled", True))

    def config_path(self) -> Path:
        return self._config_path

    def stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    proc.kill()
                proc.wait(timeout=3)
        log.info("pp-forward stopped")

    def sync_rules(self, rules: list[ForwardRule]) -> dict[str, Any]:
        if not self.enabled:
            self.stop()
            return {"enabled": False, "rules": 0, "running": False}

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"rules": [rule.as_dict() for rule in rules]}
        self._config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        if not rules:
            self.stop()
            return {"enabled": True, "rules": 0, "running": False, "config": str(self._config_path)}

        binary = resolve_pp_forward_binary(self.settings)
        if binary is None:
            log.warning("pp-forward binary not found; proxy protocol listeners disabled")
            self.stop()
            return {
                "enabled": True,
                "rules": len(rules),
                "running": False,
                "error": "binary_not_found",
                "config": str(self._config_path),
            }

        self._restart(binary)
        return {
            "enabled": True,
            "rules": len(rules),
            "running": self._proc is not None and self._proc.poll() is None,
            "binary": str(binary),
            "config": str(self._config_path),
        }

    def _restart(self, binary: Path) -> None:
        self.stop()
        cmd = [
            str(binary),
            "serve",
            "--config",
            str(self._config_path),
            "--lock",
            str(self._lock_path),
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            log.warning("pp-forward start failed: %s", exc)
            self._proc = None
            return

        time.sleep(0.05)
        if self._proc.poll() is not None:
            output = ""
            if self._proc.stdout is not None:
                output = self._proc.stdout.read() or ""
            log.warning("pp-forward exited early code=%s output=%s", self._proc.returncode, output.strip())
            self._proc = None
            return

        log.info("pp-forward started pid=%s rules=%s", self._proc.pid, self._config_path)


_manager: ProxyProtocolForwarderManager | None = None


def get_forwarder_manager(settings: AgentSettings | None = None) -> ProxyProtocolForwarderManager:
    global _manager
    if _manager is None or (settings is not None and settings is not _manager.settings):
        _manager = ProxyProtocolForwarderManager(settings)
    return _manager


def sync_forwarders_from_inbounds(
    inbounds: list[dict[str, Any]],
    *,
    settings: AgentSettings | None = None,
) -> dict[str, Any]:
    rules = rules_from_inbounds(inbounds)
    result = get_forwarder_manager(settings).sync_rules(rules)
    log.info(
        "pp-forward sync rules=%s running=%s",
        result.get("rules"),
        result.get("running"),
    )
    return result


def stop_forwarders(settings: AgentSettings | None = None) -> None:
    get_forwarder_manager(settings).stop()
