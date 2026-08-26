from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent.errors import AgentError
from agent.support import record_is_enabled
from agent.support.process import run

_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_IFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")


def _validation_error(message: str) -> AgentError:
    return AgentError("VALIDATION_ERROR", message)


def validate_wg_iface(iface: dict[str, Any]) -> None:
    name = str(iface.get("name") or "").strip()
    if not name or not _IFACE_NAME_RE.match(name):
        raise _validation_error(f"Invalid WireGuard interface name [{name!r}]")

    try:
        port = int(iface.get("listen_port", 0))
    except (TypeError, ValueError) as exc:
        raise _validation_error("listen_port must be an integer between 1 and 65535") from exc
    if port < 1 or port > 65535:
        raise _validation_error("listen_port must be between 1 and 65535")

    subnet = str(iface.get("subnet") or "").strip()
    if not subnet:
        raise _validation_error("subnet is required")
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise _validation_error(f"Invalid subnet [{subnet}]") from exc

    private_key = str(iface.get("private_key") or "").strip()
    if not private_key or not _WG_KEY_RE.match(private_key):
        raise _validation_error("Interface private_key is missing or invalid")

    public_key = str(iface.get("public_key") or "").strip()
    if public_key and not _WG_KEY_RE.match(public_key):
        raise _validation_error("Interface public_key is invalid")

    seen_ips: set[str] = set()
    for peer in iface.get("peers") or []:
        if not record_is_enabled(peer):
            continue
        pub = str(peer.get("public_key") or "").strip()
        if not pub or not _WG_KEY_RE.match(pub):
            raise _validation_error(f"Peer [{peer.get('id') or peer.get('email')}] has invalid public_key")
        allowed = str(peer.get("allowed_ips") or "").strip()
        if not allowed:
            raise _validation_error(f"Peer [{peer.get('id') or peer.get('email')}] is missing allowed_ips")
        for part in allowed.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise _validation_error(f"Peer allowed_ips contains invalid value [{part}]") from exc
        address = str(peer.get("address") or "").strip()
        if address:
            seen_ips.add(address.split("/", 1)[0])
        exit_iface = str(peer.get("exit_interface") or "").strip()
        if exit_iface and not _IFACE_NAME_RE.match(exit_iface):
            raise _validation_error(
                f"Peer [{peer.get('id') or peer.get('email')}] has invalid exit_interface [{exit_iface}]"
            )

def validate_wg_conf_stripped(
    conf_text: str,
    *,
    quick_bin: str,
    config_dir: Path,
) -> str:
    if not conf_text.strip():
        raise _validation_error("WireGuard config is empty")

    config_dir.mkdir(parents=True, exist_ok=True)
    # Pass an absolute .conf path. wg-quick/awg-quick look up a bare interface
    # name only in their default dir (/etc/wireguard or /etc/amnezia/amneziawg).
    fd, temp_path = tempfile.mkstemp(prefix="wgval", suffix=".conf", dir=str(config_dir))
    os.close(fd)
    try:
        Path(temp_path).write_text(conf_text, encoding="utf-8")
        strip = subprocess.run(
            [quick_bin, "strip", temp_path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if strip.returncode != 0 or not (strip.stdout or "").strip():
            detail = (strip.stderr or strip.stdout or "wg-quick strip failed").strip()
            raise _validation_error(f"WireGuard config rejected by wg-quick strip: {detail}")
        return strip.stdout
    finally:
        Path(temp_path).unlink(missing_ok=True)


def validate_xray_inbound(inbound: dict[str, Any]) -> None:
    protocol = str(inbound.get("protocol") or "").strip()
    if not protocol:
        raise _validation_error("Xray inbound protocol is required")

    port = inbound.get("port")
    if port is None:
        raise _validation_error("Xray inbound port is required")
    try:
        port_num = int(port)
    except (TypeError, ValueError) as exc:
        raise _validation_error("Xray inbound port must be an integer") from exc
    if port_num < 1 or port_num > 65535:
        raise _validation_error("Xray inbound port must be between 1 and 65535")

    tag = str(inbound.get("tag") or "").strip()
    if not tag:
        raise _validation_error("Xray inbound tag is required")

    settings = inbound.get("settings")
    if settings is not None and not isinstance(settings, dict):
        raise _validation_error("Xray inbound settings must be an object")

    if isinstance(settings, dict) and protocol.lower() in {"shadowsocks", "ss"}:
        method = str(settings.get("method") or "").strip()
        clients = settings.get("clients") or settings.get("users") or []
        if method == "":
            if "method" in settings and clients:
                settings.pop("method", None)
                if str(settings.get("password") or "").strip() == "":
                    settings.pop("password", None)
            elif "method" in settings or not clients:
                settings["method"] = "chacha20-ietf-poly1305"
        settings.setdefault("network", "tcp,udp")

    stream = inbound.get("streamSettings")
    if stream is not None and not isinstance(stream, dict):
        raise _validation_error("Xray inbound streamSettings must be an object")


def normalize_xray_policy(policy: Any) -> Any:
    """
    Xray expects policy.levels as a map keyed by level id (e.g. {"0": {...}}).
    PHP json_decode(..., true) and some editors turn that into a JSON array.
    """
    if not isinstance(policy, dict):
        return policy

    levels = policy.get("levels")
    if isinstance(levels, list):
        fixed = dict(policy)
        mapped: dict[str, Any] = {}
        for index, row in enumerate(levels):
            if isinstance(row, dict):
                mapped[str(index)] = row
        fixed["levels"] = mapped
        return fixed

    if isinstance(levels, dict):
        # Ensure keys stay strings after round-trips.
        fixed = dict(policy)
        fixed["levels"] = {str(key): value for key, value in levels.items() if isinstance(value, dict)}
        return fixed

    return policy


def normalize_xray_config_shapes(config: dict[str, Any]) -> dict[str, Any]:
    policy = config.get("policy")
    if policy is not None:
        config["policy"] = normalize_xray_policy(policy)
    return config


def validate_xray_config(binary: str, config: dict[str, Any]) -> None:
    if not binary:
        raise _validation_error("Xray binary not found for config validation")

    normalize_xray_config_shapes(config)

    # Repair blank Shadowsocks ciphers before xray -test (legacy broken inbounds).
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol") or "").strip().lower()
        if protocol not in {"shadowsocks", "ss"}:
            continue
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue
        method = str(settings.get("method") or "").strip()
        clients = settings.get("clients") or settings.get("users") or []
        if method == "":
            if "method" in settings and clients:
                settings.pop("method", None)
                if str(settings.get("password") or "").strip() == "":
                    settings.pop("password", None)
            elif "method" in settings or not clients:
                settings["method"] = "chacha20-ietf-poly1305"
        settings.setdefault("network", "tcp,udp")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(config, handle)
        temp_path = handle.name

    try:
        result = run([binary, "run", "-test", "-config", temp_path], check=False, timeout=60)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "xray run -test failed").strip()
            raise _validation_error(f"Xray config test failed: {detail}")
    finally:
        Path(temp_path).unlink(missing_ok=True)


def validate_xray_config_mutation(
    binary: str,
    config_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    if not config_path.is_file():
        validate_xray_config(binary, {"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": []})
        return

    config = json.loads(config_path.read_text(encoding="utf-8"))
    mutate(config)
    validate_xray_config(binary, config)
