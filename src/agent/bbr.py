"""BBR congestion-control management (install, enable, disable, status)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent.errors import AgentError
from agent.logutil import get_logger

log = get_logger('bbr')

BBR_SYSCTL_PATH = Path('/etc/sysctl.d/99-netinja-bbr.conf')
BBR_MODULE_PATH = Path('/etc/modules-load.d/netinja-bbr.conf')
BBR_SETTINGS = {
    'net.core.default_qdisc': 'fq',
    'net.ipv4.tcp_congestion_control': 'bbr',
}
DISABLED_QDISC = 'pfifo_fast'
DISABLED_CC = 'cubic'


def _run(args: list[str], *, timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def _require_linux() -> None:
    if not sys.platform.startswith('linux'):
        raise AgentError('UNSUPPORTED_CAPABILITY', 'BBR management requires Linux with sysctl support')


def _require_root() -> None:
    geteuid = getattr(os, 'geteuid', None)
    if geteuid is None or geteuid() != 0:
        raise AgentError('VALIDATION_ERROR', 'BBR management requires root (run with sudo)')


def _read_sysctl(key: str) -> str:
    proc = _run(['sysctl', '-n', key], timeout=10)
    if proc.returncode != 0:
        return ''
    return (proc.stdout or '').strip()


def _module_loaded() -> bool:
    return Path('/sys/module/tcp_bbr').is_dir()


def _kernel_supports_bbr() -> bool:
    available = _read_sysctl('net.ipv4.tcp_available_congestion_control')
    return 'bbr' in {part.strip() for part in available.split() if part.strip()}


def _persisted_settings() -> dict[str, str]:
    if not BBR_SYSCTL_PATH.is_file():
        return {}
    out: dict[str, str] = {}
    for line in BBR_SYSCTL_PATH.read_text(encoding='utf-8').splitlines():
        text = line.strip()
        if not text or text.startswith('#') or '=' not in text:
            continue
        key, value = text.split('=', 1)
        out[key.strip()] = value.strip()
    return out


def bbr_status() -> dict[str, Any]:
    _require_linux()
    current_cc = _read_sysctl('net.ipv4.tcp_congestion_control')
    current_qdisc = _read_sysctl('net.core.default_qdisc')
    available = _read_sysctl('net.ipv4.tcp_available_congestion_control')
    supported = _kernel_supports_bbr()
    enabled = current_cc == 'bbr'
    return {
        'supported': supported,
        'enabled': enabled,
        'module_loaded': _module_loaded(),
        'module_configured': BBR_MODULE_PATH.is_file(),
        'persisted': BBR_SYSCTL_PATH.is_file(),
        'persisted_settings': _persisted_settings(),
        'current': {
            'tcp_congestion_control': current_cc or None,
            'default_qdisc': current_qdisc or None,
        },
        'available_congestion_control': [part for part in available.split() if part],
    }


def _write_module_load() -> dict[str, Any]:
    previous = BBR_MODULE_PATH.read_text(encoding='utf-8') if BBR_MODULE_PATH.is_file() else ''
    content = '# Managed by Netinja agent\n' + 'tcp_bbr\n'
    written = False
    if previous != content:
        BBR_MODULE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BBR_MODULE_PATH.write_text(content, encoding='utf-8')
        written = True
    return {'path': str(BBR_MODULE_PATH), 'written': written}


def _write_sysctl(settings: dict[str, str]) -> dict[str, Any]:
    lines = ['# Managed by Netinja agent — BBR tuning']
    for key, value in settings.items():
        lines.append(f'{key}={value}')
    content = '\n'.join(lines) + '\n'
    previous = BBR_SYSCTL_PATH.read_text(encoding='utf-8') if BBR_SYSCTL_PATH.is_file() else ''
    written = False
    if previous != content:
        BBR_SYSCTL_PATH.parent.mkdir(parents=True, exist_ok=True)
        BBR_SYSCTL_PATH.write_text(content, encoding='utf-8')
        written = True
    return {'path': str(BBR_SYSCTL_PATH), 'written': written}


def _load_module() -> dict[str, Any]:
    if _module_loaded():
        return {'loaded': True, 'modprobe': False}
    modprobe = shutil.which('modprobe')
    if not modprobe:
        raise AgentError('VALIDATION_ERROR', 'modprobe not found; cannot load tcp_bbr module')
    proc = _run([modprobe, 'tcp_bbr'], timeout=30)
    if proc.returncode != 0 and not _module_loaded():
        detail = (proc.stderr or proc.stdout or '').strip()[:300]
        raise AgentError('VALIDATION_ERROR', f'Failed to load tcp_bbr: {detail or "unknown error"}')
    return {'loaded': _module_loaded(), 'modprobe': True}


def bbr_install(*, apply: bool = False) -> dict[str, Any]:
    """Prepare tcp_bbr module persistence and sysctl drop-in."""
    _require_linux()
    _require_root()
    if not _kernel_supports_bbr():
        loaded = _load_module()
        if not _kernel_supports_bbr():
            raise AgentError(
                'UNSUPPORTED_CAPABILITY',
                'Kernel does not expose BBR (upgrade kernel or enable CONFIG_TCP_CONGESTION_BBR)',
            )
    else:
        loaded = _load_module()

    module = _write_module_load()
    sysctl = _write_sysctl(BBR_SETTINGS)
    applied: dict[str, str] | None = None
    if apply:
        applied = _apply_sysctl(BBR_SETTINGS)
    return {
        'installed': True,
        'module': loaded,
        'module_file': module,
        'sysctl_file': sysctl,
        'applied': applied,
        'settings': dict(BBR_SETTINGS),
    }


def _apply_sysctl(settings: dict[str, str]) -> dict[str, str]:
    applied: dict[str, str] = {}
    for key, value in settings.items():
        proc = _run(['sysctl', '-w', f'{key}={value}'], timeout=15)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or '').strip()[:200]
            raise AgentError('VALIDATION_ERROR', f'Failed to apply {key}={value}: {detail or "unknown error"}')
        applied[key] = value
    return applied


def bbr_enable() -> dict[str, Any]:
    _require_linux()
    _require_root()
    install = bbr_install(apply=False)
    applied = _apply_sysctl(BBR_SETTINGS)
    _write_sysctl(BBR_SETTINGS)
    status = bbr_status()
    return {
        'enabled': status['enabled'],
        'installed': True,
        'module': install['module'],
        'sysctl_file': install['sysctl_file'],
        'applied': applied,
    }


def bbr_disable(*, remove_persistence: bool = False) -> dict[str, Any]:
    _require_linux()
    _require_root()
    applied = _apply_sysctl(
        {
            'net.ipv4.tcp_congestion_control': DISABLED_CC,
            'net.core.default_qdisc': DISABLED_QDISC,
        }
    )
    removed: list[str] = []
    if remove_persistence:
        for path in (BBR_SYSCTL_PATH, BBR_MODULE_PATH):
            if path.is_file():
                path.unlink()
                removed.append(str(path))
    elif BBR_SYSCTL_PATH.is_file():
        BBR_SYSCTL_PATH.unlink()
        removed.append(str(BBR_SYSCTL_PATH))

    status = bbr_status()
    return {
        'enabled': status['enabled'],
        'applied': applied,
        'removed_files': removed,
        'tcp_congestion_control': status['current']['tcp_congestion_control'],
    }
