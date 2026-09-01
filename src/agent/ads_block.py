"""Ads-blocking DNS filter for WireGuard / Amnezia clients via AdGuard Home."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from agent.adguard import (
    ADGUARD_CONFIG,
    ADS_ENABLED_MARKER,
    adguard_service_active,
    adguard_service_diagnostic,
    ensure_adguard_resolver,
    ensure_adguard_service,
)
from agent.dns_leak import (
    discover_vpn_interfaces,
    dns_leak_status,
    ensure_vpn_dns_resolver,
    teardown_vpn_dns_if_unused,
)
from agent.errors import AgentError
from agent.logutil import get_logger
from agent.support.process import run

log = get_logger('ads_block')

ADS_LIST_PATH = Path('/var/lib/agent/ads-blocklist.txt')

Runner = Callable[..., Any]


def _require_linux() -> None:
    if not sys.platform.startswith('linux'):
        raise AgentError('UNSUPPORTED_CAPABILITY', 'Ads DNS filter requires Linux')


def _require_root() -> None:
    geteuid = getattr(os, 'geteuid', None)
    if geteuid is None or geteuid() != 0:
        raise AgentError('VALIDATION_ERROR', 'Ads DNS filter requires root (run with sudo)')


def _load_user_rules() -> list[str]:
    rules: list[str] = []
    seen: set[str] = set()
    if not ADS_LIST_PATH.is_file():
        return rules
    try:
        for line in ADS_LIST_PATH.read_text(encoding='utf-8', errors='ignore').splitlines():
            domain = line.strip().lower().rstrip('.')
            if not domain or domain.startswith('#'):
                continue
            if any(ch.isspace() for ch in domain):
                continue
            rule = f'||{domain}^'
            if rule in seen:
                continue
            seen.add(rule)
            rules.append(rule)
    except OSError:
        pass
    return rules


def _vpn_dns_addresses(*, runner: Runner | None = None) -> list[str]:
    addrs: list[str] = []
    try:
        interfaces = discover_vpn_interfaces(runner=runner)
    except AgentError:
        interfaces = []
    for row in interfaces:
        gateway = str(row.get('gateway') or '').strip()
        if gateway:
            addrs.append(gateway)
    return list(dict.fromkeys(addrs))


def _firewall_backend() -> str | None:
    if shutil.which('nft'):
        return 'nft'
    if shutil.which('iptables'):
        return 'iptables'
    return None


def ads_block_prerequisites(*, runner: Runner | None = None) -> dict[str, Any]:
    if not sys.platform.startswith('linux'):
        return {
            'linux': False,
            'root': False,
            'adguard_installed': False,
            'adguard_active': False,
            'adguard_configured': False,
            'ads_enabled': False,
            'firewall_backend': None,
            'nft': False,
            'iptables': False,
            'dig': bool(shutil.which('dig')),
            'apt': bool(shutil.which('apt-get')),
            'vpn_interfaces': [],
            'vpn_interface_count': 0,
            'dns_leak_active': False,
            'adguard_error': None,
            'ready': False,
        }

    vpn_ifaces = discover_vpn_interfaces(runner=runner)
    backend = _firewall_backend()
    adguard_bin = bool(shutil.which('AdGuardHome')) or Path('/var/lib/agent/adguard/AdGuardHome').is_file()
    geteuid = getattr(os, 'geteuid', None)
    is_root = geteuid is not None and geteuid() == 0
    adguard_active = adguard_service_active(runner=runner) if adguard_bin else False
    adguard_error = None
    if adguard_bin and not adguard_active:
        adguard_error = adguard_service_diagnostic(runner=runner)

    dns_leak: dict[str, Any] = {}
    try:
        dns_leak = dns_leak_status(runner=runner)
    except AgentError:
        pass

    return {
        'linux': True,
        'root': is_root,
        'adguard_installed': adguard_bin,
        'adguard_active': adguard_active,
        'adguard_configured': ADGUARD_CONFIG.is_file(),
        'ads_enabled': ADS_ENABLED_MARKER.is_file(),
        'firewall_backend': backend,
        'nft': bool(shutil.which('nft')),
        'iptables': bool(shutil.which('iptables')),
        'dig': bool(shutil.which('dig')),
        'apt': bool(shutil.which('apt-get')),
        'vpn_interfaces': vpn_ifaces,
        'vpn_interface_count': len(vpn_ifaces),
        'dns_leak_active': bool(dns_leak.get('active')),
        'adguard_error': adguard_error,
        'ready': (
            adguard_bin
            and adguard_active
            and backend is not None
            and len(vpn_ifaces) > 0
        ),
    }


def ads_block_repair_service(*, runner: Runner | None = None) -> dict[str, Any]:
    """Try to start AdGuard Home and fix systemd-resolved port-53 conflicts."""
    _require_linux()
    _require_root()

    service = ensure_adguard_service(runner=runner)
    payload = ads_block_prerequisites(runner=runner)
    payload.update({'ok': bool(service.get('active')), 'service': service})
    if not service.get('active'):
        message = str(service.get('diagnostic') or service.get('journal') or '').strip()
        if not message:
            unit = str(service.get('unit_enabled') or 'unknown')
            message = f'AdGuard Home failed to start (unit: {unit})'
        raise AgentError('VALIDATION_ERROR', message)
    return payload


def ads_block_install_prerequisites(*, runner: Runner | None = None) -> dict[str, Any]:
    """Install AdGuard Home and dnsutils required for WireGuard ads blocking."""
    _require_linux()
    _require_root()

    from agent.adguard import install_adguard_binary

    installed: list[str] = []
    if install_adguard_binary(runner=runner):
        installed.append('adguardhome')
    else:
        raise AgentError(
            'UNSUPPORTED_CAPABILITY',
            'AdGuard Home is not installed and automatic download failed; install manually',
        )

    if not shutil.which('dig'):
        apt = shutil.which('apt-get')
        if apt is not None:
            execute = runner or run
            proc = execute([apt, 'install', '-y', '-qq', 'dnsutils'], check=False, timeout=300)
            if proc.returncode == 0 and shutil.which('dig'):
                installed.append('dnsutils')

    try:
        ADS_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not ADS_LIST_PATH.is_file():
            ADS_LIST_PATH.write_text('# Extra ads domains (one per line)\n', encoding='utf-8')
    except OSError as exc:
        raise AgentError('VALIDATION_ERROR', f'Cannot prepare ads list path: {exc}') from exc

    service = ensure_adguard_service(runner=runner)

    payload = ads_block_prerequisites(runner=runner)
    payload.update(
        {
            'ok': True,
            'installed': installed,
            'adguard_restarted': bool((service or {}).get('active')),
            'service': service,
        }
    )
    return payload


def ads_block_test(
    domain: str = 'doubleclick.net',
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Resolve a known ad domain via the suggested VPN DNS address."""
    _require_linux()
    execute = runner or run
    host = str(domain or '').strip().lower().rstrip('.')
    if host == '':
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    status = ads_block_status(runner=runner)
    dns = str(status.get('dns') or '').strip()
    if dns == '':
        raise AgentError(
            'VALIDATION_ERROR',
            'No VPN gateway DNS address detected; start WireGuard/Amnezia and retry',
        )

    if not shutil.which('dig'):
        raise AgentError('UNSUPPORTED_CAPABILITY', 'dig is required (install dnsutils)')

    proc = execute(['dig', '+time=2', '+tries=1', '+short', f'@{dns}', host], check=False, timeout=15)
    answer = (getattr(proc, 'stdout', '') or '').strip().splitlines()
    first = answer[0].strip() if answer else ''
    blocked = first in {'', '0.0.0.0'}

    return {
        'ok': True,
        'domain': host,
        'dns': dns,
        'answer': first or None,
        'blocked': blocked,
        'exit_code': getattr(proc, 'returncode', 1),
    }


def ads_block_status(*, runner: Runner | None = None) -> dict[str, Any]:
    dns_list = _vpn_dns_addresses(runner=runner)
    prereq = ads_block_prerequisites(runner=runner)
    return {
        'enabled': ADS_ENABLED_MARKER.is_file(),
        'marker': str(ADS_ENABLED_MARKER),
        'list_path': str(ADS_LIST_PATH),
        'custom_rules': len(_load_user_rules()) if ADS_ENABLED_MARKER.is_file() else 0,
        'dns': dns_list[0] if dns_list else None,
        'listen_dns': dns_list[0] if dns_list else None,
        'dns_candidates': dns_list,
        'adguard': bool(prereq.get('adguard_installed')),
        'adguard_active': prereq.get('adguard_active'),
        'adguard_configured': prereq.get('adguard_configured'),
        'adguard_config': str(ADGUARD_CONFIG),
        'firewall_backend': prereq.get('firewall_backend'),
        'vpn_interface_count': prereq.get('vpn_interface_count'),
        'ready': prereq.get('ready'),
        'prerequisites': prereq,
    }


def ads_block_ensure(*, runner: Runner | None = None) -> dict[str, Any]:
    _require_linux()
    _require_root()

    from agent.adguard import install_adguard_binary

    if not install_adguard_binary(runner=runner):
        raise AgentError(
            'UNSUPPORTED_CAPABILITY',
            'AdGuard Home is required for ads DNS filtering (run: agent ads-block install)',
        )

    ADS_ENABLED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    ADS_ENABLED_MARKER.write_text('enabled\n', encoding='utf-8')

    if not ADS_LIST_PATH.is_file():
        try:
            ADS_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            ADS_LIST_PATH.write_text('# Extra ads domains (one per line)\n', encoding='utf-8')
        except OSError:
            pass

    user_rules = _load_user_rules()
    vpn_ifaces = discover_vpn_interfaces(runner=runner)
    resolver: dict[str, Any] | None = None
    restarted = False

    if vpn_ifaces:
        try:
            resolver = ensure_vpn_dns_resolver(
                interfaces=vpn_ifaces,
                block_ipv6=False,
                filtering_enabled=True,
                user_rules=user_rules,
                runner=runner,
            )
            restarted = bool((resolver.get('resolver') or {}).get('restarted'))
        except AgentError as exc:
            log.warning('ads_block ensure: VPN DNS resolver setup failed: %s', exc)
        except Exception as exc:
            log.warning('ads_block ensure: VPN DNS resolver setup failed: %s', exc)
    else:
        listen_addresses = _vpn_dns_addresses(runner=runner)
        if listen_addresses:
            adguard_meta = ensure_adguard_resolver(
                [{'name': 'auto', 'gateway': listen_addresses[0]}],
                filtering_enabled=True,
                user_rules=user_rules,
                runner=runner,
            )
            resolver = {'resolver': adguard_meta}
            restarted = bool(adguard_meta.get('restarted'))

    service = ensure_adguard_service(runner=runner)
    restarted = bool((service or {}).get('active')) or restarted

    status = ads_block_status(runner=runner)
    status.update(
        {
            'ok': bool(status.get('ready')),
            'written': True,
            'custom_rules': len(user_rules),
            'restarted': restarted,
            'resolver': resolver,
            'service': service,
        }
    )
    if not status.get('adguard_active'):
        log.warning(
            'ads_block ensure: AdGuard Home is not active — run: sudo agent ads-block repair (%s)',
            (service or {}).get('journal') or (service or {}).get('diagnostic') or 'unknown',
        )
    if not status.get('dns'):
        log.warning('ads_block ensure: no VPN interface DNS address detected yet')
    elif not resolver:
        log.warning(
            'ads_block ensure: ads filter enabled but VPN DNS resolver was not configured; '
            'clients may not reach AdGuard on %s',
            status.get('dns'),
        )
    return status


def ads_block_disable(*, runner: Runner | None = None) -> dict[str, Any]:
    _require_linux()
    _require_root()

    removed = False
    if ADS_ENABLED_MARKER.is_file():
        ADS_ENABLED_MARKER.unlink()
        removed = True

    cleanup = teardown_vpn_dns_if_unused(runner=runner)

    return {
        'ok': True,
        'removed': removed,
        'cleanup': cleanup,
        **ads_block_status(runner=runner),
    }
