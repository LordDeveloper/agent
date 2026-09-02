"""AdGuard Home resolver for VPN client DNS (leak protection + ads filtering)."""

from __future__ import annotations

import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from agent.errors import AgentError
from agent.logutil import get_logger
from agent.support.process import run

log = get_logger('adguard')

Runner = Callable[..., Any]

ADGUARD_VERSION = 'v0.107.61'
ADGUARD_RELEASE_BASE = 'https://github.com/AdguardTeam/AdGuardHome/releases/download'

ADGUARD_WORK_DIR = Path('/var/lib/agent/adguard')
ADGUARD_BINARY = ADGUARD_WORK_DIR / 'AdGuardHome'
ADGUARD_CONFIG = ADGUARD_WORK_DIR / 'AdGuardHome.yaml'
ADGUARD_DATA_DIR = ADGUARD_WORK_DIR / 'data'
ADS_ENABLED_MARKER = Path('/var/lib/agent/ads-block-enabled')

AGENT_ADGUARD_UNIT = 'agent-adguard'
AGENT_ADGUARD_UNIT_PATH = Path('/etc/systemd/system/agent-adguard.service')
ADGUARD_UNIT_MARKER = Path('/var/lib/agent/adguard-systemd-unit')

RESOLVED_STUB_DROPIN = Path('/etc/systemd/resolved.conf.d/netinja-adguard.conf')

LEGACY_DNSMASQ_CONF_DIR = Path('/var/lib/agent/dnsmasq.conf.d')
LEGACY_DNSMASQ_UNIT = 'agent-dnsmasq'
LEGACY_DNSMASQ_UNIT_PATH = Path('/etc/systemd/system/agent-dnsmasq.service')
LEGACY_DNSMASQ_MARKER = Path('/var/lib/agent/dnsmasq-systemd-unit')
LEGACY_DNSMASQ_VPN_DROPIN = Path('/etc/dnsmasq.d/netinja-vpn-dns.conf')
LEGACY_DNSMASQ_ADS_DROPIN = Path('/etc/dnsmasq.d/netinja-ads-block.conf')

DEFAULT_UPSTREAM_DNS = ('1.1.1.1', '8.8.8.8')

DEFAULT_FILTERS = (
    {
        'enabled': True,
        'url': 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
        'name': 'AdGuard DNS filter',
        'id': 1,
    },
    {
        'enabled': True,
        'url': 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt',
        'name': 'AdGuard DNS Popup Hosts filter',
        'id': 2,
    },
)


def _detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in {'x86_64', 'amd64'}:
        return 'amd64'
    if machine in {'aarch64', 'arm64'}:
        return 'arm64'
    if machine.startswith('arm'):
        return 'armv7'
    return 'amd64'


def _yaml_list(items: list[str], indent: int = 0) -> str:
    prefix = ' ' * indent
    if not items:
        return f'{prefix}[]'
    return '\n'.join(f'{prefix}- {item!r}' for item in items)


def _yaml_filters(filters: tuple[dict[str, Any], ...]) -> str:
    lines: list[str] = []
    for row in filters:
        lines.append('  - enabled: true')
        lines.append(f'    url: {row["url"]!r}')
        lines.append(f'    name: {row["name"]!r}')
        lines.append(f'    id: {int(row["id"])}')
    return '\n'.join(lines)


def render_adguard_config(
    bind_hosts: list[str],
    *,
    upstream: tuple[str, ...] = DEFAULT_UPSTREAM_DNS,
    filtering_enabled: bool = True,
    user_rules: list[str] | None = None,
) -> str:
    hosts = sorted({str(item).strip() for item in bind_hosts if str(item).strip()})
    if not hosts:
        raise AgentError('VALIDATION_ERROR', 'AdGuard bind_hosts cannot be empty')

    upstream_list = [str(item).strip() for item in upstream if str(item).strip()]
    if not upstream_list:
        upstream_list = list(DEFAULT_UPSTREAM_DNS)

    rules = [str(item).strip() for item in (user_rules or []) if str(item).strip()]
    filters_block = _yaml_filters(DEFAULT_FILTERS) if filtering_enabled else '  []'

    return '\n'.join(
        [
            '# Managed by Netinja agent — AdGuard Home VPN DNS resolver',
            'http:',
            '  pprof:',
            '    port: 6060',
            '    enabled: false',
            '  address: 127.0.0.1:3000',
            '  session_ttl: 720h',
            'users: []',
            'auth_attempts: 5',
            'block_auth_min: 15',
            'http_proxy: ""',
            'language: en',
            'theme: auto',
            'dns:',
            '  bind_hosts:',
            _yaml_list(hosts, indent=4),
            '  port: 53',
            '  anonymize_client_ip: false',
            '  upstream_dns:',
            _yaml_list(upstream_list, indent=4),
            '  bootstrap_dns:',
            _yaml_list(upstream_list, indent=4),
            '  cache_size: 4194304',
            '  serve_plain_dns: true',
            '  hostsfile_enabled: false',
            'tls:',
            '  enabled: false',
            'querylog:',
            '  enabled: false',
            '  file_enabled: false',
            'statistics:',
            '  enabled: false',
            'filters:',
            filters_block,
            'whitelist_filters: []',
            'user_rules:',
            _yaml_list(rules, indent=2) if rules else '  []',
            'dhcp:',
            '  enabled: false',
            'filtering:',
            '  blocking_mode: default',
            '  parental_enabled: false',
            '  safebrowsing_enabled: false',
            '  filtering_enabled: ' + ('true' if filtering_enabled else 'false'),
            '  protection_enabled: ' + ('true' if filtering_enabled else 'false'),
            '  protection_disabled_until: null',
            '  blocked_services:',
            '    schedule:',
            '      time_zone: Local',
            '    ids: []',
            'clients:',
            '  runtime_sources:',
            '    whois: true',
            '    arp: true',
            '    rdns: true',
            '    dhcp: true',
            '    hosts: true',
            '  persistent: []',
            'log:',
            '  enabled: false',
            '  file: ""',
            '  max_backups: 0',
            '  max_size: 100',
            '  max_age: 3',
            '  compress: false',
            '  local_time: false',
            '  verbose: false',
            'os:',
            '  group: ""',
            '  user: ""',
            '  rlimit_nofile: 0',
            'schema_version: 29',
            '',
        ]
    )


def _command_output(proc: Any) -> str:
    return '\n'.join(
        part.strip()
        for part in (
            getattr(proc, 'stdout', '') or '',
            getattr(proc, 'stderr', '') or '',
        )
        if part and str(part).strip()
    ).strip()


def adguard_service_active(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not shutil.which('systemctl'):
        return False
    proc = execute(['systemctl', 'is-active', AGENT_ADGUARD_UNIT], check=False, timeout=10)
    return (getattr(proc, 'stdout', '') or '').strip() == 'active'


def adguard_unit_enabled(*, runner: Runner | None = None) -> str:
    execute = runner or run
    if not shutil.which('systemctl'):
        return 'unknown'
    proc = execute(['systemctl', 'is-enabled', AGENT_ADGUARD_UNIT], check=False, timeout=10)
    return (getattr(proc, 'stdout', '') or '').strip() or 'unknown'


def adguard_service_journal(*, runner: Runner | None = None, lines: int = 12) -> str:
    execute = runner or run
    if not shutil.which('journalctl'):
        return ''
    proc = execute(
        ['journalctl', '-u', AGENT_ADGUARD_UNIT, '-n', str(max(1, lines)), '--no-pager'],
        check=False,
        timeout=15,
    )
    return (getattr(proc, 'stdout', '') or '').strip()


def adguard_service_diagnostic(*, runner: Runner | None = None) -> str:
    if not AGENT_ADGUARD_UNIT_PATH.is_file() and not ADGUARD_UNIT_MARKER.is_file():
        return 'AdGuard Home unit not found (run: agent ads-block install)'
    journal = adguard_service_journal(runner=runner, lines=15)
    if journal and journal != '-- No entries --':
        return journal
    execute = runner or run
    if shutil.which('systemctl'):
        proc = execute(['systemctl', 'status', AGENT_ADGUARD_UNIT, '-n', '15', '--no-pager'], check=False, timeout=15)
        status = _command_output(proc)
        if status:
            return status
    enabled = adguard_unit_enabled(runner=runner)
    if enabled == 'not-found':
        return 'AdGuard Home unit not found (run: agent ads-block install)'
    if enabled == 'masked':
        return 'AdGuard Home service is masked'
    if enabled == 'disabled':
        return 'AdGuard Home service is disabled'
    return journal or 'AdGuard Home service is not active'


def _resolved_stub_config_disabled() -> bool:
    if RESOLVED_STUB_DROPIN.is_file():
        text = RESOLVED_STUB_DROPIN.read_text(encoding='utf-8', errors='ignore')
        if 'dnsstublistener=no' in text.replace(' ', '').lower():
            return True
    resolved_conf = Path('/etc/systemd/resolved.conf')
    if resolved_conf.is_file():
        text = resolved_conf.read_text(encoding='utf-8', errors='ignore')
        if re.search(r'^\s*DNSStubListener\s*=\s*no\s*$', text, flags=re.MULTILINE | re.IGNORECASE):
            return True
    return False


def resolved_stub_listener_listening(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not shutil.which('ss'):
        return False
    proc = execute(['ss', '-H', '-lun'], check=False, timeout=10)
    text = _command_output(proc).lower()
    for line in text.splitlines():
        if ':53' not in line:
            continue
        if '127.0.0.53' in line or 'systemd-resolve' in line:
            return True
    return False


def resolved_stub_listener_disabled(*, runner: Runner | None = None) -> bool:
    if resolved_stub_listener_listening(runner=runner):
        return False
    return _resolved_stub_config_disabled()


def disable_resolved_stub_listener(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    content = '[Resolve]\nDNSStubListener=no\n'
    changed = False
    if not RESOLVED_STUB_DROPIN.is_file() or RESOLVED_STUB_DROPIN.read_text(encoding='utf-8') != content:
        RESOLVED_STUB_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        RESOLVED_STUB_DROPIN.write_text(content, encoding='utf-8')
        changed = True
    if shutil.which('systemctl'):
        execute(['systemctl', 'restart', 'systemd-resolved'], check=False, timeout=30)
    return changed or resolved_stub_listener_disabled(runner=runner)


def restore_resolved_stub_listener(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not RESOLVED_STUB_DROPIN.is_file():
        return False
    RESOLVED_STUB_DROPIN.unlink(missing_ok=True)
    if shutil.which('systemctl'):
        execute(['systemctl', 'restart', 'systemd-resolved'], check=False, timeout=30)
    return True


def isolate_vpn_interfaces_from_host_dns(
    interfaces: list[dict[str, Any]],
    *,
    runner: Runner | None = None,
) -> list[str]:
    """Keep VPN server gateway IPs out of the host resolver (systemd-resolved)."""
    execute = runner or run
    if not shutil.which('resolvectl'):
        return []
    actions: list[str] = []
    for row in interfaces:
        name = str(row.get('name') or '').strip()
        if not name:
            continue
        dns_proc = execute(['resolvectl', 'dns', name, 'off'], check=False, timeout=10)
        execute(['resolvectl', 'domain', name, 'off'], check=False, timeout=10)
        if getattr(dns_proc, 'returncode', 1) == 0:
            actions.append(f'resolvectl_dns_off:{name}')
    return actions


def _render_agent_adguard_unit(binary: str, work_dir: str) -> str:
    return '\n'.join(
        [
            '[Unit]',
            'Description=Netinja VPN DNS resolver (AdGuard Home)',
            'After=network-online.target',
            'Wants=network-online.target',
            '',
            '[Service]',
            'Type=simple',
            f'WorkingDirectory={work_dir}',
            f'ExecStart={binary} -c {work_dir}/AdGuardHome.yaml -w {work_dir} --no-check-update',
            'Restart=on-failure',
            'RestartSec=3',
            '',
            '[Install]',
            'WantedBy=multi-user.target',
            '',
        ]
    )


def _download_adguard_binary(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    arch = _detect_arch()
    archive_name = f'AdGuardHome_linux_{arch}.tar.gz'
    url = f'{ADGUARD_RELEASE_BASE}/{ADGUARD_VERSION}/{archive_name}'

    ADGUARD_WORK_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / archive_name
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'netinja-agent/adguard'})
            with urllib.request.urlopen(request, timeout=120) as response:
                archive_path.write_bytes(response.read())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning('adguard: failed to download %s: %s', url, exc)
            return False

        try:
            with tarfile.open(archive_path, 'r:gz') as archive:
                archive.extractall(path=tmp)
        except (tarfile.TarError, OSError) as exc:
            log.warning('adguard: failed to extract archive: %s', exc)
            return False

        extracted = Path(tmp) / 'AdGuardHome' / 'AdGuardHome'
        if not extracted.is_file():
            candidates = list(Path(tmp).rglob('AdGuardHome'))
            extracted = next((path for path in candidates if path.is_file() and path.name == 'AdGuardHome'), None)
        if extracted is None or not extracted.is_file():
            return False

        shutil.copy2(extracted, ADGUARD_BINARY)
        try:
            ADGUARD_BINARY.chmod(0o755)
        except OSError:
            pass

    return ADGUARD_BINARY.is_file()


def install_adguard_binary(*, runner: Runner | None = None) -> bool:
    if ADGUARD_BINARY.is_file():
        return True
    if _download_adguard_binary(runner=runner):
        return True
    apt = shutil.which('apt-get')
    if apt is None:
        return False
    execute = runner or run
    execute([apt, 'update', '-qq'], check=False, timeout=120)
    proc = execute([apt, 'install', '-y', '-qq', 'adguardhome'], check=False, timeout=300)
    if proc.returncode == 0 and shutil.which('AdGuardHome'):
        system_binary = shutil.which('AdGuardHome')
        if system_binary:
            ADGUARD_WORK_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(system_binary, ADGUARD_BINARY)
            try:
                ADGUARD_BINARY.chmod(0o755)
            except OSError:
                pass
    return ADGUARD_BINARY.is_file()


def ensure_adguard_systemd_unit(*, runner: Runner | None = None) -> dict[str, Any]:
    execute = runner or run
    installed = install_adguard_binary(runner=runner)
    binary = str(ADGUARD_BINARY) if ADGUARD_BINARY.is_file() else shutil.which('AdGuardHome')
    if not binary:
        return {'ok': False, 'unit': None, 'message': 'AdGuard Home binary not found'}

    ADGUARD_WORK_DIR.mkdir(parents=True, exist_ok=True)
    ADGUARD_DATA_DIR.mkdir(parents=True, exist_ok=True)
    unit_content = _render_agent_adguard_unit(binary, str(ADGUARD_WORK_DIR))
    created = False
    previous = AGENT_ADGUARD_UNIT_PATH.read_text(encoding='utf-8') if AGENT_ADGUARD_UNIT_PATH.is_file() else ''
    if previous != unit_content:
        AGENT_ADGUARD_UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        AGENT_ADGUARD_UNIT_PATH.write_text(unit_content, encoding='utf-8')
        created = True
    ADGUARD_UNIT_MARKER.parent.mkdir(parents=True, exist_ok=True)
    ADGUARD_UNIT_MARKER.write_text(AGENT_ADGUARD_UNIT, encoding='utf-8')
    if shutil.which('systemctl'):
        execute(['systemctl', 'daemon-reload'], check=False, timeout=30)
    return {
        'ok': True,
        'unit': AGENT_ADGUARD_UNIT,
        'created': created,
        'installed': installed,
        'work_dir': str(ADGUARD_WORK_DIR),
    }


def remove_agent_adguard_systemd_unit(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not ADGUARD_UNIT_MARKER.is_file():
        return False
    if shutil.which('systemctl'):
        execute(['systemctl', 'stop', AGENT_ADGUARD_UNIT], check=False, timeout=30)
        execute(['systemctl', 'disable', AGENT_ADGUARD_UNIT], check=False, timeout=30)
        execute(['systemctl', 'daemon-reload'], check=False, timeout=30)
    AGENT_ADGUARD_UNIT_PATH.unlink(missing_ok=True)
    ADGUARD_UNIT_MARKER.unlink(missing_ok=True)
    return True


def cleanup_legacy_dnsmasq(*, runner: Runner | None = None) -> list[str]:
    execute = runner or run
    removed: list[str] = []

    if shutil.which('systemctl'):
        execute(['systemctl', 'stop', LEGACY_DNSMASQ_UNIT], check=False, timeout=30)
        execute(['systemctl', 'disable', LEGACY_DNSMASQ_UNIT], check=False, timeout=30)

    for path in (
        LEGACY_DNSMASQ_UNIT_PATH,
        LEGACY_DNSMASQ_MARKER,
        LEGACY_DNSMASQ_VPN_DROPIN,
        LEGACY_DNSMASQ_ADS_DROPIN,
    ):
        if path.is_file():
            path.unlink()
            removed.append(str(path))

    if LEGACY_DNSMASQ_CONF_DIR.is_dir():
        shutil.rmtree(LEGACY_DNSMASQ_CONF_DIR, ignore_errors=True)
        removed.append(str(LEGACY_DNSMASQ_CONF_DIR))

    legacy_resolved = Path('/etc/systemd/resolved.conf.d/netinja-dnsmasq.conf')
    if legacy_resolved.is_file():
        legacy_resolved.unlink()
        removed.append(str(legacy_resolved))

    if shutil.which('systemctl'):
        execute(['systemctl', 'daemon-reload'], check=False, timeout=30)
    return removed


def ensure_adguard_service(*, runner: Runner | None = None, fix_resolved: bool = True) -> dict[str, Any]:
    execute = runner or run
    actions: list[str] = []
    cleanup_legacy_dnsmasq(runner=runner)

    unit_setup = ensure_adguard_systemd_unit(runner=runner)
    unit = str(unit_setup.get('unit') or AGENT_ADGUARD_UNIT)
    if unit_setup.get('installed'):
        actions.append('installed_adguard_binary')
    if unit_setup.get('created'):
        actions.append('created_adguard_unit')
    if not unit_setup.get('ok'):
        message = str(unit_setup.get('message') or 'AdGuard Home unit is unavailable')
        return {
            'active': False,
            'config_ok': False,
            'config_message': message,
            'journal': message,
            'diagnostic': message,
            'unit': unit,
            'unit_enabled': 'not-found',
            'actions': actions,
        }

    if not ADGUARD_BINARY.is_file() and not shutil.which('AdGuardHome'):
        return {
            'active': False,
            'config_ok': False,
            'config_message': 'AdGuard Home binary not found',
            'journal': None,
            'diagnostic': 'AdGuard Home binary not found',
            'unit': unit,
            'unit_enabled': adguard_unit_enabled(runner=runner),
            'actions': actions,
            'unit_setup': unit_setup,
        }

    config_ok = ADGUARD_CONFIG.is_file()
    config_message = 'ok' if config_ok else 'AdGuardHome.yaml missing (run ensure)'
    unit_enabled = adguard_unit_enabled(runner=runner)

    if not config_ok:
        diagnostic = adguard_service_diagnostic(runner=runner)
        return {
            'active': False,
            'config_ok': False,
            'config_message': config_message,
            'journal': diagnostic or None,
            'diagnostic': diagnostic or config_message,
            'unit': unit,
            'unit_enabled': unit_enabled,
            'actions': actions,
            'unit_setup': unit_setup,
        }

    if shutil.which('systemctl'):
        if unit_enabled == 'masked':
            execute(['systemctl', 'unmask', unit], check=False, timeout=30)
            actions.append('unmasked_adguard')
            unit_enabled = adguard_unit_enabled(runner=runner)
        execute(['systemctl', 'enable', unit], check=False, timeout=30)
        execute(['systemctl', 'restart', unit], check=False, timeout=60)
        if not adguard_service_active(runner=runner):
            execute(['systemctl', 'start', unit], check=False, timeout=60)

    active = adguard_service_active(runner=runner)
    diagnostic = ''

    if not active and fix_resolved:
        diagnostic = adguard_service_diagnostic(runner=runner)
        lowered = diagnostic.lower()
        port_conflict = any(
            token in lowered
            for token in (
                'address already in use',
                'bind',
                'port 53',
                'listen tcp',
                'listen udp',
            )
        )
        if port_conflict:
            if disable_resolved_stub_listener(runner=runner):
                actions.append('disabled_resolved_stub_listener')
            execute(['systemctl', 'restart', unit], check=False, timeout=60)
            if not adguard_service_active(runner=runner):
                execute(['systemctl', 'start', unit], check=False, timeout=60)
            active = adguard_service_active(runner=runner)
            if not active:
                diagnostic = adguard_service_diagnostic(runner=runner)

    return {
        'active': active,
        'config_ok': config_ok,
        'config_message': config_message,
        'journal': diagnostic or None,
        'diagnostic': diagnostic or None,
        'unit': unit,
        'unit_enabled': unit_enabled,
        'resolved_stub_disabled': resolved_stub_listener_disabled(runner=runner),
        'resolved_stub_listening': resolved_stub_listener_listening(runner=runner),
        'actions': actions,
        'unit_setup': unit_setup,
    }


def write_adguard_config(
    bind_hosts: list[str],
    *,
    upstream: tuple[str, ...] = DEFAULT_UPSTREAM_DNS,
    filtering_enabled: bool = True,
    user_rules: list[str] | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    execute = runner or run
    content = render_adguard_config(
        bind_hosts,
        upstream=upstream,
        filtering_enabled=filtering_enabled,
        user_rules=user_rules,
    )
    ADGUARD_WORK_DIR.mkdir(parents=True, exist_ok=True)
    previous = ADGUARD_CONFIG.read_text(encoding='utf-8') if ADGUARD_CONFIG.is_file() else ''
    written = previous != content

    if shutil.which('systemctl') and adguard_service_active(runner=runner):
        execute(['systemctl', 'stop', AGENT_ADGUARD_UNIT], check=False, timeout=30)

    if written:
        ADGUARD_CONFIG.write_text(content, encoding='utf-8')

    return {
        'config': str(ADGUARD_CONFIG),
        'written': written,
        'listen_addresses': sorted({str(item).strip() for item in bind_hosts if str(item).strip()}),
        'filtering_enabled': filtering_enabled,
        'upstream': list(upstream),
    }


def ensure_adguard_resolver(
    interfaces: list[dict[str, Any]],
    *,
    upstream: tuple[str, ...] = DEFAULT_UPSTREAM_DNS,
    filtering_enabled: bool = True,
    user_rules: list[str] | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    listen_addresses = sorted({str(row['gateway']) for row in interfaces if str(row.get('gateway') or '').strip()})
    if not listen_addresses:
        raise AgentError('VALIDATION_ERROR', 'VPN interface list has no IPv4 gateway addresses')

    config_meta = write_adguard_config(
        listen_addresses,
        upstream=upstream,
        filtering_enabled=filtering_enabled,
        user_rules=user_rules,
        runner=runner,
    )
    service = ensure_adguard_service(runner=runner)
    restarted = bool(service.get('active'))

    return {
        'config': config_meta['config'],
        'written': config_meta['written'],
        'listen_addresses': listen_addresses,
        'upstream': list(upstream),
        'filtering_enabled': filtering_enabled,
        'installed': bool(service.get('unit_setup', {}).get('installed')),
        'restarted': restarted,
        'service': service,
        'work_dir': str(ADGUARD_WORK_DIR),
    }


def adguard_configured() -> bool:
    return ADGUARD_CONFIG.is_file()


def adguard_status_summary() -> dict[str, Any]:
    return {
        'installed': ADGUARD_BINARY.is_file() or bool(shutil.which('AdGuardHome')),
        'configured': adguard_configured(),
        'work_dir': str(ADGUARD_WORK_DIR),
        'config': str(ADGUARD_CONFIG),
        'unit': AGENT_ADGUARD_UNIT,
    }
