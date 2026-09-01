"""DNS leak prevention for VPN client subnets (WireGuard / Amnezia)."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from agent.errors import AgentError
from agent.logutil import get_logger
from agent.support.host_interfaces import list_host_interfaces
from agent.support.process import run

log = get_logger('dns_leak')

NFT_TABLE = 'netinja_dns'
NFT_CHAIN_PREROUTING = 'prerouting'
NFT_CHAIN_FORWARD = 'forward'
UNIT_NAME = 'agent-dns-leak.service'
UNIT_PATH = Path('/etc/systemd/system') / UNIT_NAME
DNSMASQ_DROPIN = Path('/etc/dnsmasq.d/netinja-vpn-dns.conf')
COMMENT_PREFIX = 'netinja-dns-leak:'
_IFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,14}$')

Runner = Callable[..., Any]

DEFAULT_UPSTREAM_DNS = ('1.1.1.1', '8.8.8.8')
RESOLVED_STUB_DROPIN = Path('/etc/systemd/resolved.conf.d/netinja-dnsmasq.conf')


def dnsmasq_service_active(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not shutil.which('systemctl'):
        return False
    proc = execute(['systemctl', 'is-active', 'dnsmasq'], check=False, timeout=10)
    return (getattr(proc, 'stdout', '') or '').strip() == 'active'


def dnsmasq_config_test(*, runner: Runner | None = None) -> tuple[bool, str]:
    execute = runner or run
    if not shutil.which('dnsmasq'):
        return False, 'dnsmasq binary not found'
    proc = execute(['dnsmasq', '--test'], check=False, timeout=15)
    message = (getattr(proc, 'stderr', '') or getattr(proc, 'stdout', '') or '').strip()
    return proc.returncode == 0, message


def _command_output(proc: Any) -> str:
    return '\n'.join(
        part.strip()
        for part in (
            getattr(proc, 'stdout', '') or '',
            getattr(proc, 'stderr', '') or '',
        )
        if part and str(part).strip()
    ).strip()


def dnsmasq_unit_enabled(*, runner: Runner | None = None) -> str:
    execute = runner or run
    if not shutil.which('systemctl'):
        return 'unknown'
    proc = execute(['systemctl', 'is-enabled', 'dnsmasq'], check=False, timeout=10)
    return (getattr(proc, 'stdout', '') or '').strip() or 'unknown'


def dnsmasq_service_status(*, runner: Runner | None = None) -> str:
    execute = runner or run
    if not shutil.which('systemctl'):
        return ''
    proc = execute(['systemctl', 'status', 'dnsmasq', '-n', '15', '--no-pager'], check=False, timeout=15)
    return _command_output(proc)


def dnsmasq_service_journal(*, runner: Runner | None = None, lines: int = 8) -> str:
    execute = runner or run
    if not shutil.which('journalctl'):
        return ''
    proc = execute(
        ['journalctl', '-u', 'dnsmasq', '-n', str(max(1, lines)), '--no-pager'],
        check=False,
        timeout=15,
    )
    return (getattr(proc, 'stdout', '') or '').strip()


def dnsmasq_service_diagnostic(*, runner: Runner | None = None) -> str:
    journal = dnsmasq_service_journal(runner=runner, lines=15)
    if journal and journal != '-- No entries --':
        return journal
    status = dnsmasq_service_status(runner=runner)
    if status:
        return status
    enabled = dnsmasq_unit_enabled(runner=runner)
    if enabled == 'masked':
        return 'dnsmasq service is masked'
    if enabled == 'disabled':
        return 'dnsmasq service is disabled'
    return journal or 'dnsmasq service is not active'


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


def ensure_dnsmasq_service(*, runner: Runner | None = None, fix_resolved: bool = True) -> dict[str, Any]:
    """Start dnsmasq and repair common port-53 / systemd-resolved conflicts."""
    execute = runner or run
    actions: list[str] = []
    unit_enabled = dnsmasq_unit_enabled(runner=runner)

    if not shutil.which('dnsmasq'):
        return {
            'active': False,
            'config_ok': False,
            'config_message': 'dnsmasq binary not found',
            'journal': None,
            'diagnostic': 'dnsmasq binary not found',
            'unit_enabled': unit_enabled,
            'actions': actions,
        }

    config_ok, config_message = dnsmasq_config_test(runner=runner)
    if not config_ok:
        diagnostic = dnsmasq_service_diagnostic(runner=runner)
        return {
            'active': False,
            'config_ok': False,
            'config_message': config_message,
            'journal': diagnostic or None,
            'diagnostic': diagnostic or config_message,
            'unit_enabled': unit_enabled,
            'actions': actions,
        }

    if shutil.which('systemctl'):
        if unit_enabled == 'masked':
            execute(['systemctl', 'unmask', 'dnsmasq'], check=False, timeout=30)
            actions.append('unmasked_dnsmasq')
            unit_enabled = dnsmasq_unit_enabled(runner=runner)
        execute(['systemctl', 'enable', 'dnsmasq'], check=False, timeout=30)
        execute(['systemctl', 'restart', 'dnsmasq'], check=False, timeout=60)
        if not dnsmasq_service_active(runner=runner):
            execute(['systemctl', 'start', 'dnsmasq'], check=False, timeout=60)

    active = dnsmasq_service_active(runner=runner)
    diagnostic = ''

    if not active and fix_resolved:
        diagnostic = dnsmasq_service_diagnostic(runner=runner)
        lowered = diagnostic.lower()
        port_conflict = any(
            token in lowered
            for token in (
                'address already in use',
                'failed to create listening socket',
                'failed to bind',
                'port 53',
                'masked',
            )
        )
        stub_listening = resolved_stub_listener_listening(runner=runner)
        if port_conflict or stub_listening or not resolved_stub_listener_disabled(runner=runner):
            if disable_resolved_stub_listener(runner=runner):
                actions.append('disabled_resolved_stub_listener')
            execute(['systemctl', 'restart', 'dnsmasq'], check=False, timeout=60)
            if not dnsmasq_service_active(runner=runner):
                execute(['systemctl', 'start', 'dnsmasq'], check=False, timeout=60)
            active = dnsmasq_service_active(runner=runner)
            if not active:
                diagnostic = dnsmasq_service_diagnostic(runner=runner)

    return {
        'active': active,
        'config_ok': config_ok,
        'config_message': config_message,
        'journal': diagnostic or None,
        'diagnostic': diagnostic or None,
        'unit_enabled': unit_enabled,
        'resolved_stub_disabled': resolved_stub_listener_disabled(runner=runner),
        'resolved_stub_listening': resolved_stub_listener_listening(runner=runner),
        'actions': actions,
    }


def _require_linux() -> None:
    if not sys.platform.startswith('linux'):
        raise AgentError('UNSUPPORTED_CAPABILITY', 'DNS leak protection requires Linux')


def _require_root() -> None:
    geteuid = getattr(os, 'geteuid', None)
    if geteuid is None or geteuid() != 0:
        raise AgentError('VALIDATION_ERROR', 'DNS leak protection requires root (run with sudo)')


def _firewall_backend() -> str | None:
    if shutil.which('nft'):
        return 'nft'
    if shutil.which('iptables'):
        return 'iptables'
    return None


def _interface_ipv4(addresses: list[str]) -> str | None:
    for item in addresses:
        text = str(item).strip()
        if not text:
            continue
        try:
            iface = ipaddress.ip_interface(text)
        except ValueError:
            continue
        if isinstance(iface.ip, ipaddress.IPv4Address):
            return str(iface.ip)
    return None


def _is_vpn_interface(row: dict[str, Any]) -> bool:
    name = str(row.get('name') or '').strip()
    link_type = str(row.get('link_type') or '').strip().lower()
    if link_type == 'wireguard':
        return True
    lowered = name.lower()
    return lowered.startswith('wg') or lowered.startswith('awg')


def discover_vpn_interfaces(*, runner: Runner | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_host_interfaces(runner=runner):
        if not _is_vpn_interface(item):
            continue
        gateway = _interface_ipv4(list(item.get('addresses') or []))
        if not gateway:
            continue
        rows.append(
            {
                'name': str(item['name']),
                'gateway': gateway,
                'addresses': list(item.get('addresses') or []),
                'link_type': item.get('link_type'),
            }
        )
    return rows


def apply_script_path(data_dir: str | Path | None = None) -> Path:
    base = Path(data_dir or os.environ.get('DATA_DIR') or '/var/lib/agent')
    return base / 'dns-leak-apply.sh'


def render_apply_script(
    interfaces: list[dict[str, Any]],
    *,
    block_ipv6: bool = True,
) -> str:
    lines = [
        '#!/bin/sh',
        '# Generated by Netinja agent — DNS leak prevention. Do not edit.',
        'set +e',
        '',
        '_iface_ready() {',
        '  ip link show "$1" >/dev/null 2>&1',
        '}',
        '',
    ]

    if shutil.which('nft'):
        lines.extend(
            [
                'if command -v nft >/dev/null 2>&1; then',
                f'  nft add table inet {NFT_TABLE} 2>/dev/null || true',
                f'  nft add chain inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} '
                '"{ type nat hook prerouting priority dstnat; policy accept; }" 2>/dev/null || true',
                f'  nft add chain inet {NFT_TABLE} {NFT_CHAIN_FORWARD} '
                '"{ type filter hook forward priority filter; policy accept; }" 2>/dev/null || true',
                f'  nft flush chain inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} 2>/dev/null || true',
                f'  nft flush chain inet {NFT_TABLE} {NFT_CHAIN_FORWARD} 2>/dev/null || true',
            ]
        )
        for row in interfaces:
            name = str(row['name'])
            gateway = str(row['gateway'])
            comment = f'{COMMENT_PREFIX}{name}'
            lines.append(f'if _iface_ready "{name}"; then')
            lines.append(
                f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} iifname "{name}" '
                f'udp dport 53 dnat ip to {gateway}:53 comment "{comment}-udp" 2>/dev/null || true'
            )
            lines.append(
                f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} iifname "{name}" '
                f'tcp dport 53 dnat ip to {gateway}:53 comment "{comment}-tcp" 2>/dev/null || true'
            )
            if block_ipv6:
                lines.append(
                    f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_FORWARD} iifname "{name}" '
                    f'ip6 saddr != :: drop comment "{comment}-no-v6" 2>/dev/null || true'
                )
                lines.append(
                    f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_FORWARD} oifname "{name}" '
                    f'ip6 daddr != :: drop comment "{comment}-no-v6-out" 2>/dev/null || true'
                )
            lines.append('fi')
        lines.append('fi')
        lines.append('')

    lines.append('if command -v iptables >/dev/null 2>&1; then')
    for row in interfaces:
        name = str(row['name'])
        gateway = str(row['gateway'])
        comment = f'{COMMENT_PREFIX}{name}'
        lines.append(f'if _iface_ready "{name}"; then')
        for proto in ('udp', 'tcp'):
            lines.append(
                f'  iptables -t nat -C PREROUTING -i "{name}" -p {proto} --dport 53 '
                f'-m comment --comment "{comment}-{proto}" -j DNAT --to-destination {gateway}:53 '
                f'2>/dev/null || iptables -t nat -A PREROUTING -i "{name}" -p {proto} --dport 53 '
                f'-m comment --comment "{comment}-{proto}" -j DNAT --to-destination {gateway}:53'
            )
        if block_ipv6 and shutil.which('ip6tables'):
            lines.append(
                f'  ip6tables -C FORWARD -i "{name}" -m comment --comment "{comment}-no-v6" -j DROP '
                f'2>/dev/null || ip6tables -A FORWARD -i "{name}" -m comment --comment "{comment}-no-v6" -j DROP'
            )
            lines.append(
                f'  ip6tables -C FORWARD -o "{name}" -m comment --comment "{comment}-no-v6-out" -j DROP '
                f'2>/dev/null || ip6tables -A FORWARD -o "{name}" -m comment --comment "{comment}-no-v6-out" -j DROP'
            )
        lines.append('fi')
    lines.append('fi')
    lines.append('')
    lines.append('exit 0')
    return '\n'.join(lines) + '\n'


def _normalize_interface_names(names: list[str] | None) -> list[str]:
    if not names:
        return []
    out: list[str] = []
    for raw in names:
        name = str(raw or '').strip()
        if not name:
            continue
        if not _IFACE_RE.match(name):
            raise AgentError('VALIDATION_ERROR', f'Invalid interface name [{name}]')
        out.append(name)
    return out


def _resolve_targets(
    interfaces: list[str] | None,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    discovered = discover_vpn_interfaces(runner=runner)
    by_name = {str(row['name']): row for row in discovered}
    requested = _normalize_interface_names(interfaces)

    if requested:
        missing = [name for name in requested if name not in by_name]
        if missing:
            raise AgentError(
                'VALIDATION_ERROR',
                f'VPN interface(s) not found or have no IPv4 address: {", ".join(missing)}',
            )
        return [by_name[name] for name in requested]

    if not discovered:
        raise AgentError(
            'VALIDATION_ERROR',
            'No WireGuard/Amnezia interfaces detected. Pass --interface wg0 explicitly.',
        )
    return discovered


def _write_apply_script(
    interfaces: list[dict[str, Any]],
    *,
    data_dir: str | Path | None = None,
    block_ipv6: bool = True,
) -> Path:
    path = apply_script_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_apply_script(interfaces, block_ipv6=block_ipv6), encoding='utf-8')
    try:
        path.chmod(0o755)
    except OSError:
        pass
    return path


def _ensure_dnsmasq(
    interfaces: list[dict[str, Any]],
    *,
    upstream: tuple[str, ...] = DEFAULT_UPSTREAM_DNS,
) -> dict[str, Any]:
    listen_addresses = sorted({str(row['gateway']) for row in interfaces})
    lines = ['# Managed by Netinja agent — VPN DNS resolver']
    lines.append('bind-dynamic')
    lines.append('except-interface=lo')
    for address in listen_addresses:
        lines.append(f'listen-address={address}')
    for server in upstream:
        server = str(server).strip()
        if server:
            lines.append(f'server={server}')
    content = '\n'.join(lines) + '\n'

    previous = DNSMASQ_DROPIN.read_text(encoding='utf-8') if DNSMASQ_DROPIN.is_file() else ''
    written = False
    if previous != content:
        DNSMASQ_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        DNSMASQ_DROPIN.write_text(content, encoding='utf-8')
        written = True

    installed = False
    restarted = False
    service: dict[str, Any] | None = None
    apt = shutil.which('apt-get')
    if not shutil.which('dnsmasq') and apt:
        run([apt, 'update', '-qq'], check=False, timeout=120)
        proc = run([apt, 'install', '-y', '-qq', 'dnsmasq'], check=False, timeout=300)
        installed = proc.returncode == 0 and shutil.which('dnsmasq') is not None

    if shutil.which('systemctl') and shutil.which('dnsmasq'):
        service = ensure_dnsmasq_service()
        restarted = bool(service.get('active'))
        installed = installed or bool(shutil.which('dnsmasq'))

    return {
        'dropin': str(DNSMASQ_DROPIN),
        'written': written,
        'listen_addresses': listen_addresses,
        'upstream': list(upstream),
        'installed': installed or bool(shutil.which('dnsmasq')),
        'restarted': restarted,
        'service': service if shutil.which('dnsmasq') else None,
    }


def ensure_dns_leak_unit(script_path: Path, *, runner: Runner | None = None) -> dict[str, Any]:
    execute = runner or run
    if not shutil.which('systemctl'):
        return {'ok': False, 'skipped': True, 'reason': 'systemctl not found'}

    unit = '\n'.join(
        [
            '[Unit]',
            'Description=Netinja DNS leak prevention (VPN clients)',
            'After=network-online.target',
            'Wants=network-online.target',
            '',
            '[Service]',
            'Type=oneshot',
            f'ExecStart={script_path}',
            'RemainAfterExit=yes',
            '',
            '[Install]',
            'WantedBy=multi-user.target',
            '',
        ]
    )
    previous = UNIT_PATH.read_text(encoding='utf-8') if UNIT_PATH.is_file() else ''
    if previous != unit:
        UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        UNIT_PATH.write_text(unit, encoding='utf-8')
        execute(['systemctl', 'daemon-reload'], check=False, timeout=30)

    enable = execute(['systemctl', 'enable', UNIT_NAME], check=False, timeout=30)
    start = execute(['systemctl', 'start', UNIT_NAME], check=False, timeout=60)
    return {
        'ok': getattr(enable, 'returncode', 1) == 0 and getattr(start, 'returncode', 1) == 0,
        'unit': str(UNIT_PATH),
        'script': str(script_path),
    }


def ensure_vpn_dns_resolver(
    *,
    interfaces: list[dict[str, Any]] | None = None,
    block_ipv6: bool = True,
    upstream_dns: list[str] | None = None,
    with_dnat: bool = True,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Run dnsmasq on VPN gateway IP(s) and optionally DNAT client DNS to it."""
    _require_linux()
    _require_root()

    if interfaces is None:
        targets = _resolve_targets(None, runner=runner)
    else:
        targets = [row for row in interfaces if str(row.get('gateway') or '').strip()]
        if not targets:
            raise AgentError(
                'VALIDATION_ERROR',
                'VPN interface list has no IPv4 gateway addresses',
            )

    upstream = tuple(upstream_dns or DEFAULT_UPSTREAM_DNS)
    resolver = _ensure_dnsmasq(targets, upstream=upstream)

    dnat: dict[str, Any] | None = None
    if with_dnat:
        if _firewall_backend() is None:
            log.warning('ensure_vpn_dns_resolver: nft/iptables missing; skipping DNS DNAT')
        else:
            script = _write_apply_script(targets, data_dir=data_dir, block_ipv6=block_ipv6)
            execute = runner or run
            proc = execute(['/bin/sh', str(script)], check=False, timeout=120)
            unit = ensure_dns_leak_unit(script, runner=runner)
            dnat = {
                'applied': proc.returncode == 0,
                'script': str(script),
                'unit': unit,
                'backend': _firewall_backend(),
            }

    return {
        'ok': True,
        'interfaces': targets,
        'resolver': resolver,
        'dnat': dnat,
        'block_ipv6': block_ipv6,
    }


def dns_leak_apply(
    *,
    interfaces: list[str] | None = None,
    block_ipv6: bool = True,
    with_dnsmasq: bool = True,
    upstream_dns: list[str] | None = None,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    _require_linux()
    _require_root()
    if _firewall_backend() is None:
        raise AgentError('VALIDATION_ERROR', 'nft or iptables is required for DNS leak protection')

    targets = _resolve_targets(interfaces, runner=runner)
    script = _write_apply_script(targets, data_dir=data_dir, block_ipv6=block_ipv6)
    execute = runner or run
    proc = execute(['/bin/sh', str(script)], check=False, timeout=120)
    unit = ensure_dns_leak_unit(script, runner=runner)

    resolver: dict[str, Any] | None = None
    if with_dnsmasq:
        upstream = tuple(upstream_dns or DEFAULT_UPSTREAM_DNS)
        resolver = _ensure_dnsmasq(targets, upstream=upstream)

    return {
        'applied': proc.returncode == 0,
        'interfaces': targets,
        'script': str(script),
        'unit': unit,
        'block_ipv6': block_ipv6,
        'backend': _firewall_backend(),
        'resolver': resolver,
        'exit_code': getattr(proc, 'returncode', 1),
    }


def _nft_table_exists(*, runner: Runner | None = None) -> bool:
    execute = runner or run
    if not shutil.which('nft'):
        return False
    proc = execute(['nft', 'list', 'table', 'inet', NFT_TABLE], check=False, timeout=15)
    return proc.returncode == 0


def dns_leak_status(*, runner: Runner | None = None) -> dict[str, Any]:
    _require_linux()
    execute = runner or run
    interfaces = discover_vpn_interfaces(runner=runner)
    active = _nft_table_exists(runner=runner)
    unit_active = False
    if shutil.which('systemctl'):
        proc = execute(['systemctl', 'is-active', UNIT_NAME], check=False, timeout=10)
        unit_active = (getattr(proc, 'stdout', '') or '').strip() == 'active'

    return {
        'active': active or unit_active,
        'backend': _firewall_backend(),
        'nft_table': NFT_TABLE if active else None,
        'unit': UNIT_NAME,
        'unit_active': unit_active,
        'script': str(apply_script_path()),
        'script_exists': apply_script_path().is_file(),
        'dnsmasq_dropin': str(DNSMASQ_DROPIN),
        'dnsmasq_configured': DNSMASQ_DROPIN.is_file(),
        'interfaces': interfaces,
    }


def render_remove_script() -> str:
    lines = [
        '#!/bin/sh',
        '# Generated by Netinja agent — remove DNS leak prevention.',
        'set +e',
    ]
    if shutil.which('nft'):
        lines.append(f'nft delete table inet {NFT_TABLE} 2>/dev/null || true')
    lines.append('if command -v iptables >/dev/null 2>&1; then')
    lines.append(
        f'  iptables-save -t nat 2>/dev/null | grep -v "{COMMENT_PREFIX}" | iptables-restore -T nat 2>/dev/null || true'
    )
    lines.append('fi')
    if shutil.which('ip6tables'):
        lines.append('if command -v ip6tables >/dev/null 2>&1; then')
        lines.append(
            f'  ip6tables-save 2>/dev/null | grep -v "{COMMENT_PREFIX}" | ip6tables-restore 2>/dev/null || true'
        )
        lines.append('fi')
    lines.append('exit 0')
    return '\n'.join(lines) + '\n'


def dns_leak_remove(*, runner: Runner | None = None) -> dict[str, Any]:
    _require_linux()
    _require_root()
    execute = runner or run

    if shutil.which('nft'):
        execute(['nft', 'delete', 'table', 'inet', NFT_TABLE], check=False, timeout=15)

    remove_script = apply_script_path().with_name('dns-leak-remove.sh')
    remove_script.write_text(render_remove_script(), encoding='utf-8')
    try:
        remove_script.chmod(0o755)
    except OSError:
        pass
    execute(['/bin/sh', str(remove_script)], check=False, timeout=60)

    stopped = False
    if shutil.which('systemctl') and UNIT_PATH.is_file():
        execute(['systemctl', 'stop', UNIT_NAME], check=False, timeout=30)
        execute(['systemctl', 'disable', UNIT_NAME], check=False, timeout=30)
        UNIT_PATH.unlink(missing_ok=True)
        execute(['systemctl', 'daemon-reload'], check=False, timeout=30)
        stopped = True

    removed_files: list[str] = []
    for path in (apply_script_path(), remove_script, DNSMASQ_DROPIN):
        if path.is_file():
            path.unlink()
            removed_files.append(str(path))

    if DNSMASQ_DROPIN not in {Path(p) for p in removed_files} and shutil.which('systemctl'):
        execute(['systemctl', 'try-restart', 'dnsmasq'], check=False, timeout=30)

    return {
        'removed': True,
        'stopped_unit': stopped,
        'removed_files': removed_files,
    }
