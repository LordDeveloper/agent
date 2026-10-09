"""DNS leak prevention for VPN client subnets (WireGuard / Amnezia / L2TP / OpenVPN)."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from agent.adguard import (
    ADGUARD_CONFIG,
    ADS_ENABLED_MARKER,
    DEFAULT_UPSTREAM_DNS,
    adguard_configured,
    adguard_service_active,
    cleanup_legacy_dnsmasq,
    ensure_adguard_resolver,
    ensure_adguard_service,
    isolate_vpn_interfaces_from_host_dns,
    remove_agent_adguard_systemd_unit,
    restore_resolved_stub_listener,
)
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
COMMENT_PREFIX = 'netinja-dns-leak:'
DNS_DUMMY_IFACE = 'agentdns0'
PPP_WILDCARD = 'ppp+'
OPENVPN_SERVER_ROOT = Path('/etc/openvpn/server')
XL2TPD_CONF = Path('/etc/xl2tpd/xl2tpd.conf')
PPP_OPTIONS_PATH = Path('/etc/ppp/options.xl2tpd')
PPP_DNS_HOOK = Path('/etc/ppp/ip-up.d/99-netinja-dns-leak')
_IFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,14}$')
_WILDCARD_IFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.+-]{0,14}$')
_PPP_NAME_RE = re.compile(r'^ppp\d+$', re.I)
_OPENVPN_NAME_RE = re.compile(r'^ovpn\d*$', re.I)

Runner = Callable[..., Any]


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


def _wg_conf_path(name: str) -> Path:
    return Path('/etc/wireguard') / f'{name}.conf'


def _is_mullvad_exit_interface(name: str) -> bool:
    """Mullvad region exits use Table=off; they must not get client DNS DNAT/AdGuard.

    Ads-block previously applied resolvectl dns off + DNAT on these exits, which
    made host health probes (`curl --interface <exit>`) hang on DNS and flap nodes.
    """
    path = _wg_conf_path(name)
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return False
    return bool(re.search(r'(?im)^\s*Table\s*=\s*off\s*$', text))


def _is_wildcard_iface(name: str) -> bool:
    return '+' in name or '*' in name


def _nft_iifname(name: str) -> str:
    """iptables uses ppp+; nftables uses ppp*."""
    if name.endswith('+'):
        return name[:-1] + '*'
    return name


def _looks_like_l2tp_address(text: str) -> bool:
    host = str(text or '').split('/', 1)[0].strip()
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    # Agent L2TP pools reserve third octet >= 128 (see l2tp_ip.is_l2tp_host).
    return int(ip.packed[2]) >= 128


def _is_vpn_interface(row: dict[str, Any]) -> bool:
    name = str(row.get('name') or '').strip()
    if not name or name == DNS_DUMMY_IFACE or _is_mullvad_exit_interface(name):
        return False
    link_type = str(row.get('link_type') or '').strip().lower()
    if link_type == 'wireguard':
        return True
    lowered = name.lower()
    if lowered.startswith('wg') or lowered.startswith('awg'):
        return True
    if _OPENVPN_NAME_RE.match(lowered) or (link_type in {'tun', 'tun6'} and lowered.startswith('ovpn')):
        return True
    if _PPP_NAME_RE.match(lowered):
        # Prefer L2TP PPP sessions; ignore unrelated dial-up/PPPoE when possible.
        if XL2TPD_CONF.is_file():
            addresses = [str(item) for item in (row.get('addresses') or [])]
            if not addresses or any(_looks_like_l2tp_address(item) for item in addresses):
                return True
        return any(_looks_like_l2tp_address(str(item)) for item in (row.get('addresses') or []))
    return False


def _configured_l2tp_gateways() -> list[str]:
    if not XL2TPD_CONF.is_file():
        return []
    try:
        text = XL2TPD_CONF.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    found: list[str] = []
    for match in re.finditer(r'(?im)^\s*local\s+ip\s*=\s*([0-9.]+)\s*$', text):
        gateway = match.group(1).strip()
        if gateway and gateway not in found:
            found.append(gateway)
    return found


def _configured_openvpn_targets() -> list[dict[str, str]]:
    if not OPENVPN_SERVER_ROOT.is_dir():
        return []
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for conf in sorted(OPENVPN_SERVER_ROOT.glob('*.conf')):
        try:
            text = conf.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if 'Managed by Netinja Agent' not in text and 'dev-type tun' not in text:
            # Still accept plain OpenVPN server confs managed on this host.
            if not re.search(r'(?im)^\s*server\s+', text):
                continue
        dev_match = re.search(r'(?im)^\s*dev\s+(\S+)', text)
        server_match = re.search(r'(?im)^\s*server\s+([0-9.]+)\s+([0-9.]+)', text)
        if not dev_match or not server_match:
            continue
        name = dev_match.group(1).strip()
        try:
            network = ipaddress.IPv4Network(
                f'{server_match.group(1)}/{server_match.group(2)}',
                strict=False,
            )
            gateway = str(next(network.hosts()))
        except (ValueError, StopIteration):
            continue
        key = f'{name}:{gateway}'
        if key in seen:
            continue
        seen.add(key)
        rows.append({'name': name, 'gateway': gateway})
    return rows


def _host_ipv4_set(*, runner: Runner | None = None) -> set[str]:
    addrs: set[str] = set()
    for item in list_host_interfaces(runner=runner):
        for raw in item.get('addresses') or []:
            host = str(raw).split('/', 1)[0].strip()
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address):
                addrs.add(str(ip))
    return addrs


def ensure_dns_bind_addresses(
    gateways: list[str],
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Ensure AdGuard can bind VPN gateway IPs even before PPP/OpenVPN clients exist."""
    execute = runner or run
    wanted = [str(item).strip() for item in gateways if str(item).strip()]
    wanted = list(dict.fromkeys(wanted))
    if not wanted:
        return {'ok': True, 'added': [], 'iface': DNS_DUMMY_IFACE, 'skipped': True}

    existing = _host_ipv4_set(runner=runner)
    missing = [gw for gw in wanted if gw not in existing]
    if not missing:
        return {'ok': True, 'added': [], 'iface': DNS_DUMMY_IFACE, 'skipped': True}

    if not shutil.which('ip'):
        return {'ok': False, 'added': [], 'iface': DNS_DUMMY_IFACE, 'error': 'ip not found'}

    execute(['ip', 'link', 'add', 'name', DNS_DUMMY_IFACE, 'type', 'dummy'], check=False, timeout=10)
    execute(['ip', 'link', 'set', 'dev', DNS_DUMMY_IFACE, 'up'], check=False, timeout=10)
    added: list[str] = []
    for gateway in missing:
        proc = execute(
            ['ip', 'addr', 'add', f'{gateway}/32', 'dev', DNS_DUMMY_IFACE],
            check=False,
            timeout=10,
        )
        if getattr(proc, 'returncode', 1) == 0:
            added.append(gateway)
        else:
            # Already present (race) still counts as success.
            if gateway in _host_ipv4_set(runner=runner):
                added.append(gateway)
    return {'ok': True, 'added': added, 'iface': DNS_DUMMY_IFACE, 'missing': missing}


def discover_vpn_interfaces(*, runner: Runner | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_gateways: set[str] = set()

    for item in list_host_interfaces(runner=runner):
        if not _is_vpn_interface(item):
            continue
        gateway = _interface_ipv4(list(item.get('addresses') or []))
        if not gateway:
            continue
        name = str(item['name'])
        rows.append(
            {
                'name': name,
                'gateway': gateway,
                'addresses': list(item.get('addresses') or []),
                'link_type': item.get('link_type'),
            }
        )
        seen_names.add(name.lower())
        seen_gateways.add(gateway)

    for gateway in _configured_l2tp_gateways():
        if gateway in seen_gateways:
            continue
        rows.append(
            {
                'name': PPP_WILDCARD,
                'gateway': gateway,
                'addresses': [f'{gateway}/32'],
                'link_type': 'ppp',
            }
        )
        seen_gateways.add(gateway)

    for target in _configured_openvpn_targets():
        name = target['name']
        gateway = target['gateway']
        if name.lower() in seen_names or gateway in seen_gateways:
            continue
        rows.append(
            {
                'name': name,
                'gateway': gateway,
                'addresses': [f'{gateway}/24'],
                'link_type': 'tun',
            }
        )
        seen_names.add(name.lower())
        seen_gateways.add(gateway)

    # If any L2TP PPP sessions exist, always include wildcard DNAT target once.
    if any(_PPP_NAME_RE.match(str(row.get('name') or '')) for row in rows):
        if not any(str(row.get('name') or '') == PPP_WILDCARD for row in rows):
            gateway = next(
                (str(row.get('gateway') or '') for row in rows if _PPP_NAME_RE.match(str(row.get('name') or ''))),
                '',
            )
            if gateway:
                rows.append(
                    {
                        'name': PPP_WILDCARD,
                        'gateway': gateway,
                        'addresses': [f'{gateway}/32'],
                        'link_type': 'ppp',
                    }
                )

    return rows


def apply_script_path(data_dir: str | Path | None = None) -> Path:
    base = Path(data_dir or os.environ.get('DATA_DIR') or '/var/lib/agent')
    return base / 'dns-leak-apply.sh'


def render_apply_script(
    interfaces: list[dict[str, Any]],
    *,
    block_ipv6: bool = False,
) -> str:
    lines = [
        '#!/bin/sh',
        '# Generated by Netinja agent — DNS leak prevention. Do not edit.',
        'set +e',
        '',
        '_iface_ready() {',
        '  case "$1" in',
        '    *[+]*|*[\\*]*) return 0 ;;',
        '  esac',
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
            nft_name = _nft_iifname(name)
            comment = f'{COMMENT_PREFIX}{name}'.replace('+', 'x').replace('*', 'x')
            lines.append(f'if _iface_ready "{name}"; then')
            lines.append(
                f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} iifname "{nft_name}" '
                f'udp dport 53 dnat ip to {gateway}:53 comment "{comment}-udp" 2>/dev/null || true'
            )
            lines.append(
                f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_PREROUTING} iifname "{nft_name}" '
                f'tcp dport 53 dnat ip to {gateway}:53 comment "{comment}-tcp" 2>/dev/null || true'
            )
            if block_ipv6 and not _is_wildcard_iface(name):
                lines.append(
                    f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_FORWARD} iifname "{nft_name}" '
                    f'ip6 saddr != :: drop comment "{comment}-no-v6" 2>/dev/null || true'
                )
                lines.append(
                    f'  nft add rule inet {NFT_TABLE} {NFT_CHAIN_FORWARD} oifname "{nft_name}" '
                    f'ip6 daddr != :: drop comment "{comment}-no-v6-out" 2>/dev/null || true'
                )
            if not _is_wildcard_iface(name):
                lines.append(
                    f'  if command -v resolvectl >/dev/null 2>&1; then resolvectl dns "{name}" off 2>/dev/null || true; fi'
                )
                lines.append(
                    f'  if command -v resolvectl >/dev/null 2>&1; then resolvectl domain "{name}" off 2>/dev/null || true; fi'
                )
            lines.append('fi')
        lines.append('fi')
        lines.append('')

    lines.append('if command -v iptables >/dev/null 2>&1; then')
    for row in interfaces:
        name = str(row['name'])
        gateway = str(row['gateway'])
        comment = f'{COMMENT_PREFIX}{name}'.replace('+', 'x').replace('*', 'x')
        lines.append(f'if _iface_ready "{name}"; then')
        for proto in ('udp', 'tcp'):
            lines.append(
                f'  iptables -t nat -C PREROUTING -i "{name}" -p {proto} --dport 53 '
                f'-m comment --comment "{comment}-{proto}" -j DNAT --to-destination {gateway}:53 '
                f'2>/dev/null || iptables -t nat -A PREROUTING -i "{name}" -p {proto} --dport 53 '
                f'-m comment --comment "{comment}-{proto}" -j DNAT --to-destination {gateway}:53'
            )
        if block_ipv6 and shutil.which('ip6tables') and not _is_wildcard_iface(name):
            lines.append(
                f'  ip6tables -C FORWARD -i "{name}" -m comment --comment "{comment}-no-v6" -j DROP '
                f'2>/dev/null || ip6tables -A FORWARD -i "{name}" -m comment --comment "{comment}-no-v6" -j DROP'
            )
            lines.append(
                f'  ip6tables -C FORWARD -o "{name}" -m comment --comment "{comment}-no-v6-out" -j DROP '
                f'2>/dev/null || ip6tables -A FORWARD -o "{name}" -m comment --comment "{comment}-no-v6-out" -j DROP'
            )
        if not _is_wildcard_iface(name):
            lines.append(
                f'  if command -v resolvectl >/dev/null 2>&1; then resolvectl dns "{name}" off 2>/dev/null || true; fi'
            )
            lines.append(
                f'  if command -v resolvectl >/dev/null 2>&1; then resolvectl domain "{name}" off 2>/dev/null || true; fi'
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
        if not (_WILDCARD_IFACE_RE.match(name) or _IFACE_RE.match(name)):
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
            'No WireGuard/Amnezia/L2TP/OpenVPN interfaces detected. Pass --interface explicitly.',
        )
    return discovered


def _dns_leak_active(*, runner: Runner | None = None) -> bool:
    if UNIT_PATH.is_file() or apply_script_path().is_file():
        return True
    return _nft_table_exists(runner=runner)


def preferred_client_dns(*, runner: Runner | None = None) -> list[str]:
    """DNS servers pushed to L2TP/OpenVPN clients (AdGuard gateways when active)."""
    if not (ADS_ENABLED_MARKER.is_file() or _dns_leak_active(runner=runner)):
        return list(DEFAULT_UPSTREAM_DNS)
    try:
        interfaces = discover_vpn_interfaces(runner=runner)
    except AgentError:
        interfaces = []
    dns: list[str] = []
    for row in interfaces:
        gateway = str(row.get('gateway') or '').strip()
        if gateway and gateway not in dns:
            dns.append(gateway)
        if len(dns) >= 2:
            break
    return dns or list(DEFAULT_UPSTREAM_DNS)


def rewrite_ms_dns_options(text: str, dns_servers: list[str]) -> str:
    servers = list(dict.fromkeys(str(item).strip() for item in dns_servers if str(item).strip()))
    if not servers:
        servers = list(DEFAULT_UPSTREAM_DNS)
    lines: list[str] = []
    inserted = False
    for line in str(text or '').replace('\r\n', '\n').splitlines():
        if line.strip().lower().startswith('ms-dns'):
            if not inserted:
                for dns in servers:
                    lines.append(f'ms-dns {dns}')
                inserted = True
            continue
        lines.append(line)
    if not inserted:
        for dns in servers:
            lines.append(f'ms-dns {dns}')
    return '\n'.join(lines) + '\n'


def rewrite_openvpn_dns_push(text: str, dns_servers: list[str]) -> str:
    servers = list(dict.fromkeys(str(item).strip() for item in dns_servers if str(item).strip()))
    if not servers:
        servers = list(DEFAULT_UPSTREAM_DNS)
    lines: list[str] = []
    inserted = False
    for line in str(text or '').replace('\r\n', '\n').splitlines():
        if re.search(r'(?i)push\s+"dhcp-option\s+DNS\s+', line):
            if not inserted:
                for dns in servers:
                    lines.append(f'push "dhcp-option DNS {dns}"')
                inserted = True
            continue
        lines.append(line)
    if not inserted:
        # Insert after redirect-gateway when present.
        out: list[str] = []
        for line in lines:
            out.append(line)
            if (not inserted) and 'redirect-gateway' in line:
                for dns in servers:
                    out.append(f'push "dhcp-option DNS {dns}"')
                inserted = True
        lines = out
    if not inserted:
        for dns in servers:
            lines.append(f'push "dhcp-option DNS {dns}"')
    return '\n'.join(lines) + '\n'


def ensure_ppp_dns_hook(*, runner: Runner | None = None) -> dict[str, Any]:
    """Re-apply DNS DNAT when L2TP PPP sessions appear."""
    del runner  # hook is pure filesystem
    script = apply_script_path()
    content = (
        '#!/bin/sh\n'
        '# Managed by Netinja Agent — refresh DNS leak DNAT after PPP up\n'
        f'SCRIPT="{script}"\n'
        'if [ -x "$SCRIPT" ]; then\n'
        '  "$SCRIPT" >/dev/null 2>&1 || true\n'
        'fi\n'
    )
    try:
        PPP_DNS_HOOK.parent.mkdir(parents=True, exist_ok=True)
        previous = PPP_DNS_HOOK.read_text(encoding='utf-8') if PPP_DNS_HOOK.is_file() else ''
        if previous != content:
            PPP_DNS_HOOK.write_text(content, encoding='utf-8')
        PPP_DNS_HOOK.chmod(0o755)
        return {'ok': True, 'path': str(PPP_DNS_HOOK), 'script': str(script)}
    except OSError as exc:
        log.warning('dns_leak ppp ip-up hook install failed: %s', exc)
        return {'ok': False, 'error': str(exc)}


def sync_client_dns_push(
    dns_servers: list[str] | None = None,
    *,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Point L2TP ms-dns and OpenVPN dhcp-option DNS at AdGuard (or defaults)."""
    execute = runner or run
    dns = [str(item).strip() for item in (dns_servers or preferred_client_dns(runner=runner)) if str(item).strip()]
    if not dns:
        dns = list(DEFAULT_UPSTREAM_DNS)

    updated: list[str] = []
    if PPP_OPTIONS_PATH.is_file():
        try:
            previous = PPP_OPTIONS_PATH.read_text(encoding='utf-8', errors='ignore')
            rewritten = rewrite_ms_dns_options(previous, dns)
            if rewritten != previous:
                PPP_OPTIONS_PATH.write_text(rewritten, encoding='utf-8')
                updated.append(str(PPP_OPTIONS_PATH))
        except OSError as exc:
            log.warning('dns_leak: failed to rewrite %s: %s', PPP_OPTIONS_PATH, exc)

    reloaded: list[str] = []
    if OPENVPN_SERVER_ROOT.is_dir():
        for conf in sorted(OPENVPN_SERVER_ROOT.glob('*.conf')):
            try:
                previous = conf.read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            if not re.search(r'(?im)^\s*server\s+', previous):
                continue
            rewritten = rewrite_openvpn_dns_push(previous, dns)
            if rewritten == previous:
                continue
            try:
                conf.write_text(rewritten, encoding='utf-8')
            except OSError as exc:
                log.warning('dns_leak: failed to rewrite %s: %s', conf, exc)
                continue
            updated.append(str(conf))
            instance = conf.stem
            unit = f'openvpn-server@{instance}.service'
            if shutil.which('systemctl'):
                proc = execute(['systemctl', 'reload', unit], check=False, timeout=30)
                if getattr(proc, 'returncode', 1) != 0:
                    execute(['systemctl', 'restart', unit], check=False, timeout=60)
                reloaded.append(unit)

    return {'ok': True, 'dns': dns, 'updated': updated, 'reloaded': reloaded}


def _write_apply_script(
    interfaces: list[dict[str, Any]],
    *,
    data_dir: str | Path | None = None,
    block_ipv6: bool = False,
) -> Path:
    path = apply_script_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_apply_script(interfaces, block_ipv6=block_ipv6), encoding='utf-8')
    try:
        path.chmod(0o755)
    except OSError:
        pass
    return path


def _ensure_adguard(
    interfaces: list[dict[str, Any]],
    *,
    upstream: tuple[str, ...] = DEFAULT_UPSTREAM_DNS,
    filtering_enabled: bool = False,
    user_rules: list[str] | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    cleanup_legacy_dnsmasq(runner=runner)
    resolver = ensure_adguard_resolver(
        interfaces,
        upstream=upstream,
        filtering_enabled=filtering_enabled,
        user_rules=user_rules,
        runner=runner,
    )
    return resolver


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
    block_ipv6: bool = False,
    upstream_dns: list[str] | None = None,
    filtering_enabled: bool | None = None,
    user_rules: list[str] | None = None,
    with_dnat: bool = True,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Run AdGuard Home on VPN gateway IP(s) and optionally DNAT client DNS to it."""
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
    ads_filtering = ADS_ENABLED_MARKER.is_file() if filtering_enabled is None else bool(filtering_enabled)
    gateways = [str(row.get('gateway') or '').strip() for row in targets if str(row.get('gateway') or '').strip()]
    bind = ensure_dns_bind_addresses(gateways, runner=runner)
    resolver = _ensure_adguard(
        targets,
        upstream=upstream,
        filtering_enabled=ads_filtering,
        user_rules=user_rules,
        runner=runner,
    )
    resolver['bind_addresses'] = bind
    host_dns = isolate_vpn_interfaces_from_host_dns(targets, runner=runner)
    if host_dns:
        resolver['host_dns_isolated'] = host_dns

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

    push = sync_client_dns_push(gateways or list(upstream), runner=runner)
    hook = ensure_ppp_dns_hook(runner=runner)

    return {
        'ok': True,
        'interfaces': targets,
        'resolver': resolver,
        'dnat': dnat,
        'client_dns_push': push,
        'ppp_hook': hook,
        'block_ipv6': block_ipv6,
        'filtering_enabled': ads_filtering,
    }


def dns_leak_apply(
    *,
    interfaces: list[str] | None = None,
    block_ipv6: bool = False,
    with_resolver: bool = True,
    upstream_dns: list[str] | None = None,
    data_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    _require_linux()
    _require_root()
    if _firewall_backend() is None:
        raise AgentError('VALIDATION_ERROR', 'nft or iptables is required for DNS leak protection')

    targets = _resolve_targets(interfaces, runner=runner)
    gateways = [str(row.get('gateway') or '').strip() for row in targets if str(row.get('gateway') or '').strip()]
    ensure_dns_bind_addresses(gateways, runner=runner)
    script = _write_apply_script(targets, data_dir=data_dir, block_ipv6=block_ipv6)
    execute = runner or run
    proc = execute(['/bin/sh', str(script)], check=False, timeout=120)
    unit = ensure_dns_leak_unit(script, runner=runner)
    push = sync_client_dns_push(gateways or list(upstream_dns or DEFAULT_UPSTREAM_DNS), runner=runner)
    hook = ensure_ppp_dns_hook(runner=runner)

    resolver: dict[str, Any] | None = None
    if with_resolver:
        upstream = tuple(upstream_dns or DEFAULT_UPSTREAM_DNS)
        resolver = _ensure_adguard(targets, upstream=upstream, filtering_enabled=False, runner=runner)

    return {
        'applied': proc.returncode == 0,
        'interfaces': targets,
        'script': str(script),
        'unit': unit,
        'block_ipv6': block_ipv6,
        'backend': _firewall_backend(),
        'resolver': resolver,
        'client_dns_push': push,
        'ppp_hook': hook,
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
        'adguard_config': str(ADGUARD_CONFIG),
        'adguard_configured': adguard_configured(),
        'adguard_active': adguard_service_active(runner=runner),
        'interfaces': interfaces,
    }


def _vpn_dns_still_needed(*, runner: Runner | None = None) -> bool:
    if ADS_ENABLED_MARKER.is_file():
        return True
    return _nft_table_exists(runner=runner) or UNIT_PATH.is_file()


def teardown_vpn_dns_if_unused(*, runner: Runner | None = None) -> dict[str, Any]:
    """Remove AdGuard VPN resolver and restore host DNS when leak/ads are both off."""
    removed_files: list[str] = []
    resolved_restored = False

    if _vpn_dns_still_needed(runner=runner):
        return {
            'removed_files': removed_files,
            'resolved_restored': resolved_restored,
            'skipped': True,
        }

    if ADGUARD_CONFIG.is_file():
        ADGUARD_CONFIG.unlink()
        removed_files.append(str(ADGUARD_CONFIG))

    cleanup_legacy_dnsmasq(runner=runner)
    resolved_restored = restore_resolved_stub_listener(runner=runner)
    agent_unit_removed = remove_agent_adguard_systemd_unit(runner=runner)

    return {
        'removed_files': removed_files,
        'resolved_restored': resolved_restored,
        'agent_unit_removed': agent_unit_removed,
        'skipped': False,
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
    for path in (apply_script_path(), remove_script):
        if path.is_file():
            path.unlink()
            removed_files.append(str(path))

    cleanup = teardown_vpn_dns_if_unused(runner=runner)
    removed_files.extend(cleanup.get('removed_files') or [])
    push: dict[str, Any] | None = None
    if not cleanup.get('skipped'):
        push = sync_client_dns_push(list(DEFAULT_UPSTREAM_DNS), runner=runner)

    return {
        'removed': True,
        'stopped_unit': stopped,
        'removed_files': removed_files,
        'resolved_restored': cleanup.get('resolved_restored'),
        'cleanup': cleanup,
        'client_dns_push': push,
    }
