"""Render OpenVPN server/client configs, certs, auth script, and CCD."""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any

from agent.errors import AgentError
from agent.support import record_is_enabled
from agent.support.openvpn_ip import openvpn_gateway, openvpn_netmask, normalize_openvpn_subnet

_SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$')
_TLS_CRYPT_BEGIN = '-----BEGIN OpenVPN Static key V1-----'
_TLS_CRYPT_END = '-----END OpenVPN Static key V1-----'
_TLS_CRYPT_BLOCK = re.compile(
    r'-----BEGIN OpenVPN Static key V1-----(.*?)-----END OpenVPN Static key V1-----',
    re.IGNORECASE | re.DOTALL,
)
_TLS_CRYPT_HEX_LEN = 512  # 2048-bit OpenVPN static key


def tls_crypt_hex(value: Any) -> str:
    text = str(value or '')
    match = _TLS_CRYPT_BLOCK.search(text)
    body = match.group(1) if match else text
    return re.sub(r'[^0-9A-Fa-f]', '', body)


def normalize_tls_crypt(value: Any) -> str:
    """PEM-only tls-crypt (no comments). Hex body hashes then match client.ovpn and tc.key."""
    hexed = tls_crypt_hex(value)
    if len(hexed) < _TLS_CRYPT_HEX_LEN:
        return ''
    lines = [hexed[i : i + 32] for i in range(0, len(hexed), 32)]
    return _TLS_CRYPT_BEGIN + '\n' + '\n'.join(lines) + '\n' + _TLS_CRYPT_END


def render_tls_crypt_key() -> str:
    return normalize_tls_crypt(secrets.token_bytes(256).hex())


def _read_utf8(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return ''


def sanitize_instance_name(value: Any, *, fallback: str = 'ovpn') -> str:
    text = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip()).strip('-_.')
    if not text or not _SAFE_NAME.match(text):
        text = fallback
    return text[:32]


def tun_dev_for_server(server: dict[str, Any]) -> str:
    explicit = str(server.get('tun_dev') or '').strip()
    if explicit and _SAFE_NAME.match(explicit):
        return explicit
    sid = server.get('id')
    return f'ovpn{sid}' if sid is not None else 'ovpn0'


def instance_name_for_server(server: dict[str, Any]) -> str:
    explicit = str(server.get('instance') or '').strip()
    if explicit:
        return sanitize_instance_name(explicit, fallback=f"ovpn{server.get('id') or 0}")
    return sanitize_instance_name(server.get('name') or f"ovpn{server.get('id') or 0}")


async def _run_openssl(args: list[str], *, cwd: Path | None = None) -> None:
    from agent.support.process import run

    try:
        proc = await run(
            ['openssl', *args],
            timeout=60,
            check=False,
            env=None,
        )
    except FileNotFoundError as exc:
        raise AgentError('VALIDATION_ERROR', 'openssl is required to issue OpenVPN certificates', 500) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or 'openssl failed').strip()
        raise AgentError('EXEC_ERROR', f'openssl failed: {detail[:400]}', 500)


async def ensure_server_pki(pki_dir: Path, *, common_name: str = 'netinja-openvpn') -> dict[str, str]:
    """Create CA + server cert/key (+ tls-crypt key) under pki_dir if missing."""
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca_key = pki_dir / 'ca.key'
    ca_crt = pki_dir / 'ca.crt'
    server_key = pki_dir / 'server.key'
    server_crt = pki_dir / 'server.crt'
    tls_crypt = pki_dir / 'tc.key'
    # dh.pem unused: server conf uses `dh none` (ECDH). Never run openssl dhparam.

    if not ca_crt.is_file():
        if not ca_key.is_file():
            await _run_openssl(['genrsa', '-out', str(ca_key), '2048'])
            try:
                ca_key.chmod(0o600)
            except OSError:
                pass
        await _run_openssl(
            [
                'req',
                '-new',
                '-x509',
                '-days',
                '3650',
                '-key',
                str(ca_key),
                '-out',
                str(ca_crt),
                '-subj',
                f'/CN={common_name}-ca',
            ]
        )

    if not server_crt.is_file() or not server_key.is_file():
        if server_crt.is_file() and not server_key.is_file():
            raise AgentError(
                'VALIDATION_ERROR',
                f'OpenVPN server certificate exists without its key in {pki_dir}',
                422,
            )
        if not ca_key.is_file() or not ca_crt.is_file():
            raise AgentError(
                'VALIDATION_ERROR',
                f'OpenVPN CA material is incomplete in {pki_dir}',
                422,
            )
        req = pki_dir / 'server.csr'
        if not server_key.is_file():
            await _run_openssl(['genrsa', '-out', str(server_key), '2048'])
        await _run_openssl(
            [
                'req',
                '-new',
                '-key',
                str(server_key),
                '-out',
                str(req),
                '-subj',
                f'/CN={common_name}-server',
            ]
        )
        await _run_openssl(
            [
                'x509',
                '-req',
                '-days',
                '3650',
                '-in',
                str(req),
                '-CA',
                str(ca_crt),
                '-CAkey',
                str(ca_key),
                '-CAcreateserial',
                '-out',
                str(server_crt),
            ]
        )
        try:
            server_key.chmod(0o600)
            req.unlink(missing_ok=True)
        except OSError:
            pass

    existing_tls = normalize_tls_crypt(_read_utf8(tls_crypt) if tls_crypt.is_file() else '')
    if not existing_tls:
        generated = await _generate_tls_crypt_file(tls_crypt)
        existing_tls = generated
    elif existing_tls != _read_utf8(tls_crypt).strip():
        tls_crypt.write_text(existing_tls + '\n', encoding='utf-8')
        try:
            tls_crypt.chmod(0o600)
        except OSError:
            pass

    # dh.pem is unused: server conf uses `dh none` (ECDH). Skip openssl dhparam.

    return {
        'ca_crt': _read_utf8(ca_crt),
        'ca_key': _read_utf8(ca_key),
        'server_crt': _read_utf8(server_crt),
        'server_key': _read_utf8(server_key),
        'tls_crypt': existing_tls,
        'dh_pem': '',
    }


async def _generate_tls_crypt_file(path: Path) -> str:
    from agent.support.process import run

    attempts = (
        ['openvpn', '--genkey', 'secret', str(path)],
        ['openvpn', '--genkey', '--secret', str(path)],
    )
    for args in attempts:
        try:
            proc = await run(args, check=False, timeout=30)
        except FileNotFoundError:
            break
        if proc.returncode == 0:
            normalized = normalize_tls_crypt(_read_utf8(path))
            if normalized:
                path.write_text(normalized + '\n', encoding='utf-8')
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
                return normalized

    pem = render_tls_crypt_key()
    path.write_text(pem + '\n', encoding='utf-8')
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return pem


AUTH_SCRIPT = r'''#!/bin/sh
# Netinja OpenVPN auth-user-pass-verify (via-file).
# OpenVPN passes a temp file path whose first line is username and second is password.
set -eu
PASSWD="$(CDPATH= cd -- "$(dirname "$0")" && pwd)/passwd"
CREDS="${1:-}"

if [ -z "$CREDS" ] || [ ! -f "$CREDS" ] || [ ! -f "$PASSWD" ]; then
  exit 1
fi

username=$(sed -n '1p' "$CREDS" | tr -d '\r')
password=$(sed -n '2p' "$CREDS" | tr -d '\r')
if [ -z "$username" ]; then
  exit 1
fi

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|\#*) continue ;;
  esac
  user=${line%% *}
  secret=${line#* }
  if [ "$user" = "$username" ] && [ "$secret" = "$password" ]; then
    exit 0
  fi
done < "$PASSWD"
exit 1
'''


def render_passwd(servers: list[dict[str, Any]], *, server_id: Any = None) -> str:
    lines = ['# Managed by Netinja Agent — username password']
    for server in servers:
        if server_id is not None and str(server.get('id')) != str(server_id):
            continue
        for user in server.get('users') or []:
            if not isinstance(user, dict) or not record_is_enabled(user):
                continue
            username = str(user.get('username') or '').strip()
            password = str(user.get('password') or '')
            if not username:
                continue
            # Passwords must not contain newlines; spaces are kept (reader splits on first space).
            password = password.replace('\r', '').replace('\n', '')
            lines.append(f'{username} {password}')
    return '\n'.join(lines) + '\n'


def render_ccd_file(user: dict[str, Any], *, subnet: str) -> str:
    address = str(user.get('address') or '').split('/', 1)[0].strip()
    if not address:
        return ''
    netmask = openvpn_netmask(subnet)
    return f'ifconfig-push {address} {netmask}\n'


def render_server_conf(
    server: dict[str, Any],
    *,
    server_dir: str | Path,
    auth_script: str | Path,
    dns_servers: list[str] | None = None,
) -> str:
    """Render server .conf for Debian/Ubuntu openvpn-server@ units.

    Status file is left to systemd ExecStart (--status %t/openvpn-server/...),
    which avoids nobody write failures under ProtectSystem.
    """
    subnet = normalize_openvpn_subnet(str(server.get('subnet') or '10.8.0.0/24'))
    network = subnet.split('/')[0]
    netmask = openvpn_netmask(subnet)
    port = int(server.get('listen_port') or 1194)
    proto = str(server.get('proto') or 'udp').strip().lower()
    if proto not in {'udp', 'tcp'}:
        proto = 'udp'
    tun = tun_dev_for_server(server)
    root = Path(server_dir)
    script = Path(auth_script)

    if dns_servers is None:
        try:
            from agent.dns_leak import sync_preferred_client_dns

            dns_servers = sync_preferred_client_dns()
        except Exception:
            dns_servers = ['1.1.1.1', '8.8.8.8']
    if not dns_servers:
        dns_servers = ['1.1.1.1', '8.8.8.8']

    lines = [
        '# Managed by Netinja Agent',
        f'port {port}',
        f'proto {proto}',
        'dev-type tun',
        f'dev {tun}',
        'topology subnet',
        f'server {network} {netmask}',
        f'ca {root / "ca.crt"}',
        f'cert {root / "server.crt"}',
        f'key {root / "server.key"}',
        'dh none',
        f'tls-crypt {root / "tc.key"}',
        f'client-config-dir {root / "ccd"}',
        'duplicate-cn',
        'username-as-common-name',
        'verify-client-cert none',
        'script-security 2',
        f'auth-user-pass-verify {script} via-file',
        'push "redirect-gateway def1 bypass-dhcp"',
    ]
    for dns in dns_servers[:2]:
        lines.append(f'push "dhcp-option DNS {dns}"')
    lines.extend(
        [
            'keepalive 10 60',
            'persist-key',
            'persist-tun',
            'verb 3',
            'explicit-exit-notify 1' if proto == 'udp' else '# tcp mode',
        ]
    )
    return '\n'.join(lines) + '\n'


def render_client_ovpn(
    server: dict[str, Any],
    user: dict[str, Any],
    *,
    endpoint_host: str,
    ca_crt: str,
    tls_crypt: str = '',
    dns_servers: list[str] | None = None,
) -> str:
    host = str(endpoint_host or server.get('public_host') or '127.0.0.1').strip()
    port = int(server.get('listen_port') or 1194)
    proto = str(server.get('proto') or 'udp').strip().lower()
    if proto not in {'udp', 'tcp'}:
        proto = 'udp'
    username = str(user.get('username') or '')
    password = str(user.get('password') or '')

    blocks = [
        'client',
        'dev tun',
        f'proto {proto}',
        f'remote {host} {port}',
        'resolv-retry infinite',
        'nobind',
        'persist-key',
        'persist-tun',
        'remote-cert-tls server',
        'verb 3',
        '<ca>',
        ca_crt.strip(),
        '</ca>',
    ]
    tls_block = normalize_tls_crypt(tls_crypt)
    if tls_block:
        blocks.extend(['<tls-crypt>', tls_block, '</tls-crypt>'])
    # When ads-block / DNS leak is active, embed AdGuard gateway DNS in the
    # client profile (server push alone is easy to miss after an early ensure).
    try:
        from agent.adguard import ADS_ENABLED_MARKER
        from agent.dns_leak import sync_preferred_client_dns

        if ADS_ENABLED_MARKER.is_file():
            servers = dns_servers if dns_servers is not None else sync_preferred_client_dns()
            for dns in servers[:1]:
                dns = str(dns).strip()
                if dns:
                    blocks.append(f'dhcp-option DNS {dns}')
                    break
    except Exception:
        pass
    # Bare auth-user-pass keeps username/password editable in OpenVPN Connect.
    # Credentials stay in comments + Telegram caption — never lock them into the profile.
    blocks.append('auth-user-pass')
    blocks.extend(
        [
            f'# username: {username}',
            f'# password: {password}',
            f'# assigned_ip: {user.get("address") or ""}',
        ]
    )
    return '\n'.join(blocks) + '\n'


def _status_int(value: str) -> int:
    text = str(value or '').strip()
    return int(text) if text.isdigit() else 0


def _status_field(parts: list[str], header_index: dict[str, int], name: str, fallback: int) -> str:
    """Map a HEADER,CLIENT_LIST column onto a CLIENT_LIST row (header has an extra HEADER token)."""
    index = header_index.get(name.lower())
    if index is not None:
        data_index = index - 1
        if 0 <= data_index < len(parts):
            return parts[data_index].strip()
    if 0 <= fallback < len(parts):
        return parts[fallback].strip()
    return ''


def parse_status_v2(text: str) -> list[dict[str, Any]]:
    """Parse OpenVPN status-version 2 into session rows keyed by Common Name / Virtual Address.

    OpenVPN 2.5+ inserts Virtual IPv6 Address before the byte counters. Fixed indexes then
    treat upload as download and drop the real download column.
    """
    rows: list[dict[str, Any]] = []
    header_index: dict[str, int] = {}
    in_clients = False
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('HEADER,CLIENT_LIST'):
            header_index = {
                part.strip().lower(): index
                for index, part in enumerate(line.split(','))
            }
            in_clients = True
            continue
        if line.startswith('HEADER,') or line.startswith('GLOBAL') or line.startswith('END') or line.startswith('TITLE'):
            in_clients = False
            continue
        if not in_clients or not line.startswith('CLIENT_LIST,'):
            continue
        parts = line.split(',')
        if len(parts) < 6:
            continue
        rows.append(
            {
                'username': _status_field(parts, header_index, 'common name', 1),
                'real_address': _status_field(parts, header_index, 'real address', 2),
                'virtual_address': _status_field(parts, header_index, 'virtual address', 3),
                'bytes_received': _status_int(_status_field(parts, header_index, 'bytes received', 4)),
                'bytes_sent': _status_int(_status_field(parts, header_index, 'bytes sent', 5)),
            }
        )
    return rows
