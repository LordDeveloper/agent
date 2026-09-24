"""Render OpenVPN server/client configs, certs, auth script, and CCD."""

from __future__ import annotations

import re
import secrets
import subprocess
from pathlib import Path
from typing import Any

from agent.errors import AgentError
from agent.support import record_is_enabled
from agent.support.openvpn_ip import openvpn_gateway, openvpn_netmask, normalize_openvpn_subnet

_SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$')


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


def _run_openssl(args: list[str], *, cwd: Path | None = None) -> None:
    try:
        proc = subprocess.run(
            ['openssl', *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AgentError('VALIDATION_ERROR', 'openssl is required to issue OpenVPN certificates', 500) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or 'openssl failed').strip()
        raise AgentError('EXEC_ERROR', f'openssl failed: {detail[:400]}', 500)


def ensure_server_pki(pki_dir: Path, *, common_name: str = 'netinja-openvpn') -> dict[str, str]:
    """Create CA + server cert/key (+ tls-crypt key) under pki_dir if missing."""
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca_key = pki_dir / 'ca.key'
    ca_crt = pki_dir / 'ca.crt'
    server_key = pki_dir / 'server.key'
    server_crt = pki_dir / 'server.crt'
    tls_crypt = pki_dir / 'tc.key'
    dh = pki_dir / 'dh.pem'

    if not ca_key.is_file() or not ca_crt.is_file():
        _run_openssl(['genrsa', '-out', str(ca_key), '2048'])
        _run_openssl(
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
        try:
            ca_key.chmod(0o600)
        except OSError:
            pass

    if not server_key.is_file() or not server_crt.is_file():
        req = pki_dir / 'server.csr'
        _run_openssl(['genrsa', '-out', str(server_key), '2048'])
        _run_openssl(
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
        _run_openssl(
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

    if not tls_crypt.is_file():
        # Prefer openvpn --genkey; fall back to openssl rand.
        try:
            proc = subprocess.run(
                ['openvpn', '--genkey', 'secret', str(tls_crypt)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0 or not tls_crypt.is_file():
                raise FileNotFoundError('openvpn genkey failed')
        except FileNotFoundError:
            tls_crypt.write_bytes(secrets.token_bytes(256))
        try:
            tls_crypt.chmod(0o600)
        except OSError:
            pass

    # Optional DH for older clients; modern OpenVPN prefers ECDH.
    if not dh.is_file():
        try:
            _run_openssl(['dhparam', '-out', str(dh), '2048'])
        except AgentError:
            dh.write_text('', encoding='utf-8')

    return {
        'ca_crt': ca_crt.read_text(encoding='utf-8'),
        'ca_key': ca_key.read_text(encoding='utf-8'),
        'server_crt': server_crt.read_text(encoding='utf-8'),
        'server_key': server_key.read_text(encoding='utf-8'),
        'tls_crypt': tls_crypt.read_text(encoding='utf-8') if tls_crypt.is_file() else '',
        'dh_pem': dh.read_text(encoding='utf-8') if dh.is_file() else '',
    }


AUTH_SCRIPT = r'''#!/usr/bin/python3
"""Netinja OpenVPN auth-user-pass-verify (via-env)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

PASSWD = Path(__file__).resolve().parent / "passwd"


def main() -> int:
    username = (os.environ.get("username") or "").strip()
    password = os.environ.get("password") or ""
    if not username or not PASSWD.is_file():
        return 1
    try:
        lines = PASSWD.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 1
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if " " not in text:
            continue
        user, secret = text.split(" ", 1)
        if user == username and secret == password:
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
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
            # Spaces in password would break the simple passwd format.
            password = password.replace(' ', '')
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
        f'auth-user-pass-verify {script} via-env',
        'push "redirect-gateway def1 bypass-dhcp"',
        'push "dhcp-option DNS 1.1.1.1"',
        'push "dhcp-option DNS 8.8.8.8"',
        'keepalive 10 60',
        'persist-key',
        'persist-tun',
        'verb 3',
        'explicit-exit-notify 1' if proto == 'udp' else '# tcp mode',
    ]
    return '\n'.join(lines) + '\n'


def render_client_ovpn(
    server: dict[str, Any],
    user: dict[str, Any],
    *,
    endpoint_host: str,
    ca_crt: str,
    tls_crypt: str = '',
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
        'auth-user-pass',
        'verb 3',
        '<ca>',
        ca_crt.strip(),
        '</ca>',
    ]
    if tls_crypt.strip():
        blocks.extend(['<tls-crypt>', tls_crypt.strip(), '</tls-crypt>'])
    # Inline credentials for panel convenience (optional auth file style).
    blocks.extend(
        [
            f'# username: {username}',
            f'# password: {password}',
            f'# assigned_ip: {user.get("address") or ""}',
        ]
    )
    return '\n'.join(blocks) + '\n'


def parse_status_v2(text: str) -> list[dict[str, Any]]:
    """Parse OpenVPN status-version 2 into session rows keyed by Common Name / Virtual Address."""
    rows: list[dict[str, Any]] = []
    section = ''
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('HEADER,CLIENT_LIST'):
            section = 'client'
            continue
        if line.startswith('HEADER,ROUTING_TABLE'):
            section = 'routing'
            continue
        if line.startswith('GLOBAL') or line.startswith('END') or line.startswith('TITLE'):
            section = ''
            continue
        if section != 'client' or not line.startswith('CLIENT_LIST,'):
            continue
        parts = line.split(',')
        # CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,...
        if len(parts) < 6:
            continue
        rows.append(
            {
                'username': parts[1].strip(),
                'real_address': parts[2].strip(),
                'virtual_address': parts[3].strip(),
                'bytes_received': int(parts[4] or 0) if str(parts[4]).isdigit() else 0,
                'bytes_sent': int(parts[5] or 0) if str(parts[5]).isdigit() else 0,
            }
        )
    return rows
