"""TLS certificate management via acme.sh (standalone & DNS challenges)."""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from agent.errors import AgentError
from agent.logutil import get_logger

log = get_logger('tls')

ACME_HOME = Path(os.environ.get('ACME_HOME', '/root/.acme.sh'))
ACME_BIN = ACME_HOME / 'acme.sh'
CERT_BASE = Path(os.environ.get('TLS_CERT_DIR', '/var/lib/agent/certs'))

ACME_INSTALL_URL = 'https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh'


def _run(args: list[str], *, timeout: int = 300, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=merged)


def acme_installed() -> bool:
    return ACME_BIN.is_file()


def ensure_acme(email: str = '') -> dict:
    if acme_installed():
        return {'installed': True, 'downloaded': False, 'path': str(ACME_BIN)}

    curl = shutil.which('curl')
    wget = shutil.which('wget')
    if not curl and not wget:
        raise AgentError('VALIDATION_ERROR', 'curl or wget is required to install acme.sh')

    ACME_HOME.mkdir(parents=True, exist_ok=True)

    if curl:
        proc = _run([
            curl, '-fsSL', ACME_INSTALL_URL,
            '-o', str(ACME_HOME / 'acme.sh'),
        ])
    else:
        proc = _run([
            wget, '-qO', str(ACME_HOME / 'acme.sh'), ACME_INSTALL_URL,
        ])

    if proc.returncode != 0:
        raise AgentError('VALIDATION_ERROR', f'Failed to download acme.sh: {proc.stderr.strip()[:300]}')

    ACME_BIN.chmod(0o755)

    install_args = [str(ACME_BIN), '--install', '--home', str(ACME_HOME)]
    if email:
        install_args += ['--accountemail', email]
    proc = _run(install_args)
    if proc.returncode != 0:
        log.warning('acme.sh --install warning: %s', proc.stderr.strip()[:300])

    return {'installed': True, 'downloaded': True, 'path': str(ACME_BIN)}


def _cert_dir(domain: str) -> Path:
    return CERT_BASE / domain


def cert_paths(domain: str) -> dict[str, str]:
    d = _cert_dir(domain)
    return {
        'cert_file': str(d / 'fullchain.pem'),
        'key_file': str(d / 'privkey.pem'),
    }


def cert_exists(domain: str) -> bool:
    paths = cert_paths(domain)
    return Path(paths['cert_file']).is_file() and Path(paths['key_file']).is_file()


def issue_cert(
    domain: str,
    method: str = 'standalone',
    cf_token: str | None = None,
    cf_account_id: str | None = None,
    email: str = '',
    force: bool = False,
) -> dict:
    if not domain or not domain.strip():
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    domain = domain.strip().lower()
    ensure_acme(email=email)

    out_dir = _cert_dir(domain)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = cert_paths(domain)

    if cert_exists(domain) and not force:
        return {
            'success': True,
            'issued': False,
            'cached': True,
            'domain': domain,
            **paths,
        }

    args = [
        str(ACME_BIN), '--issue',
        '--home', str(ACME_HOME),
        '-d', domain,
    ]

    env: dict[str, str] = {}

    if method == 'standalone':
        args += ['--standalone']
    elif method in ('dns_cloudflare', 'dns_cf'):
        if not cf_token:
            raise AgentError('VALIDATION_ERROR', 'cf_token is required for DNS Cloudflare method')
        args += ['--dns', 'dns_cf']
        env['CF_Token'] = cf_token
        if cf_account_id:
            env['CF_Account_ID'] = cf_account_id
    else:
        raise AgentError('VALIDATION_ERROR', f'Unknown method [{method}]. Use standalone or dns_cloudflare.')

    if force:
        args += ['--force']

    log.info('issuing certificate domain=%s method=%s', domain, method)
    proc = _run(args, timeout=180, env=env)

    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:500] or proc.stdout.strip()[:500]
        log.error('acme.sh --issue failed: %s', stderr)
        raise AgentError('VALIDATION_ERROR', f'Certificate issue failed: {stderr}')

    install_args = [
        str(ACME_BIN), '--install-cert',
        '--home', str(ACME_HOME),
        '-d', domain,
        '--fullchain-file', paths['cert_file'],
        '--key-file', paths['key_file'],
    ]
    proc = _run(install_args, timeout=60)
    if proc.returncode != 0:
        raise AgentError('VALIDATION_ERROR', f'Certificate install failed: {proc.stderr.strip()[:300]}')

    log.info('certificate issued domain=%s cert=%s', domain, paths['cert_file'])
    return {
        'success': True,
        'issued': True,
        'cached': False,
        'domain': domain,
        **paths,
    }


def renew_cert(domain: str, force: bool = False) -> dict:
    if not domain or not domain.strip():
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    domain = domain.strip().lower()
    if not acme_installed():
        raise AgentError('VALIDATION_ERROR', 'acme.sh is not installed. Call install-acme first.')

    args = [
        str(ACME_BIN), '--renew',
        '--home', str(ACME_HOME),
        '-d', domain,
    ]
    if force:
        args += ['--force']

    proc = _run(args, timeout=180)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:500] or proc.stdout.strip()[:500]
        raise AgentError('VALIDATION_ERROR', f'Certificate renew failed: {stderr}')

    paths = cert_paths(domain)
    install_args = [
        str(ACME_BIN), '--install-cert',
        '--home', str(ACME_HOME),
        '-d', domain,
        '--fullchain-file', paths['cert_file'],
        '--key-file', paths['key_file'],
    ]
    _run(install_args, timeout=60)

    return {'success': True, 'renewed': True, 'domain': domain, **paths}


def list_certs() -> list[dict]:
    certs = []
    if not CERT_BASE.is_dir():
        return certs

    for entry in sorted(CERT_BASE.iterdir()):
        if not entry.is_dir():
            continue
        domain = entry.name
        fullchain = entry / 'fullchain.pem'
        privkey = entry / 'privkey.pem'
        if not fullchain.is_file():
            continue

        info: dict = {
            'domain': domain,
            'cert_file': str(fullchain),
            'key_file': str(privkey) if privkey.is_file() else None,
            'has_key': privkey.is_file(),
        }

        try:
            stat = fullchain.stat()
            info['modified_at'] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            pass

        certs.append(info)

    return certs


def revoke_cert(domain: str) -> dict:
    if not domain or not domain.strip():
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    domain = domain.strip().lower()
    if not acme_installed():
        raise AgentError('VALIDATION_ERROR', 'acme.sh is not installed.')

    args = [
        str(ACME_BIN), '--revoke',
        '--home', str(ACME_HOME),
        '-d', domain,
    ]
    proc = _run(args, timeout=120)
    revoked = proc.returncode == 0

    cert_dir = _cert_dir(domain)
    removed = False
    if cert_dir.is_dir():
        shutil.rmtree(cert_dir, ignore_errors=True)
        removed = True

    return {'success': True, 'revoked': revoked, 'removed': removed, 'domain': domain}
