"""TLS certificate management via acme.sh and certbot (standalone & DNS challenges)."""

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
ACME_SERVER = (os.environ.get('ACME_SERVER', 'letsencrypt') or 'letsencrypt').strip()
ACME_DEFAULT_EMAIL = (os.environ.get('ACME_EMAIL', '') or '').strip()

ACME_INSTALL_URL = 'https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh'

CERTBOT_BIN = Path(shutil.which('certbot') or '/usr/bin/certbot')
CERTBOT_LIVE = Path('/etc/letsencrypt/live')

TOOLS = ('acme', 'certbot')


def _run(args: list[str], *, timeout: int = 300, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=merged)


def _resolve_acme_email(email: str = '') -> str:
    return (email or ACME_DEFAULT_EMAIL).strip()


def _acme_server_args() -> list[str]:
    return ['--server', ACME_SERVER]


def _strip_acme_log_line(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ''
    if stripped.startswith('[') and '] ' in stripped:
        return stripped.split('] ', 1)[1].strip()
    return stripped


def _extract_acme_error(combined: str) -> str:
    """Prefer actionable acme.sh lines over debug timestamps."""
    meaningful: list[str] = []
    hints = (
        'error', 'failed', 'please', 'cannot', 'unable', 'invalid',
        'rate limit', 'verify error', 'connection refused', 'skipping',
        'domains not changed', 'register-account',
    )

    for raw in combined.splitlines():
        line = _strip_acme_log_line(raw)
        if not line:
            continue
        lower = line.lower()
        if any(hint in lower for hint in hints):
            meaningful.append(line)

    if meaningful:
        return '\n'.join(meaningful[-8:])[:800]

    tail = [_strip_acme_log_line(line) for line in combined.splitlines()[-12:]]
    tail = [line for line in tail if line]
    return '\n'.join(tail)[-800:]


def _configure_acme(email: str = '') -> None:
    """Force Let's Encrypt (or ACME_SERVER) and register account email when needed."""
    if not acme_installed():
        return

    proc = _run([
        str(ACME_BIN), '--set-default-ca',
        '--home', str(ACME_HOME),
        *_acme_server_args(),
    ], timeout=60)
    if proc.returncode != 0:
        log.warning(
            'acme.sh --set-default-ca warning: %s',
            _extract_acme_error(f'{proc.stdout or ""}\n{proc.stderr or ""}'),
        )

    resolved_email = _resolve_acme_email(email)
    if not resolved_email:
        return

    proc = _run([
        str(ACME_BIN), '--register-account',
        '--home', str(ACME_HOME),
        *_acme_server_args(),
        '-m', resolved_email,
    ], timeout=60)
    if proc.returncode != 0:
        combined = f'{proc.stdout or ""}\n{proc.stderr or ""}'.lower()
        if 'already' not in combined and 'registered' not in combined:
            log.warning(
                'acme.sh --register-account warning: %s',
                _extract_acme_error(f'{proc.stdout or ""}\n{proc.stderr or ""}'),
            )


def _install_cert_to_agent(domain: str, paths: dict[str, str]) -> None:
    base_args = [
        str(ACME_BIN), '--install-cert',
        '--home', str(ACME_HOME),
        '-d', domain,
        '--fullchain-file', paths['cert_file'],
        '--key-file', paths['key_file'],
    ]
    last_error = ''
    for extra in (['--ecc'], []):
        proc = _run(base_args + extra, timeout=60)
        if proc.returncode == 0 and Path(paths['cert_file']).is_file() and Path(paths['key_file']).is_file():
            return
        last_error = _extract_acme_error(f'{proc.stdout or ""}\n{proc.stderr or ""}')

    raise AgentError('VALIDATION_ERROR', f'Certificate install failed: {last_error or "unknown error"}')


def _try_install_from_acme_store(domain: str, paths: dict[str, str]) -> bool:
    """Restore agent cert files from an existing acme.sh store entry."""
    if not acme_installed():
        return False

    try:
        _install_cert_to_agent(domain, paths)
    except AgentError:
        return False

    return Path(paths['cert_file']).is_file() and Path(paths['key_file']).is_file()


# ---------------------------------------------------------------------------
# acme.sh helpers
# ---------------------------------------------------------------------------

def acme_installed() -> bool:
    return ACME_BIN.is_file()


def ensure_acme(email: str = '') -> dict:
    downloaded = False

    if not acme_installed():
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

        install_args = [
            str(ACME_BIN), '--install',
            '--home', str(ACME_HOME),
            *_acme_server_args(),
        ]
        resolved_email = _resolve_acme_email(email)
        if resolved_email:
            install_args += ['--accountemail', resolved_email]
        proc = _run(install_args)
        if proc.returncode != 0:
            log.warning('acme.sh --install warning: %s', proc.stderr.strip()[:300])
        downloaded = True

    _configure_acme(email)

    return {'installed': True, 'downloaded': downloaded, 'path': str(ACME_BIN)}


# ---------------------------------------------------------------------------
# certbot helpers
# ---------------------------------------------------------------------------

def certbot_installed() -> bool:
    return shutil.which('certbot') is not None


def ensure_certbot() -> dict:
    if certbot_installed():
        return {'installed': True, 'downloaded': False, 'path': str(shutil.which('certbot'))}

    apt = shutil.which('apt-get')
    if apt:
        proc = _run([apt, 'update', '-qq'], timeout=120)
        proc = _run([apt, 'install', '-y', '-qq', 'certbot'], timeout=300)
        if proc.returncode == 0 and certbot_installed():
            return {'installed': True, 'downloaded': True, 'path': str(shutil.which('certbot'))}

    snap = shutil.which('snap')
    if snap:
        proc = _run([snap, 'install', '--classic', 'certbot'], timeout=300)
        if proc.returncode == 0 and certbot_installed():
            return {'installed': True, 'downloaded': True, 'path': str(shutil.which('certbot'))}

    raise AgentError('VALIDATION_ERROR', 'Failed to install certbot. Install it manually (apt install certbot or snap install --classic certbot).')


# ---------------------------------------------------------------------------
# cert directory / paths
# ---------------------------------------------------------------------------

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


def normalize_domains(domain: str, domains: list[str] | None = None) -> list[str]:
    """Primary domain first, then optional SAN domains (deduped, lowercased)."""
    ordered: list[str] = []
    seen: set[str] = set()

    for raw in [domain, *(domains or [])]:
        value = str(raw or '').strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)

    if not ordered:
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    return ordered


def _domain_args(domains: list[str]) -> list[str]:
    args: list[str] = []
    for item in domains:
        args += ['-d', item]
    return args


# ---------------------------------------------------------------------------
# issue / renew dispatchers
# ---------------------------------------------------------------------------

def issue_cert(
    domain: str,
    method: str = 'standalone',
    cf_token: str | None = None,
    cf_account_id: str | None = None,
    email: str = '',
    force: bool = False,
    tool: str = 'acme',
    domains: list[str] | None = None,
) -> dict:
    tool = (tool or 'acme').strip().lower()
    if tool not in TOOLS:
        raise AgentError('VALIDATION_ERROR', f'Unknown tool [{tool}]. Use acme or certbot.')

    if tool == 'certbot':
        return _issue_cert_certbot(
            domain,
            method=method,
            cf_token=cf_token,
            email=email,
            force=force,
            domains=domains,
        )
    return _issue_cert_acme(
        domain,
        method=method,
        cf_token=cf_token,
        cf_account_id=cf_account_id,
        email=email,
        force=force,
        domains=domains,
    )


def renew_cert(domain: str, force: bool = False, tool: str = 'acme') -> dict:
    tool = (tool or 'acme').strip().lower()
    if tool not in TOOLS:
        raise AgentError('VALIDATION_ERROR', f'Unknown tool [{tool}]. Use acme or certbot.')

    if tool == 'certbot':
        return _renew_cert_certbot(domain, force=force)
    return _renew_cert_acme(domain, force=force)


# ---------------------------------------------------------------------------
# acme.sh issue / renew
# ---------------------------------------------------------------------------

def _issue_cert_acme(
    domain: str,
    method: str = 'standalone',
    cf_token: str | None = None,
    cf_account_id: str | None = None,
    email: str = '',
    force: bool = False,
    domains: list[str] | None = None,
) -> dict:
    san_domains = normalize_domains(domain, domains)
    primary = san_domains[0]
    ensure_acme(email=email)

    out_dir = _cert_dir(primary)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = cert_paths(primary)

    if cert_exists(primary) and not force:
        return {
            'success': True,
            'issued': False,
            'cached': True,
            'tool': 'acme',
            'domain': primary,
            'domains': san_domains,
            **paths,
        }

    if not force and _try_install_from_acme_store(primary, paths):
        log.info('certificate restored from acme store domain=%s cert=%s', primary, paths['cert_file'])
        return {
            'success': True,
            'issued': False,
            'cached': True,
            'restored': True,
            'tool': 'acme',
            'domain': primary,
            'domains': san_domains,
            **paths,
        }

    args = [
        str(ACME_BIN), '--issue',
        '--home', str(ACME_HOME),
        *_acme_server_args(),
        *_domain_args(san_domains),
    ]

    resolved_email = _resolve_acme_email(email)
    if resolved_email:
        args += ['--accountemail', resolved_email]

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

    log.info(
        'issuing certificate domain=%s domains=%s method=%s tool=acme',
        primary,
        ','.join(san_domains),
        method,
    )
    proc = _run(args, timeout=300, env=env)

    if proc.returncode != 0:
        combined = f'{proc.stdout or ""}\n{proc.stderr or ""}'.strip()
        detail = _extract_acme_error(combined)
        log.error('acme.sh --issue failed: %s', detail)
        raise AgentError('VALIDATION_ERROR', f'Certificate issue failed: {detail}')

    _install_cert_to_agent(primary, paths)

    log.info('certificate issued domain=%s cert=%s tool=acme', primary, paths['cert_file'])
    return {
        'success': True,
        'issued': True,
        'cached': False,
        'tool': 'acme',
        'domain': primary,
        'domains': san_domains,
        **paths,
    }


def _renew_cert_acme(domain: str, force: bool = False) -> dict:
    if not domain or not domain.strip():
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    domain = domain.strip().lower()
    if not acme_installed():
        raise AgentError('VALIDATION_ERROR', 'acme.sh is not installed. Call install-acme first.')

    _configure_acme()

    args = [
        str(ACME_BIN), '--renew',
        '--home', str(ACME_HOME),
        *_acme_server_args(),
        '-d', domain,
    ]
    if force:
        args += ['--force']

    proc = _run(args, timeout=180)
    if proc.returncode != 0:
        combined = f'{proc.stdout or ""}\n{proc.stderr or ""}'.strip()
        raise AgentError('VALIDATION_ERROR', f'Certificate renew failed: {_extract_acme_error(combined)}')

    paths = cert_paths(domain)
    _install_cert_to_agent(domain, paths)

    return {'success': True, 'renewed': True, 'tool': 'acme', 'domain': domain, **paths}


# ---------------------------------------------------------------------------
# certbot issue / renew
# ---------------------------------------------------------------------------

def _issue_cert_certbot(
    domain: str,
    method: str = 'standalone',
    cf_token: str | None = None,
    email: str = '',
    force: bool = False,
    domains: list[str] | None = None,
) -> dict:
    san_domains = normalize_domains(domain, domains)
    primary = san_domains[0]
    ensure_certbot()

    out_dir = _cert_dir(primary)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = cert_paths(primary)

    if cert_exists(primary) and not force:
        return {
            'success': True,
            'issued': False,
            'cached': True,
            'tool': 'certbot',
            'domain': primary,
            'domains': san_domains,
            **paths,
        }

    certbot = shutil.which('certbot') or str(CERTBOT_BIN)
    args = [
        certbot, 'certonly',
        '--non-interactive',
        '--agree-tos',
        '--cert-name', primary,
        *_domain_args(san_domains),
    ]

    if email:
        args += ['--email', email]
    else:
        args += ['--register-unsafely-without-email']

    env: dict[str, str] = {}

    if method == 'standalone':
        args += ['--standalone']
    elif method in ('dns_cloudflare', 'dns_cf'):
        if not cf_token:
            raise AgentError('VALIDATION_ERROR', 'cf_token is required for DNS Cloudflare method')
        cred_path = Path('/tmp/.certbot_cf_creds')
        cred_path.write_text(f'dns_cloudflare_api_token = {cf_token}\n')
        cred_path.chmod(0o600)
        args += ['--dns-cloudflare', '--dns-cloudflare-credentials', str(cred_path)]
    else:
        raise AgentError('VALIDATION_ERROR', f'Unknown method [{method}]. Use standalone or dns_cloudflare.')

    if force:
        args += ['--force-renewal']

    log.info(
        'issuing certificate domain=%s domains=%s method=%s tool=certbot',
        primary,
        ','.join(san_domains),
        method,
    )
    proc = _run(args, timeout=300, env=env)

    if proc.returncode != 0:
        output = (proc.stdout or '').strip()
        stderr = (proc.stderr or '').strip()
        combined = f'{output}\n{stderr}'.strip()
        last_lines = '\n'.join(combined.splitlines()[-20:])[:800]
        log.error('certbot certonly failed: %s', last_lines)
        raise AgentError('VALIDATION_ERROR', f'Certificate issue failed: {last_lines}')

    live_dir = CERTBOT_LIVE / primary
    src_fullchain = live_dir / 'fullchain.pem'
    src_privkey = live_dir / 'privkey.pem'

    if src_fullchain.exists():
        shutil.copy2(str(src_fullchain), paths['cert_file'])
    if src_privkey.exists():
        shutil.copy2(str(src_privkey), paths['key_file'])

    if not Path(paths['cert_file']).is_file():
        raise AgentError('VALIDATION_ERROR', 'certbot succeeded but certificate files not found in expected location.')

    log.info('certificate issued domain=%s cert=%s tool=certbot', primary, paths['cert_file'])
    return {
        'success': True,
        'issued': True,
        'cached': False,
        'tool': 'certbot',
        'domain': primary,
        'domains': san_domains,
        **paths,
    }


def _renew_cert_certbot(domain: str, force: bool = False) -> dict:
    if not domain or not domain.strip():
        raise AgentError('VALIDATION_ERROR', 'domain is required')

    domain = domain.strip().lower()
    if not certbot_installed():
        raise AgentError('VALIDATION_ERROR', 'certbot is not installed. Call install-certbot first.')

    certbot = shutil.which('certbot') or str(CERTBOT_BIN)
    args = [certbot, 'renew', '--non-interactive', '--cert-name', domain]
    if force:
        args += ['--force-renewal']

    proc = _run(args, timeout=300)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:500] or proc.stdout.strip()[:500]
        raise AgentError('VALIDATION_ERROR', f'Certificate renew failed: {stderr}')

    paths = cert_paths(domain)
    live_dir = CERTBOT_LIVE / domain
    src_fullchain = live_dir / 'fullchain.pem'
    src_privkey = live_dir / 'privkey.pem'
    if src_fullchain.exists():
        shutil.copy2(str(src_fullchain), paths['cert_file'])
    if src_privkey.exists():
        shutil.copy2(str(src_privkey), paths['key_file'])

    return {'success': True, 'renewed': True, 'tool': 'certbot', 'domain': domain, **paths}


# ---------------------------------------------------------------------------
# list / revoke (tool-agnostic, work on unified cert store)
# ---------------------------------------------------------------------------

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
        *_acme_server_args(),
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
