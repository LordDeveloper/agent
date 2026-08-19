from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body

from agent.errors import AgentError, raise_agent_error
from agent.tls import (
    acme_installed,
    cert_paths,
    ensure_acme,
    issue_cert,
    list_certs,
    renew_cert,
    revoke_cert,
)

router = APIRouter(prefix='/tls', tags=['tls'])


@router.get('/status')
def tls_status():
    return {
        'success': True,
        'acme_installed': acme_installed(),
    }


@router.post('/install-acme')
def install_acme(body: dict[str, Any] | None = Body(default=None)):
    payload = body or {}
    try:
        result = ensure_acme(email=str(payload.get('email', '')))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/issue')
def tls_issue(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    method = str(body.get('method', 'standalone')).strip()
    cf_token = body.get('cf_token') or None
    cf_account_id = body.get('cf_account_id') or None
    email = str(body.get('email', '')).strip()
    force = bool(body.get('force', False))

    try:
        result = issue_cert(
            domain=domain,
            method=method,
            cf_token=cf_token,
            cf_account_id=cf_account_id,
            email=email,
            force=force,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result


@router.post('/renew')
def tls_renew(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    force = bool(body.get('force', False))

    try:
        result = renew_cert(domain=domain, force=force)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result


@router.get('/certs')
def tls_list():
    return {'success': True, 'certs': list_certs()}


@router.get('/certs/{domain}')
def tls_cert_info(domain: str):
    paths = cert_paths(domain)
    from pathlib import Path

    exists = Path(paths['cert_file']).is_file()
    return {
        'success': True,
        'domain': domain,
        'exists': exists,
        **paths,
    }


@router.post('/revoke')
def tls_revoke(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    try:
        result = revoke_cert(domain=domain)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result
