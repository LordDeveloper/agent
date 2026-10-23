from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body

from agent.errors import AgentError, raise_agent_error
from agent.tls import (
    acme_installed,
    cert_paths,
    certbot_installed,
    ensure_acme,
    ensure_certbot,
    export_acme_store,
    export_files,
    import_acme_store,
    import_files,
    issue_cert,
    list_certs,
    renew_cert,
    revoke_cert,
)

router = APIRouter(prefix='/tls', tags=['tls'])


@router.get('/status')
async def tls_status():
    return {
        'success': True,
        'acme_installed': acme_installed(),
        'certbot_installed': certbot_installed(),
    }


@router.post('/install-acme')
async def install_acme(body: dict[str, Any] | None = Body(default=None)):
    payload = body or {}
    try:
        result = await ensure_acme(email=str(payload.get('email', '')))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/install-certbot')
async def install_certbot_endpoint(body: dict[str, Any] | None = Body(default=None)):
    try:
        result = await ensure_certbot()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/issue')
async def tls_issue(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    raw_domains = body.get('domains')
    domains: list[str] | None = None
    if isinstance(raw_domains, list):
        domains = [str(item).strip() for item in raw_domains if str(item).strip()]
    elif isinstance(raw_domains, str) and raw_domains.strip():
        domains = [part.strip() for part in raw_domains.replace('،', ',').split(',') if part.strip()]

    method = str(body.get('method', 'standalone')).strip()
    cf_token = body.get('cf_token') or None
    cf_account_id = body.get('cf_account_id') or None
    email = str(body.get('email', '')).strip()
    force = bool(body.get('force', False))
    tool = str(body.get('tool', 'acme')).strip().lower()

    try:
        result = await issue_cert(
            domain=domain,
            method=method,
            cf_token=cf_token,
            cf_account_id=cf_account_id,
            email=email,
            force=force,
            tool=tool,
            domains=domains,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result


@router.post('/renew')
async def tls_renew(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    force = bool(body.get('force', False))
    tool = str(body.get('tool', 'acme')).strip().lower()

    try:
        result = await renew_cert(domain=domain, force=force, tool=tool)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result


@router.get('/certs')
async def tls_list():
    return {'success': True, 'certs': list_certs()}


@router.get('/certs/{domain}')
async def tls_cert_info(domain: str):
    paths = cert_paths(domain)
    from pathlib import Path

    exists = Path(paths['cert_file']).is_file()
    return {
        'success': True,
        'domain': domain,
        'exists': exists,
        **paths,
    }


@router.post('/export-files')
async def tls_export_files(body: dict[str, Any] = Body()):
    raw = body.get('paths')
    if not isinstance(raw, list):
        raise_agent_error('VALIDATION_ERROR', 'paths must be a list', 422)
    try:
        result = export_files([str(item) for item in raw])
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/import-files')
async def tls_import_files(body: dict[str, Any] = Body()):
    raw = body.get('files')
    if not isinstance(raw, list):
        raise_agent_error('VALIDATION_ERROR', 'files must be a list', 422)
    try:
        result = import_files(raw)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.get('/acme-store')
async def tls_export_acme_store():
    try:
        result = export_acme_store()
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/acme-store')
async def tls_import_acme_store(body: dict[str, Any] = Body()):
    raw = body.get('files')
    if not isinstance(raw, list):
        raise_agent_error('VALIDATION_ERROR', 'files must be a list', 422)
    try:
        result = import_acme_store(raw)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.post('/revoke')
async def tls_revoke(body: dict[str, Any] = Body()):
    domain = str(body.get('domain', '')).strip()
    try:
        result = await revoke_cert(domain=domain)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return result
