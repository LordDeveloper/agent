from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.openvpn import OpenVpnDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import OpenVpnServerPayload, OpenVpnUserPayload
from agent.registry import CoreRegistry

router = APIRouter(prefix='/cores/openvpn', tags=['openvpn'])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_openvpn(registry: CoreRegistry = Depends(get_registry)) -> OpenVpnDriver:
    try:
        driver = registry.get('openvpn')
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not isinstance(driver, OpenVpnDriver) or driver.key != 'openvpn':
        raise_agent_error('UNSUPPORTED_CAPABILITY', 'OpenVPN core is not available')
    return driver


attach_lifecycle(router, core='openvpn', get_driver=get_openvpn)


@router.get('/status')
def status(openvpn: OpenVpnDriver = Depends(get_openvpn)):
    return health_payload(openvpn)


@router.get('/servers')
def list_servers(openvpn: OpenVpnDriver = Depends(get_openvpn)):
    return {'success': True, 'servers': openvpn.list_servers()}


@router.post('/servers')
def create_server(payload: OpenVpnServerPayload, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        server = openvpn.create_server(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.get('/servers/{server_id}')
def get_server(server_id: str, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        server = openvpn.get_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.put('/servers/{server_id}')
def update_server(server_id: str, payload: OpenVpnServerPayload, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        server = openvpn.update_server(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.delete('/servers/{server_id}')
def delete_server(server_id: str, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        openvpn.delete_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.post('/servers/{server_id}/users')
def add_user(server_id: str, payload: OpenVpnUserPayload, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        user = openvpn.add_user(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.post('/servers/{server_id}/users/batch')
@router.post('/servers/{server_id}/users:batch')
def batch_users(server_id: str, body: dict[str, Any], openvpn: OpenVpnDriver = Depends(get_openvpn)):
    users = body.get('users') or []
    if not isinstance(users, list):
        raise_agent_error('VALIDATION_ERROR', 'users must be a list', 422)
    mode = str(body.get('mode') or 'upsert')
    atomic = bool(body.get('atomic', False))
    try:
        result = openvpn.batch_users(
            server_id,
            [row for row in users if isinstance(row, dict)],
            mode=mode,
            atomic=atomic,
        )
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.put('/servers/{server_id}/users/{user_id}')
def update_user(
    server_id: str,
    user_id: str,
    payload: OpenVpnUserPayload,
    openvpn: OpenVpnDriver = Depends(get_openvpn),
):
    try:
        user = openvpn.update_user(server_id, user_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.delete('/servers/{server_id}/users/{user_id}')
def delete_user(server_id: str, user_id: str, openvpn: OpenVpnDriver = Depends(get_openvpn)):
    try:
        openvpn.delete_user(server_id, user_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.get('/servers/{server_id}/users/{user_id}/config')
def user_config(
    server_id: str,
    user_id: str,
    endpoint: str | None = None,
    openvpn: OpenVpnDriver = Depends(get_openvpn),
):
    try:
        bundle = openvpn.user_config_bundle(server_id, user_id, endpoint_host=endpoint or None)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **bundle}


@router.post('/backup')
def backup(openvpn: OpenVpnDriver = Depends(get_openvpn)):
    return {'success': True, 'backup': openvpn.backup()}


@router.post('/restore')
def restore(body: dict[str, Any], openvpn: OpenVpnDriver = Depends(get_openvpn)):
    payload = body.get('backup') if isinstance(body.get('backup'), dict) else body
    try:
        openvpn.restore(payload)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}
