from typing import Any

from fastapi import APIRouter, Depends, Request

from agent.api.lifecycle import attach_lifecycle, health_payload
from agent.drivers.l2tp import L2tpDriver
from agent.errors import AgentError, raise_agent_error
from agent.models import L2tpServerPayload, L2tpUserPayload
from agent.registry import CoreRegistry
from agent.traffic.service import TrafficService

router = APIRouter(prefix='/cores/l2tp', tags=['l2tp'])


def get_registry(request: Request) -> CoreRegistry:
    return request.app.state.registry


def get_traffic(request: Request) -> TrafficService:
    return request.app.state.traffic


def get_l2tp(registry: CoreRegistry = Depends(get_registry)) -> L2tpDriver:
    try:
        driver = registry.get('l2tp')
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    if not isinstance(driver, L2tpDriver) or driver.key != 'l2tp':
        raise_agent_error('UNSUPPORTED_CAPABILITY', 'L2TP core is not available')
    return driver


attach_lifecycle(router, core='l2tp', get_driver=get_l2tp)


@router.get('/status')
def status(l2tp: L2tpDriver = Depends(get_l2tp)):
    return health_payload(l2tp)


@router.get('/servers')
def list_servers(l2tp: L2tpDriver = Depends(get_l2tp)):
    return {'success': True, 'servers': l2tp.list_servers()}


@router.post('/servers')
def create_server(payload: L2tpServerPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = l2tp.create_server(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.get('/servers/{server_id}')
def get_server(server_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = l2tp.get_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.put('/servers/{server_id}')
def update_server(server_id: str, payload: L2tpServerPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = l2tp.update_server(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.delete('/servers/{server_id}')
def delete_server(server_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        l2tp.delete_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.post('/servers/{server_id}/users')
def add_user(server_id: str, payload: L2tpUserPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        user = l2tp.add_user(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.post('/servers/{server_id}/users/batch')
@router.post('/servers/{server_id}/users:batch')
def batch_users(server_id: str, body: dict[str, Any], l2tp: L2tpDriver = Depends(get_l2tp)):
    users = body.get('users') or []
    if not isinstance(users, list):
        raise_agent_error('VALIDATION_ERROR', 'users must be a list', 422)
    mode = str(body.get('mode') or 'upsert')
    atomic = bool(body.get('atomic', False))
    try:
        result = l2tp.batch_users(server_id, [row for row in users if isinstance(row, dict)], mode=mode, atomic=atomic)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.put('/servers/{server_id}/users/{user_id}')
def update_user(
    server_id: str,
    user_id: str,
    payload: L2tpUserPayload,
    l2tp: L2tpDriver = Depends(get_l2tp),
):
    try:
        user = l2tp.update_user(server_id, user_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.delete('/servers/{server_id}/users/{user_id}')
def delete_user(server_id: str, user_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        l2tp.delete_user(server_id, user_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.get('/servers/{server_id}/users/{user_id}/config')
def user_config(
    server_id: str,
    user_id: str,
    endpoint: str | None = None,
    l2tp: L2tpDriver = Depends(get_l2tp),
):
    try:
        bundle = l2tp.user_config_bundle(server_id, user_id, endpoint_host=endpoint or None)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **bundle}


@router.get('/diagnose')
def diagnose_user(address: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        report = l2tp.diagnose_address(address)
    except ValueError as exc:
        raise_agent_error('VALIDATION_ERROR', str(exc), 422)
    return report


@router.post('/backup')
def backup(l2tp: L2tpDriver = Depends(get_l2tp)):
    return {'success': True, 'backup': l2tp.backup()}


@router.post('/restore')
def restore(body: dict[str, Any], l2tp: L2tpDriver = Depends(get_l2tp)):
    payload = body.get('backup') if isinstance(body.get('backup'), dict) else body
    l2tp.restore(payload)
    return {'success': True}
