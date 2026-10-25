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
async def status(l2tp: L2tpDriver = Depends(get_l2tp)):
    return await health_payload(l2tp)


@router.get('/servers')
async def list_servers(l2tp: L2tpDriver = Depends(get_l2tp)):
    return {'success': True, 'servers': await l2tp.list_servers()}


@router.post('/servers')
async def create_server(payload: L2tpServerPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = await l2tp.create_server(payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.get('/servers/{server_id}')
async def get_server(server_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = await l2tp.get_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.put('/servers/{server_id}')
async def update_server(server_id: str, payload: L2tpServerPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        server = await l2tp.update_server(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'server': server}


@router.delete('/servers/{server_id}')
async def delete_server(server_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        await l2tp.delete_server(server_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.post('/servers/{server_id}/users')
async def add_user(server_id: str, payload: L2tpUserPayload, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        user = await l2tp.add_user(server_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.post('/servers/{server_id}/users/batch')
@router.post('/servers/{server_id}/users:batch')
async def batch_users(server_id: str, body: dict[str, Any], l2tp: L2tpDriver = Depends(get_l2tp)):
    users = body.get('users') or []
    if not isinstance(users, list):
        raise_agent_error('VALIDATION_ERROR', 'users must be a list', 422)
    mode = str(body.get('mode') or 'upsert')
    atomic = bool(body.get('atomic', False))
    try:
        result = await l2tp.batch_users(server_id, [row for row in users if isinstance(row, dict)], mode=mode, atomic=atomic)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **result}


@router.put('/servers/{server_id}/users/{user_id}')
async def update_user(
    server_id: str,
    user_id: str,
    payload: L2tpUserPayload,
    l2tp: L2tpDriver = Depends(get_l2tp),
):
    try:
        user = await l2tp.update_user(server_id, user_id, payload.model_dump(exclude_none=True))
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, 'user': user}


@router.delete('/servers/{server_id}/users/{user_id}')
async def delete_user(server_id: str, user_id: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        await l2tp.delete_user(server_id, user_id)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True}


@router.get('/servers/{server_id}/users/{user_id}/config')
async def user_config(
    server_id: str,
    user_id: str,
    endpoint: str | None = None,
    l2tp: L2tpDriver = Depends(get_l2tp),
):
    try:
        bundle = await l2tp.user_config_bundle(server_id, user_id, endpoint_host=endpoint or None)
    except AgentError as exc:
        raise_agent_error(exc.code, exc.message, exc.status)
    return {'success': True, **bundle}


@router.get('/diagnose')
async def diagnose_user(address: str, l2tp: L2tpDriver = Depends(get_l2tp)):
    try:
        report = await l2tp.diagnose_address(address)
    except ValueError as exc:
        raise_agent_error('VALIDATION_ERROR', str(exc), 422)
    return report


@router.post('/backup')
async def backup(l2tp: L2tpDriver = Depends(get_l2tp)):
    return {'success': True, 'backup': await l2tp.backup()}


@router.post('/restore')
async def restore(body: dict[str, Any], l2tp: L2tpDriver = Depends(get_l2tp)):
    payload = body.get('backup') if isinstance(body.get('backup'), dict) else body
    await l2tp.restore(payload)
    return {'success': True}
