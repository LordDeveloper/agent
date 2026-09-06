from __future__ import annotations

from typing import Any

from agent.support import normalize_xray_client, record_is_enabled
from agent.support.disable_reason import explain_disabled
from agent.support.quota import has_volume_quota, quota_exceeded


def _issue(level: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {'level': level, 'code': code, 'message': message}
    row.update(extra)
    return row


def _client_keys_match(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_id = str(left.get('id') or '').strip()
    right_id = str(right.get('id') or '').strip()
    left_email = str(left.get('email') or '').strip()
    right_email = str(right.get('email') or '').strip()

    if left_id and right_id and left_id == right_id:
        return True

    return bool(left_email and right_email and left_email == right_email)


def _find_client_in_inbound(inbound: dict[str, Any], client_key: str) -> dict[str, Any] | None:
    key = str(client_key or '').strip()
    if not key:
        return None

    settings = inbound.get('settings') or {}
    rows = settings.get('clients') or settings.get('users') or []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get('id') or '').strip() == key or str(row.get('email') or '').strip() == key:
            return normalize_xray_client(row)

    return None


def _find_config_client(config: dict[str, Any], inbound_tag: str, inbound_id: str, client_key: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    for inbound in config.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get('tag') or '').strip()
        if tag != inbound_tag and str(inbound.get('id') or '') != str(inbound_id):
            continue
        client = _find_client_in_inbound(inbound, client_key)
        if client is not None:
            summary = {
                'id': inbound.get('id'),
                'tag': tag,
                'port': inbound.get('port'),
                'protocol': inbound.get('protocol'),
            }
            return client, summary

    return None, None


def _find_config_clients_by_key(config: dict[str, Any], client_key: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    key = str(client_key or '').strip()
    if not key:
        return []

    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for inbound in config.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        client = _find_client_in_inbound(inbound, key)
        if client is None:
            continue
        tag = str(inbound.get('tag') or '').strip()
        rows.append(
            (
                client,
                {
                    'id': inbound.get('id'),
                    'tag': tag,
                    'port': inbound.get('port'),
                    'protocol': inbound.get('protocol'),
                },
            )
        )

    return rows


def _live_user_snapshot(
    driver: Any,
    inbound_tag: str,
    client: dict[str, Any],
    *,
    online_emails: set[str],
) -> dict[str, Any] | None:
    runtime = None
    try:
        for inbound in driver.list_inbounds():
            tag = str(inbound.get('tag') or '').strip()
            if tag != inbound_tag:
                continue
            runtime = _find_client_in_inbound(inbound, str(client.get('email') or client.get('id') or ''))
            break
    except Exception:
        runtime = None

    if runtime is None:
        return None

    email = str(runtime.get('email') or client.get('email') or '').strip()
    live: dict[str, Any] = {
        'id': runtime.get('id'),
        'email': email,
        'is_enabled': record_is_enabled(runtime),
        'online': email in online_emails if email else False,
    }

    try:
        ips = driver.client_ips(email) if email else []
        if ips:
            live['ips'] = ips
    except Exception:
        pass

    return live


def diagnose_client_match(
    *,
    driver: Any,
    inbound_id: str,
    inbound_tag: str,
    inbound_summary: dict[str, Any],
    config_client: dict[str, Any],
    client_key: str,
    online_emails: set[str],
    live_traffic: tuple[int, int],
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    enabled = record_is_enabled(config_client)
    checks.append({'name': 'client_enabled', 'ok': enabled})
    if not enabled:
        issues.append(
            _issue(
                'error',
                'CLIENT_DISABLED',
                explain_disabled(config_client).replace('Peer', 'Client'),
                disabled_reason=config_client.get('disabled_reason'),
                disabled_at=config_client.get('disabled_at'),
                disabled_detail=config_client.get('disabled_detail'),
            )
        )

    xray_running = bool(getattr(driver, 'running', lambda: False)())
    checks.append({'name': 'xray_running', 'ok': xray_running})
    if not xray_running:
        issues.append(_issue('error', 'XRAY_NOT_RUNNING', 'Xray process or HTTP API is not reachable'))

    live = _live_user_snapshot(driver, inbound_tag, config_client, online_emails=online_emails)
    checks.append({'name': 'client_in_live_xray', 'ok': (live is not None) if enabled else True})
    if enabled and live is None:
        issues.append(
            _issue(
                'error',
                'CLIENT_NOT_IN_LIVE_XRAY',
                'Client is enabled in config but missing from live Xray inbound users — sync again or inspect apply/runtime.',
                inbound_tag=inbound_tag,
            )
        )

    if live is not None and not _client_keys_match(config_client, live):
        issues.append(
            _issue(
                'error',
                'CLIENT_KEY_MISMATCH',
                'Config client id/email does not match the live Xray user row',
                config_id=config_client.get('id'),
                live_id=live.get('id'),
            )
        )

    live_in, live_out = live_traffic
    checks.append({'name': 'traffic_stats', 'ok': live_in > 0 or live_out > 0 or not has_volume_quota(config_client)})

    if has_volume_quota(config_client) and enabled and quota_exceeded(config_client, live_in, live_out):
        issues.append(
            _issue(
                'error',
                'QUOTA_EXCEEDED',
                'Usage since baseline reached the synced remaining quota on Agent',
                remaining_bytes=int(config_client.get('volume') or 0),
            )
        )

    online = bool(live and live.get('online'))
    checks.append({'name': 'online_now', 'ok': online or not enabled})
    if enabled and live is not None and not online:
        issues.append(
            _issue(
                'warning',
                'CLIENT_OFFLINE',
                'Client is enabled on Xray but has no active online session right now',
            )
        )

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')

    return {
        'healthy': error_count == 0,
        'inbound_id': inbound_id,
        'inbound_tag': inbound_tag,
        'inbound': inbound_summary,
        'address': str(config_client.get('email') or client_key),
        'email': str(config_client.get('email') or ''),
        'client': config_client,
        'live': live,
        'checks': checks,
        'issues': issues,
        'issue_counts': {'error': error_count, 'warning': warning_count},
    }


def _traffic_for_client(driver: Any, inbound_tag: str, inbound_id: str, config_client: dict[str, Any]) -> tuple[int, int]:
    live_in = live_out = 0
    try:
        snapshot = driver.usage_snapshot()
        email = str(config_client.get('email') or '').strip()
        cid = str(config_client.get('id') or '').strip()
        for inbound in snapshot.inbounds:
            if str(inbound.tag or '') != inbound_tag and str(inbound.id or '') != str(inbound_id):
                continue
            for client in inbound.clients:
                if (email and client.email == email) or (cid and client.id == cid):
                    return int(client.incoming or 0), int(client.outgoing or 0)
    except Exception:
        pass

    return live_in, live_out


def _online_email_set(driver: Any) -> set[str]:
    try:
        return {str(email).strip() for email in driver.online_users() if str(email).strip()}
    except Exception:
        return set()


def _not_found_report(*, inbound_id: str | None, key: str) -> dict[str, Any]:
    scope = f'inbound [{inbound_id}]' if inbound_id else 'any inbound'
    issue = _issue(
        'error',
        'CLIENT_NOT_FOUND',
        f'Client [{key}] not found in Xray config for {scope}',
    )
    return {
        'success': True,
        'found': False,
        'core': 'xray',
        'inbound_id': inbound_id,
        'key': key,
        'matches': [],
        'issues': [issue],
        'summary': {
            'healthy': False,
            'issue_count': 1,
            'warning_count': 0,
            'match_count': 0,
        },
    }


def _finalize_report(*, inbound_id: str | None, key: str, email: str, matches: list[dict[str, Any]]) -> dict[str, Any]:
    issue_count = sum(int(match['issue_counts']['error']) for match in matches)
    warning_count = sum(int(match['issue_counts']['warning']) for match in matches)
    issues: list[dict[str, Any]] = []
    for match in matches:
        issues.extend(list(match.get('issues') or []))

    return {
        'success': True,
        'found': True,
        'core': 'xray',
        'inbound_id': inbound_id,
        'key': key,
        'email': email,
        'matches': matches,
        'issues': issues,
        'summary': {
            'healthy': issue_count == 0 and all(bool(match.get('healthy')) for match in matches),
            'issue_count': issue_count,
            'warning_count': warning_count,
            'match_count': len(matches),
        },
    }


def diagnose_xray_clients_by_key(driver: Any, client_key: str) -> dict[str, Any]:
    key = str(client_key or '').strip()
    if not key:
        raise ValueError('client key is required')

    config = driver.read_config()
    located = _find_config_clients_by_key(config, key)
    if not located:
        return _not_found_report(inbound_id=None, key=key)

    online_emails = _online_email_set(driver)
    matches: list[dict[str, Any]] = []
    resolved_email = ''

    for config_client, inbound_summary in located:
        inbound_tag = str(inbound_summary.get('tag') or '').strip()
        inbound_id = str(inbound_summary.get('id') or driver.id_from_tag(inbound_tag) or inbound_tag)
        if not resolved_email:
            resolved_email = str(config_client.get('email') or key)
        live_traffic = _traffic_for_client(driver, inbound_tag, inbound_id, config_client)
        matches.append(
            diagnose_client_match(
                driver=driver,
                inbound_id=inbound_id,
                inbound_tag=inbound_tag,
                inbound_summary=inbound_summary,
                config_client=config_client,
                client_key=key,
                online_emails=online_emails,
                live_traffic=live_traffic,
            )
        )

    return _finalize_report(
        inbound_id=None,
        key=key,
        email=resolved_email,
        matches=matches,
    )


def diagnose_xray_client(driver: Any, inbound_id: str | int, client_key: str) -> dict[str, Any]:
    key = str(client_key or '').strip()
    if not key:
        raise ValueError('client key is required')

    tag = driver.inbound_tag(inbound_id)
    config = driver.read_config()
    config_client, inbound_summary = _find_config_client(config, tag, str(inbound_id), key)

    if config_client is None:
        return _not_found_report(inbound_id=str(inbound_id), key=key)

    online_emails = _online_email_set(driver)
    live_in, live_out = _traffic_for_client(driver, tag, str(inbound_id), config_client)

    match = diagnose_client_match(
        driver=driver,
        inbound_id=str(inbound_id),
        inbound_tag=tag,
        inbound_summary=inbound_summary or {'id': inbound_id, 'tag': tag},
        config_client=config_client,
        client_key=key,
        online_emails=online_emails,
        live_traffic=(live_in, live_out),
    )

    return _finalize_report(
        inbound_id=str(inbound_id),
        key=key,
        email=str(config_client.get('email') or ''),
        matches=[match],
    )
