from __future__ import annotations

from typing import Any

from agent.asyncutil import gather_independent, maybe_await
from agent.drivers.xray_http import ONLINE_IP_MAX_AGE_SECONDS, ip_last_seen_unix
from agent.support import normalize_xray_client, record_is_enabled, xray_client_rows
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

    for row in xray_client_rows(inbound):
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


def _client_identity_keys(*rows: dict[str, Any] | None) -> list[str]:
    """Email, protocol UUID, and node id, in lookup order.

    Xray stats and the online-user list are keyed by email, while
    ``XrayDriver.online_users()`` rewrites a known email to the protocol id.
    Both identifiers have to be accepted. Comparison is case-insensitive.
    """
    ordered: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ('email', 'id', 'node_id', 'uuid'):
            text = str(row.get(field) or '').strip()
            folded = text.casefold()
            if not text or folded in seen:
                continue
            seen.add(folded)
            ordered.append(text)
    return ordered


def _keys_overlap(left: list[str] | set[str], right: list[str] | set[str]) -> bool:
    folded = {str(item).strip().casefold() for item in left if str(item).strip()}
    if not folded:
        return False
    return any(str(item).strip().casefold() in folded for item in right)


def _coerce_ip_map(rows: Any) -> dict[str, Any]:
    if isinstance(rows, dict):
        return {str(ip): seen for ip, seen in rows.items() if str(ip).strip()}
    if isinstance(rows, list):
        return {str(ip): None for ip in rows if str(ip).strip()}
    return {}


def _max_last_seen(ips: dict[str, Any]) -> float | None:
    latest: float | None = None
    for seen in ips.values():
        stamp = ip_last_seen_unix(seen)
        if stamp is None:
            continue
        if latest is None or stamp > latest:
            latest = stamp
    return latest


async def _load_online_user_keys(driver: Any) -> tuple[set[str] | None, str | None]:
    """Identifiers from the online-user list.

    ``None`` means the list could not be read. An empty set means the call
    succeeded and Xray reported nobody online. Do not collapse those cases:
    a failed call is not evidence that this client is offline.
    """
    try:
        users = await maybe_await(driver.online_users())
    except Exception as exc:
        return None, str(exc) or exc.__class__.__name__

    keys: set[str] = set()
    for item in users or []:
        text = str(item or '').strip()
        if text:
            keys.add(text)
    return keys, None


async def _load_fresh_session_ips(
    driver: Any,
    identities: list[str],
) -> tuple[dict[str, Any] | None, str | None]:
    """Fresh session IPs for this client.

    Tries each identity (email, then UUID) and stops at the first key that
    still has a live address, so a stats entry stored under the other id is
    not missed. A successful empty map means Xray answered and no session IP
    is inside the freshness window. ``None`` means every lookup failed.
    """
    last_seen = getattr(driver, 'client_ip_last_seen', None)
    ips_only = getattr(driver, 'client_ips', None)
    if not callable(last_seen) and not callable(ips_only):
        return None, 'session IP list is not available on this driver'

    errors: list[str] = []
    saw_success = False
    for key in identities:
        try:
            if callable(last_seen):
                rows = await maybe_await(last_seen(key))
            else:
                rows = await maybe_await(ips_only(key))
        except Exception as exc:
            errors.append(str(exc) or exc.__class__.__name__)
            continue
        saw_success = True
        parsed = _coerce_ip_map(rows)
        if parsed:
            return parsed, None
    if saw_success:
        return {}, None
    return None, errors[0] if errors else 'session IP list could not be read'


def _classify_online(
    *,
    xray_running: bool,
    live_present: bool,
    identities: list[str],
    online_keys: set[str] | None,
    online_error: str | None,
    session_ips: dict[str, Any] | None,
    session_error: str | None,
) -> dict[str, Any]:
    """ONLINE, OFFLINE, or UNKNOWN from session evidence.

    A fresh iplist address or a matching online-user entry (email or UUID) is
    enough to call the client online. Cumulative uplink/downlink counters are
    not session evidence: they survive after the client disconnects and are
    reset independently of presence.
    """
    window = int(ONLINE_IP_MAX_AGE_SECONDS)
    ips = session_ips or {}
    # A stopped core makes online_users() return [] without an error. That
    # empty list is not a confirmed "nobody is connected" result.
    users_ok = bool(xray_running) and online_keys is not None and not online_error
    ips_ok = session_ips is not None and not session_error
    in_users = users_ok and _keys_overlap(identities, online_keys or set())
    has_ip = bool(ips)
    base: dict[str, Any] = {
        'window_seconds': window,
        'last_activity': _max_last_seen(ips),
        'session_ips': list(ips.keys()),
        'ip_last_seen': {ip: seen for ip, seen in ips.items() if seen is not None},
    }

    if has_ip and in_users:
        return {
            **base,
            'status': 'online',
            'source': 'online_ips+online_users',
            'reason': (
                f'Fresh session IP within {window}s and a matching online-user entry (email or UUID)'
            ),
        }
    if has_ip:
        return {
            **base,
            'status': 'online',
            'source': 'online_ips',
            'reason': (
                f'Xray iplist has a session IP seen within {window}s. '
                'Missing from the online-user list alone is not treated as offline'
            ),
        }
    if in_users:
        return {
            **base,
            'status': 'online',
            'source': 'online_users',
            'reason': 'Email or UUID is present in the Xray online-user list',
        }
    if not live_present:
        return {
            **base,
            'status': 'unknown',
            'source': 'unavailable',
            'reason': 'Client is not in the live Xray user list, so session state was not evaluated',
        }
    if not xray_running:
        return {
            **base,
            'status': 'unknown',
            'source': 'unavailable',
            'reason': 'Xray is not running, so an active session cannot be confirmed or ruled out',
        }
    if not users_ok and not ips_ok:
        detail = online_error or session_error or 'runtime online data was not returned'
        return {
            **base,
            'status': 'unknown',
            'source': 'unavailable',
            'reason': f'Online-user list and session IP list were unavailable ({detail})',
        }
    if not users_ok:
        return {
            **base,
            'status': 'unknown',
            'source': 'unavailable',
            'reason': (
                'No fresh session IP, but the online-user list could not be read. '
                'That is not enough to call the client offline'
            ),
        }
    if not ips_ok:
        return {
            **base,
            'status': 'unknown',
            'source': 'unavailable',
            'reason': (
                'Client is not in the online-user list, but the session IP list could not be read. '
                'That is not enough to call the client offline'
            ),
        }
    return {
        **base,
        'status': 'offline',
        'source': 'online_ips+online_users',
        'reason': (
            f'No online-user entry for this email or UUID and no session IP within {window}s. '
            'Cumulative traffic counters are not current activity'
        ),
    }


async def _live_user_snapshot(
    driver: Any,
    inbound_tag: str,
    client: dict[str, Any],
) -> dict[str, Any] | None:
    runtime = None
    try:
        for inbound in await maybe_await(driver.list_inbounds()):
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
    return {
        'id': runtime.get('id'),
        'email': email,
        'node_id': runtime.get('node_id') or client.get('node_id'),
        'is_enabled': record_is_enabled(runtime),
    }


async def diagnose_client_match(
    *,
    driver: Any,
    inbound_id: str,
    inbound_tag: str,
    inbound_summary: dict[str, Any],
    config_client: dict[str, Any],
    client_key: str,
    online_keys: set[str] | None,
    online_error: str | None,
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

    running = getattr(driver, 'running', None)
    xray_running = bool(await maybe_await(running())) if callable(running) else False
    checks.append({'name': 'xray_running', 'ok': xray_running})
    if not xray_running:
        issues.append(_issue('error', 'XRAY_NOT_RUNNING', 'Xray process or HTTP API is not reachable'))

    live = await _live_user_snapshot(driver, inbound_tag, config_client)
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

    identities = _client_identity_keys(config_client, live)
    if identities:
        session_ips, session_error = await _load_fresh_session_ips(driver, identities)
    else:
        session_ips, session_error = None, 'client has no email or UUID to query'
    decision = _classify_online(
        xray_running=xray_running,
        live_present=live is not None,
        identities=identities,
        online_keys=online_keys,
        online_error=online_error,
        session_ips=session_ips,
        session_error=session_error,
    )
    status = str(decision['status'])
    online_value = True if status == 'online' else False if status == 'offline' else None
    if live is not None:
        live['online'] = online_value
        live['online_status'] = status
        live['online_source'] = decision['source']
        live['online_reason'] = decision['reason']
        live['online_window_seconds'] = decision['window_seconds']
        if decision['session_ips']:
            live['ips'] = decision['session_ips']
        if decision['ip_last_seen']:
            live['ip_last_seen'] = decision['ip_last_seen']
        if decision['last_activity'] is not None:
            live['last_activity'] = decision['last_activity']
        live['traffic'] = {
            'uplink': live_out,
            'downlink': live_in,
            'kind': 'cumulative',
        }

    online_check: dict[str, Any] = {
        'name': 'online_now',
        'ok': True if not enabled else online_value,
        'status': status if enabled else 'skipped',
        'source': decision['source'],
        'reason': decision['reason'] if enabled else 'Client is disabled; an active session is not required',
        'window_seconds': decision['window_seconds'],
        'uplink': live_out,
        'downlink': live_in,
        'counters': 'cumulative',
    }
    if decision['last_activity'] is not None:
        online_check['last_activity'] = int(decision['last_activity'])
    if decision['session_ips']:
        online_check['ips'] = ','.join(str(ip) for ip in decision['session_ips'])
    checks.append(online_check)
    if enabled and status == 'offline':
        issues.append(
            _issue(
                'warning',
                'CLIENT_OFFLINE',
                str(decision['reason']),
                source=decision['source'],
                window_seconds=decision['window_seconds'],
            )
        )
    elif enabled and status == 'unknown':
        issues.append(
            _issue(
                'info',
                'ONLINE_STATUS_UNKNOWN',
                str(decision['reason']),
                source=decision['source'],
            )
        )

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')
    stored_id = await _stored_client_id(driver, config_client)
    from agent.support.bandwidth import unsupported_bandwidth_report

    return {
        'healthy': error_count == 0,
        'inbound_id': inbound_id,
        'inbound_tag': inbound_tag,
        'inbound': inbound_summary,
        'address': str(config_client.get('email') or client_key),
        'email': str(config_client.get('email') or ''),
        'id': stored_id,
        'client': config_client,
        'live': live,
        'checks': checks,
        'issues': issues,
        'issue_counts': {'error': error_count, 'warning': warning_count},
        'bandwidth': unsupported_bandwidth_report(),
    }


async def _stored_client_id(driver: Any, client: dict[str, Any]) -> str:
    """Agent database id for this client. Not the Xray/link UUID."""
    xray_id = str(client.get('id') or '').strip()
    lookup = getattr(driver, '_quota_index', None)
    if not callable(lookup):
        return str(client.get('agent_id') or '').strip()

    try:
        index = await maybe_await(lookup())
    except Exception:
        index = None
    if not isinstance(index, dict):
        return str(client.get('agent_id') or '').strip()

    email = str(client.get('email') or '').strip()
    node_id = str(client.get('node_id') or '').strip()
    meta = index.get(f'n:{xray_id}') if xray_id else None
    if meta is None and node_id:
        meta = index.get(f'n:{node_id}')
    if meta is None and email:
        meta = index.get(f'e:{email}')
    if meta is None and xray_id:
        meta = index.get(f'i:{xray_id}')
    if not isinstance(meta, dict):
        return str(client.get('agent_id') or '').strip()

    link = str(meta.get('node_id') or xray_id).strip()
    legacy = str(meta.get('agent_id') or meta.get('primary_key') or '').strip()
    stored = str(meta.get('id') or '').strip()
    if legacy and legacy != link:
        return legacy
    return stored


async def _traffic_for_client(driver: Any, inbound_tag: str, inbound_id: str, config_client: dict[str, Any]) -> tuple[int, int]:
    live_in = live_out = 0
    try:
        snapshot = await maybe_await(driver.usage_snapshot())
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


async def diagnose_xray_clients_by_key(driver: Any, client_key: str) -> dict[str, Any]:
    key = str(client_key or '').strip()
    if not key:
        raise ValueError('client key is required')

    config = await driver.read_config()
    located = _find_config_clients_by_key(config, key)
    if not located:
        return _not_found_report(inbound_id=None, key=key)

    online_keys, online_error = await _load_online_user_keys(driver)
    resolved_email = ''
    jobs = []
    for config_client, inbound_summary in located:
        inbound_tag = str(inbound_summary.get('tag') or '').strip()
        inbound_id = str(inbound_summary.get('id') or driver.id_from_tag(inbound_tag) or inbound_tag)
        if not resolved_email:
            resolved_email = str(config_client.get('email') or key)
        jobs.append((config_client, inbound_summary, inbound_tag, inbound_id))

    async def one(config_client, inbound_summary, inbound_tag, inbound_id):
        live_traffic = await _traffic_for_client(driver, inbound_tag, inbound_id, config_client)
        return await diagnose_client_match(
            driver=driver,
            inbound_id=inbound_id,
            inbound_tag=inbound_tag,
            inbound_summary=inbound_summary,
            config_client=config_client,
            client_key=key,
            online_keys=online_keys,
            online_error=online_error,
            live_traffic=live_traffic,
        )

    matches = await gather_independent(*(one(*job) for job in jobs))
    matches = [row for row in matches if isinstance(row, dict)]

    return _finalize_report(
        inbound_id=None,
        key=key,
        email=resolved_email,
        matches=matches,
    )


async def diagnose_xray_client(driver: Any, inbound_id: str | int, client_key: str) -> dict[str, Any]:
    key = str(client_key or '').strip()
    if not key:
        raise ValueError('client key is required')

    tag = driver.inbound_tag(inbound_id)
    config = await driver.read_config()
    config_client, inbound_summary = _find_config_client(config, tag, str(inbound_id), key)

    if config_client is None:
        return _not_found_report(inbound_id=str(inbound_id), key=key)

    online_state, live_traffic = await gather_independent(
        _load_online_user_keys(driver),
        _traffic_for_client(driver, tag, str(inbound_id), config_client),
    )
    online_keys, online_error = online_state
    live_in, live_out = live_traffic

    match = await diagnose_client_match(
        driver=driver,
        inbound_id=str(inbound_id),
        inbound_tag=tag,
        inbound_summary=inbound_summary or {'id': inbound_id, 'tag': tag},
        config_client=config_client,
        client_key=key,
        online_keys=online_keys,
        online_error=online_error,
        live_traffic=(live_in, live_out),
    )

    return _finalize_report(
        inbound_id=str(inbound_id),
        key=key,
        email=str(config_client.get('email') or ''),
        matches=[match],
    )
