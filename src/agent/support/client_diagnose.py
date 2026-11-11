from __future__ import annotations

from typing import Any

from agent.asyncutil import gather_independent, maybe_await
from agent.drivers.xray_http import ONLINE_IP_MAX_AGE_SECONDS, ip_last_seen_unix
from agent.support import normalize_xray_client, record_is_enabled, xray_client_rows
from agent.support.client_identity import billing_client_id, select_quota_meta
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

    The online-user list is keyed by email, and ``XrayDriver.online_users()``
    rewrites a known email to the protocol id. Both identifiers have to be
    accepted there. Comparison is case-insensitive.
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


def _session_lookup_keys(*rows: dict[str, Any] | None) -> list[str]:
    """Emails for ``/api/stats/online/iplist``.

    That route's ``email`` parameter is the Xray stats name
    (``user>>>{email}>>>online``). The protocol UUID and the panel primary key
    are not that name. Querying them returns ``online not found``.
    """
    emails: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        email = str(row.get('email') or '').strip()
        folded = email.casefold()
        if not email or folded in seen:
            continue
        seen.add(folded)
        emails.append(email)
    if emails:
        return emails
    return _client_identity_keys(*rows)


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

    Keys are Xray stats emails. A successful empty map means Xray answered and
    no session IP is inside the freshness window. ``None`` means every lookup
    failed.
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

    live_in, live_out, stats_available = _traffic_parts(live_traffic)
    checks.append({
        'name': 'traffic_stats',
        'ok': stats_available,
        'meaning': 'xray counters were read' if stats_available else 'xray counters were not read',
    })

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
    session_keys = _session_lookup_keys(config_client, live)
    if session_keys:
        session_ips, session_error = await _load_fresh_session_ips(driver, session_keys)
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

    identity = await _resolve_client_identity(driver, config_client)
    accounting = await _load_traffic_accounting(
        driver,
        node_id=str(identity.get('node_id') or ''),
        live_uplink=live_out if stats_available else None,
        live_downlink=live_in if stats_available else None,
    )
    _append_identity_checks(checks, issues, identity)
    _append_accounting_checks(checks, issues, accounting, stats_available=stats_available)

    error_count = sum(1 for row in issues if row.get('level') == 'error')
    warning_count = sum(1 for row in issues if row.get('level') == 'warning')
    from agent.support.bandwidth import unsupported_bandwidth_report

    node_id = str(identity.get('node_id') or '')
    return {
        'healthy': error_count == 0,
        'inbound_id': inbound_id,
        'inbound_tag': inbound_tag,
        'inbound': inbound_summary,
        'address': str(config_client.get('email') or client_key),
        'email': str(config_client.get('email') or ''),
        'id': node_id,
        'node_id': node_id,
        'xray_uuid': str(identity.get('xray_uuid') or ''),
        'client_link_uuid': str(identity.get('client_link_uuid') or ''),
        'client': config_client,
        'live': live,
        'traffic_accounting': accounting,
        'checks': checks,
        'issues': issues,
        'issue_counts': {'error': error_count, 'warning': warning_count},
        'bandwidth': unsupported_bandwidth_report(),
    }


def _traffic_parts(live_traffic: tuple[Any, ...]) -> tuple[int, int, bool]:
    if len(live_traffic) >= 3:
        return int(live_traffic[0] or 0), int(live_traffic[1] or 0), bool(live_traffic[2])
    if len(live_traffic) >= 2:
        return int(live_traffic[0] or 0), int(live_traffic[1] or 0), True
    return 0, 0, False


async def _resolve_client_identity(driver: Any, client: dict[str, Any]) -> dict[str, Any]:
    """Database node_id and the Xray UUID. The UUID is never filled in as node_id."""
    xray_id = str(client.get('id') or '').strip()
    email = str(client.get('email') or '').strip()
    lookup = getattr(driver, '_quota_index', None)
    index: dict[str, Any] | None = None
    if callable(lookup):
        try:
            loaded = await maybe_await(lookup())
        except Exception:
            loaded = None
        if isinstance(loaded, dict):
            index = loaded
    meta = select_quota_meta(index, protocol_id=xray_id, email=email)
    node_id = billing_client_id(meta, protocol_id=xray_id, email=email) if isinstance(meta, dict) else ''
    link = str(meta.get('client_link_uuid') or '').strip() if isinstance(meta, dict) else ''
    return {
        'node_id': node_id,
        'xray_uuid': xray_id,
        'client_link_uuid': link,
        'email': email,
        'coupled': bool(node_id and xray_id and node_id == xray_id),
    }


def describe_traffic_accounting(
    *,
    node_id: str,
    queried: bool,
    ack_rows: list[dict[str, Any]],
    pending_rows: list[dict[str, Any]],
    live_uplink: int | None,
    live_downlink: int | None,
    core: str = 'xray',
    read_error: str | None = None,
) -> dict[str, Any]:
    """Read-only view of the existing ack watermark and pending queue.

    Panel ACK attempts, retries, and persisted subscription usage are not
    stored on the agent. Those fields stay null.
    """
    node_id = str(node_id or '').strip()
    core_ack = [row for row in ack_rows if str(row.get('core') or '') == core]
    core_pending = [row for row in pending_rows if str(row.get('core') or '') == core]
    ack = core_ack[0] if core_ack else None
    pending = core_pending[0] if core_pending else None

    previous_uplink = int(ack['outgoing']) if ack is not None else None
    previous_downlink = int(ack['incoming']) if ack is not None else None
    delta_uplink = None
    delta_downlink = None
    if previous_uplink is not None and previous_downlink is not None and live_uplink is not None and live_downlink is not None:
        delta_uplink = int(live_uplink) - previous_uplink
        delta_downlink = int(live_downlink) - previous_downlink

    pending_uplink = int(pending['delta_outgoing']) if pending is not None else None
    pending_downlink = int(pending['delta_incoming']) if pending is not None else None
    ahead = (
        delta_uplink is not None
        and delta_downlink is not None
        and (delta_uplink > 0 or delta_downlink > 0)
        and pending is None
    )
    behind = (
        delta_uplink is not None
        and delta_downlink is not None
        and (delta_uplink < 0 or delta_downlink < 0)
    )

    if not node_id:
        status = 'missing'
        detail = 'Internal node_id is unavailable. Pending ACK was not queried by Xray UUID or email.'
    elif not queried:
        status = 'unavailable'
        detail = read_error or 'Pending ACK rows could not be read.'
    elif pending is not None:
        status = 'pending'
        detail = 'Pending ACK waiting to be processed.'
    elif ack is None:
        status = 'missing'
        detail = 'Missing or inconsistent accounting state. No watermark and no pending ACK.'
    elif ahead:
        status = 'inconsistent'
        detail = 'Missing or inconsistent accounting state. Live counters are ahead of the watermark and no pending ACK is stored.'
    elif behind:
        status = 'reset'
        detail = 'Missing or inconsistent accounting state. Live counters are behind the watermark.'
    else:
        status = 'no_pending_ack'
        detail = 'No pending ACK. The watermark matches the live counters. That is not a panel acknowledgement receipt.'

    return {
        'node_id': node_id or None,
        'status': status,
        'detail': detail,
        'live_uplink': live_uplink,
        'live_downlink': live_downlink,
        'previous_uplink': previous_uplink,
        'previous_downlink': previous_downlink,
        'delta_uplink': delta_uplink,
        'delta_downlink': delta_downlink,
        'pending_uplink': pending_uplink,
        'pending_downlink': pending_downlink,
        'pending_ack': bool(pending is not None) if queried and node_id else None,
        'pending_ack_id': node_id if pending is not None and node_id else None,
        'ack_watermark_updated_at': (str(ack.get('updated_at') or '') or None) if ack is not None else None,
        'pending_updated_at': (str(pending.get('updated_at') or '') or None) if pending is not None else None,
        'ack_processing': None,
        'ack_retry_count': None,
        'last_ack_attempt_at': None,
        'last_ack_error': None,
        'last_successful_ack_at': None,
        'last_persisted_usage': None,
    }


async def _load_traffic_accounting(
    driver: Any,
    *,
    node_id: str,
    live_uplink: int | None,
    live_downlink: int | None,
) -> dict[str, Any]:
    core = str(getattr(driver, 'key', 'xray') or 'xray')
    if not str(node_id or '').strip():
        return describe_traffic_accounting(
            node_id='',
            queried=False,
            ack_rows=[],
            pending_rows=[],
            live_uplink=live_uplink,
            live_downlink=live_downlink,
            core=core,
        )
    store = getattr(driver, 'store', None)
    inspect = getattr(store, 'inspect_traffic_ack', None) if store is not None else None
    if not callable(inspect):
        return describe_traffic_accounting(
            node_id=node_id,
            queried=False,
            ack_rows=[],
            pending_rows=[],
            live_uplink=live_uplink,
            live_downlink=live_downlink,
            core=core,
            read_error='traffic ack storage is not available on this driver',
        )
    try:
        inspected = await maybe_await(inspect(node_id))
    except Exception as exc:
        return describe_traffic_accounting(
            node_id=node_id,
            queried=False,
            ack_rows=[],
            pending_rows=[],
            live_uplink=live_uplink,
            live_downlink=live_downlink,
            core=core,
            read_error=str(exc) or exc.__class__.__name__,
        )
    if not isinstance(inspected, dict):
        inspected = {}
    return describe_traffic_accounting(
        node_id=node_id,
        queried=True,
        ack_rows=list(inspected.get('ack_rows') or []),
        pending_rows=list(inspected.get('pending_rows') or []),
        live_uplink=live_uplink,
        live_downlink=live_downlink,
        core=core,
    )


def _append_identity_checks(
    checks: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    identity: dict[str, Any],
) -> None:
    node_id = str(identity.get('node_id') or '')
    xray_uuid = str(identity.get('xray_uuid') or '')
    link = str(identity.get('client_link_uuid') or '')
    coupled = bool(identity.get('coupled'))
    checks.append({
        'name': 'client_identity',
        'ok': bool(node_id) and bool(xray_uuid) and not coupled,
        'node_id': node_id or None,
        'xray_uuid': xray_uuid or None,
    })
    checks.append({'name': 'node_id', 'ok': bool(node_id)})
    mapping_ok = bool(xray_uuid) and bool(node_id) and bool(link) and link == xray_uuid
    checks.append({
        'name': 'xray_uuid_mapping',
        'ok': mapping_ok,
        'client_link_uuid': link or None,
    })
    if not node_id:
        issues.append(_issue(
            'error',
            'CLIENT_NODE_ID_MISSING',
            'No internal node_id is stored for this Xray user. The Xray UUID was not used as a substitute.',
            xray_uuid=xray_uuid or None,
        ))
    elif coupled:
        issues.append(_issue(
            'warning',
            'IDENTITY_COUPLED',
            'The stored node_id and the Xray client UUID are the same string. The existing node_id was left unchanged.',
            node_id=node_id,
        ))
    if link and xray_uuid and link != xray_uuid:
        issues.append(_issue(
            'error',
            'XRAY_UUID_MISMATCH',
            'Stored client_link_uuid does not match the Xray user id.',
            client_link_uuid=link,
            xray_uuid=xray_uuid,
        ))


def _append_accounting_checks(
    checks: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    accounting: dict[str, Any],
    *,
    stats_available: bool,
) -> None:
    status = str(accounting.get('status') or '')
    delta_known = accounting.get('delta_uplink') is not None and accounting.get('delta_downlink') is not None
    live_known = accounting.get('live_uplink') is not None and accounting.get('live_downlink') is not None
    idle = (
        live_known
        and int(accounting.get('live_uplink') or 0) == 0
        and int(accounting.get('live_downlink') or 0) == 0
        and status == 'missing'
    )
    checks.append({
        'name': 'traffic_delta',
        'ok': delta_known or idle,
        'uplink': accounting.get('delta_uplink'),
        'downlink': accounting.get('delta_downlink'),
    })
    pending_ok = status in {'pending', 'no_pending_ack'} or idle or (
        status == 'reset' and bool(accounting.get('pending_ack'))
    )
    checks.append({
        'name': 'pending_usage',
        'ok': pending_ok if stats_available or status == 'pending' else False,
        'status': status or None,
    })
    if status == 'no_pending_ack':
        pending_ack_ok: bool | None = True
    elif status == 'inconsistent' or (status == 'missing' and not idle):
        pending_ack_ok = False
    else:
        pending_ack_ok = None
    checks.append({
        'name': 'pending_ack',
        'ok': pending_ack_ok,
        'state': status or None,
    })
    checks.append({
        'name': 'ack_completion',
        'ok': None,
        'reason': 'panel ACK completion is not stored on the agent',
    })
    if status == 'inconsistent':
        issues.append(_issue(
            'error',
            'TRAFFIC_DELTA_NOT_PERSISTED',
            'Live Xray counters moved past the watermark and the pending queue has no row for this node_id.',
            node_id=accounting.get('node_id'),
            delta_uplink=accounting.get('delta_uplink'),
            delta_downlink=accounting.get('delta_downlink'),
        ))
    elif status == 'missing' and live_known and (
        int(accounting.get('live_uplink') or 0) > 0 or int(accounting.get('live_downlink') or 0) > 0
    ):
        issues.append(_issue(
            'warning',
            'TRAFFIC_NOT_ANCHORED',
            'Xray counters are available, but this node_id has no traffic watermark yet. Those counters were not billed.',
            node_id=accounting.get('node_id'),
        ))
    elif status == 'reset':
        issues.append(_issue(
            'warning',
            'TRAFFIC_COUNTER_RESET',
            'Live counters are behind the stored watermark. Unacked pending bytes are kept; the cumulative total is not billed again.',
            node_id=accounting.get('node_id'),
        ))
    if not stats_available:
        issues.append(_issue(
            'error',
            'TRAFFIC_STATS_UNAVAILABLE',
            'Xray traffic statistics could not be read. Online state does not replace them.',
        ))


async def _traffic_for_client(driver: Any, inbound_tag: str, inbound_id: str, config_client: dict[str, Any]) -> tuple[int, int, bool]:
    live_in = live_out = 0
    try:
        snapshot = await maybe_await(driver.usage_snapshot())
    except Exception:
        return live_in, live_out, False

    email = str(config_client.get('email') or '').strip()
    cid = str(config_client.get('id') or '').strip()
    for inbound in snapshot.inbounds:
        if str(inbound.tag or '') != inbound_tag and str(inbound.id or '') != str(inbound_id):
            continue
        for client in inbound.clients:
            protocol = str(getattr(client, 'protocol_id', '') or '').strip()
            if (email and client.email == email) or (cid and (client.id == cid or protocol == cid)):
                return int(client.incoming or 0), int(client.outgoing or 0), True

    return live_in, live_out, True




async def _orphan_hints(driver: Any, key: str) -> dict[str, Any]:
    """Live runtime or quota rows left after the client left the saved config."""
    hints: dict[str, Any] = {}
    key = str(key or '').strip()
    if not key:
        return hints
    try:
        index = await driver._quota_index()
        meta = select_quota_meta(index, protocol_id=key, email=key)
        if meta is None:
            meta = index.get(f'n:{key}') or index.get(f'i:{key}')
        if isinstance(meta, dict):
            hints['quota_doc_present'] = True
            email = str(meta.get('email') or '').strip()
            if email:
                hints['quota_email'] = email
    except Exception:
        pass
    try:
        aliases = await driver._lookup_keys_for_panel_id(key)
        probe = driver._probe_email(aliases) if hasattr(driver, '_probe_email') else ''
        if probe:
            hints['probe_email'] = probe
        live_tags: list[str] = []
        config = await driver.read_config()
        for inbound in config.get('inbounds') or []:
            if not isinstance(inbound, dict):
                continue
            tag = str(inbound.get('tag') or '').strip()
            if not tag:
                continue
            email = probe or key
            try:
                live = await driver._filtered_live_user(tag, email)
            except Exception:
                live = None
            if live is not None:
                live_tags.append(tag)
        if live_tags:
            hints['live_inbound_tags'] = live_tags
    except Exception:
        pass
    return hints


def _not_found_report(
    *,
    inbound_id: str | None,
    key: str,
    orphan_hints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scope = f'inbound [{inbound_id}]' if inbound_id else 'any inbound'
    issue = _issue(
        'error',
        'CLIENT_NOT_FOUND',
        f'Client [{key}] not found in Xray config for {scope}',
    )
    issues = [issue]
    if orphan_hints:
        if orphan_hints.get('quota_doc_present'):
            issues.append(
                _issue(
                    'warning',
                    'ORPHAN_QUOTA_DOC',
                    'Quota document still exists even though the client is missing from config.',
                ),
            )
        if orphan_hints.get('live_inbound_tags'):
            issues.append(
                _issue(
                    'warning',
                    'ORPHAN_LIVE_USER',
                    'User is still present on a live inbound: '
                    + ', '.join(str(tag) for tag in orphan_hints['live_inbound_tags']),
                ),
            )
    return {
        'success': True,
        'found': False,
        'core': 'xray',
        'inbound_id': inbound_id,
        'key': key,
        'matches': [],
        'issues': issues,
        'orphan_hints': orphan_hints or {},
        'summary': {
            'healthy': False,
            'issue_count': sum(1 for row in issues if row.get('level') == 'error'),
            'warning_count': sum(1 for row in issues if row.get('level') == 'warning'),
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
        return _not_found_report(
            inbound_id=None,
            key=key,
            orphan_hints=await _orphan_hints(driver, key),
        )

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
        return _not_found_report(
            inbound_id=str(inbound_id),
            key=key,
            orphan_hints=await _orphan_hints(driver, key),
        )

    online_state, live_traffic = await gather_independent(
        _load_online_user_keys(driver),
        _traffic_for_client(driver, tag, str(inbound_id), config_client),
    )
    online_keys, online_error = online_state

    match = await diagnose_client_match(
        driver=driver,
        inbound_id=str(inbound_id),
        inbound_tag=tag,
        inbound_summary=inbound_summary or {'id': inbound_id, 'tag': tag},
        config_client=config_client,
        client_key=key,
        online_keys=online_keys,
        online_error=online_error,
        live_traffic=live_traffic,
    )

    return _finalize_report(
        inbound_id=str(inbound_id),
        key=key,
        email=str(config_client.get('email') or ''),
        matches=[match],
    )
