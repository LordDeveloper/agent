import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer

from agent.config import AgentSettings
from agent.errors import error_body

security_bearer = HTTPBearer(auto_error=False)
security_basic = HTTPBasic(auto_error=False)

_FAIL_WINDOW = 60
_MAX_FAILURES = 20
_failures: dict[str, list[float]] = defaultdict(list)


def _record_failure(key: str) -> None:
    now = time.time()
    bucket = _failures[key]
    bucket.append(now)
    _failures[key] = [t for t in bucket if now - t < _FAIL_WINDOW]
    if len(_failures[key]) >= _MAX_FAILURES:
        raise HTTPException(status_code=429, detail=error_body("INVALID_CREDENTIALS", "Too many auth failures"))


def _clear_failures(key: str) -> None:
    _failures.pop(key, None)


def verify_auth(
    request: Request,
    bearer: HTTPAuthorizationCredentials | None = Depends(security_bearer),
    basic: HTTPBasicCredentials | None = Depends(security_basic),
) -> None:
    settings: AgentSettings = request.app.state.settings
    client_key = request.client.host if request.client else "unknown"

    token = settings.auth_token
    if not token and not (settings.auth_username and settings.auth_password):
        raise HTTPException(
            status_code=500,
            detail=error_body("CONFIG_NOT_FOUND", "Agent auth is not configured"),
        )

    if bearer and bearer.credentials:
        if token and bearer.credentials == token:
            _clear_failures(client_key)
            return
        _record_failure(client_key)
        raise HTTPException(status_code=401, detail=error_body("INVALID_CREDENTIALS", "Invalid bearer token"))

    if basic and settings.auth_username and settings.auth_password:
        if basic.username == settings.auth_username and basic.password == settings.auth_password:
            _clear_failures(client_key)
            return
        _record_failure(client_key)
        raise HTTPException(status_code=401, detail=error_body("INVALID_CREDENTIALS", "Invalid basic credentials"))

    if token:
        _record_failure(client_key)
        raise HTTPException(status_code=401, detail=error_body("INVALID_CREDENTIALS", "Bearer token required"))

    _record_failure(client_key)
    raise HTTPException(status_code=401, detail=error_body("INVALID_CREDENTIALS", "Authentication required"))
