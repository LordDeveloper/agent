from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# The AUTH_TOKEN in .env owns this scope. Existing clients and inbounds stay here.
# Extra tokens from the menu get their own book.
DEFAULT_SCOPE = "default"

# Mullvad exits are one set on the machine. A server has one public IP, so it
# cannot host two regions, and the normal server does not own these interfaces.
# Their rows are not classified by auth token.
SHARED_CORES = frozenset({"mullvad"})

_scope: ContextVar[str] = ContextVar("auth_scope", default=DEFAULT_SCOPE)
_isolated: ContextVar[bool] = ContextVar("auth_scope_isolated", default=False)


def current_scope() -> str:
    scope = str(_scope.get() or "").strip()
    return scope or DEFAULT_SCOPE


def storage_scope(core: str) -> str:
    """Scope written on a new row. Shared cores always stay on the machine set."""
    if str(core) in SHARED_CORES:
        return DEFAULT_SCOPE
    return current_scope()


def set_current_scope(scope: str) -> None:
    _scope.set(str(scope or "").strip() or DEFAULT_SCOPE)


def set_request_isolation(enabled: bool) -> None:
    """Panel requests only see and change their own token's resources."""
    _isolated.set(bool(enabled))


def request_isolated() -> bool:
    return bool(_isolated.get())


def scope_is_enforced(core: str | None = None) -> bool:
    if not request_isolated():
        return False
    if core and str(core) in SHARED_CORES:
        return False
    return True


def row_visible(core: str, stored_scope: str | None) -> bool:
    if not scope_is_enforced(core):
        return True
    stored = str(stored_scope or "").strip() or DEFAULT_SCOPE
    return stored == current_scope()


def filter_visible(rows: list[dict[str, Any]], core: str) -> list[dict[str, Any]]:
    if not scope_is_enforced(core):
        return list(rows)
    return [row for row in rows if isinstance(row, dict) and row_visible(core, row.get("scope"))]
