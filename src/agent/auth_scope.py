from __future__ import annotations

from contextvars import ContextVar

# The AUTH_TOKEN in .env owns this scope. Extra tokens from the menu get their own.
DEFAULT_SCOPE = "default"

_scope: ContextVar[str] = ContextVar("auth_scope", default=DEFAULT_SCOPE)


def current_scope() -> str:
    scope = str(_scope.get() or "").strip()
    return scope or DEFAULT_SCOPE


def set_current_scope(scope: str) -> None:
    _scope.set(str(scope or "").strip() or DEFAULT_SCOPE)
