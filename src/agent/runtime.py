from __future__ import annotations

import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from agent.audit import AuditLog
    from agent.config import AgentSettings
    from agent.db import Store
    from agent.registry import CoreRegistry

_TOKEN_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_HEADER = 1400


@dataclass
class Runtime:
    settings: AgentSettings
    store: Store
    audit: AuditLog
    registry: CoreRegistry

    def close(self) -> None:
        self.store.close()


def open_runtime(env_file: str | None = None) -> Runtime:
    from agent.audit import AuditLog
    from agent.config import load_settings
    from agent.db import Store
    from agent.registry import CoreRegistry

    settings = load_settings(env_file)
    store = Store(settings.resolve_db_path())
    audit = AuditLog(store)
    registry = CoreRegistry(settings, audit, store)
    return Runtime(settings=settings, store=store, audit=audit, registry=registry)

_started: ContextVar[float | None] = ContextVar("runtime_started", default=None)
_spans: ContextVar[list[tuple[str, float]] | None] = ContextVar("runtime_spans", default=None)
_action: ContextVar[str] = ContextVar("runtime_action", default="")


class RuntimeTrace:
    """Request-scoped timings exposed as the X-RUNTIME response header."""

    header_name = "X-RUNTIME"

    @classmethod
    def start(cls, action: str = "") -> None:
        _started.set(time.perf_counter())
        _spans.set([])
        _action.set(cls.safe_name(action) if action else "")

    @classmethod
    def reset(cls) -> None:
        _started.set(None)
        _spans.set(None)
        _action.set("")

    @classmethod
    def set_action(cls, action: str) -> None:
        _action.set(cls.safe_name(action))

    @classmethod
    def add(cls, name: str, ms: float) -> None:
        spans = _spans.get()
        if spans is None:
            return
        token = cls.safe_name(name)
        if token == "":
            return
        spans.append((token, max(0.0, float(ms))))

    @classmethod
    @contextmanager
    def span(cls, name: str) -> Iterator[None]:
        if _spans.get() is None:
            yield
            return
        started = time.perf_counter()
        try:
            yield
        finally:
            cls.add(name, (time.perf_counter() - started) * 1000)

    @classmethod
    def header(cls) -> str:
        started = _started.get()
        if started is None:
            return ""

        total_ms = max(0.0, (time.perf_counter() - started) * 1000)
        parts = []
        action = _action.get()
        if action:
            parts.append(f"action={action}")
        parts.append(f"total={total_ms:.1f}ms")

        for name, ms, count in cls._aggregated():
            item = f"{name}={ms:.1f}ms"
            if count > 1:
                item += f"*{count}"
            parts.append(item)

        value = ";".join(parts)
        if len(value) <= _MAX_HEADER:
            return value
        return value[: _MAX_HEADER - 3] + "..."

    @classmethod
    def apply(cls, response: object) -> None:
        value = cls.header()
        headers = getattr(response, "headers", None)
        if not value or headers is None:
            return
        headers[cls.header_name] = value

    @classmethod
    def safe_name(cls, value: str) -> str:
        token = _TOKEN_RE.sub(".", str(value or "").strip()).strip(".")
        while ".." in token:
            token = token.replace("..", ".")
        return token[:64]

    @classmethod
    def _aggregated(cls) -> list[tuple[str, float, int]]:
        ordered: list[str] = []
        totals: dict[str, float] = {}
        counts: dict[str, int] = {}
        for name, ms in _spans.get() or []:
            if name not in totals:
                ordered.append(name)
                totals[name] = 0.0
                counts[name] = 0
            totals[name] += ms
            counts[name] += 1
        return [(name, totals[name], counts[name]) for name in ordered]


def command_span_name(args: list[str]) -> str:
    if not args:
        return "cmd"
    command = str(args[0]).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    verb = ""
    if len(args) > 1:
        candidate = str(args[1])
        if candidate and not candidate.startswith("-"):
            verb = candidate
    if verb:
        return RuntimeTrace.safe_name(f"{command}.{verb}")
    return RuntimeTrace.safe_name(command)
