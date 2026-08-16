from __future__ import annotations

from dataclasses import dataclass

from agent.audit import AuditLog
from agent.config import AgentSettings, load_settings
from agent.db import Store
from agent.registry import CoreRegistry


@dataclass
class Runtime:
    settings: AgentSettings
    store: Store
    audit: AuditLog
    registry: CoreRegistry

    def close(self) -> None:
        self.store.close()


def open_runtime(env_file: str | None = None) -> Runtime:
    settings = load_settings(env_file)
    store = Store(settings.resolve_db_path())
    audit = AuditLog(store)
    registry = CoreRegistry(settings, audit, store)
    return Runtime(settings=settings, store=store, audit=audit, registry=registry)
