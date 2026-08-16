from pathlib import Path

from agent.db import Store


class AuditLog:
    def __init__(self, store: Store):
        self.store = store

    def record(self, action: str, resource: str, detail: str = "") -> None:
        self.store.audit(action, resource, detail)
