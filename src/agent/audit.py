from agent.db import Store


class AuditLog:
    def __init__(self, store: Store):
        self.store = store

    async def record(self, action: str, resource: str, detail: str = "") -> None:
        await self.store.audit(action, resource, detail)
