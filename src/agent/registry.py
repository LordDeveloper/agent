from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.amnezia import AmneziaDriver
from agent.drivers.base import CoreDriver
from agent.drivers.wireguard import WireGuardDriver
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError
from agent.models import CoreInfo, UsageSnapshotModel
from agent.routing import resolve_core_key


class CoreRegistry:
    def __init__(self, settings: AgentSettings, audit: AuditLog, store: Store):
        self.settings = settings
        self.audit = audit
        self.store = store
        self._drivers: dict[str, CoreDriver] = {}
        factories: dict[str, type[CoreDriver]] = {
            "xray": XrayDriver,
            "wireguard": WireGuardDriver,
            "amnezia": AmneziaDriver,
        }
        for key, factory in factories.items():
            self._drivers[key] = factory(settings, audit, store)

    def list_cores(self) -> list[CoreInfo]:
        return [self._info(driver) for driver in self._drivers.values()]

    def has(self, key: str) -> bool:
        resolved = resolve_core_key(key) or ""
        return resolved in self._drivers

    def get(self, key: str) -> CoreDriver:
        resolved = resolve_core_key(key) or ""
        driver = self._drivers.get(resolved)
        if driver is None:
            raise AgentError("CONFIG_NOT_FOUND", f"Core [{key}] is not enabled", 404)
        return driver

    def usage_snapshot(self, core: str | None = None) -> UsageSnapshotModel:
        if core:
            return self.get(core).usage_snapshot()
        merged: list = []
        for driver in self._drivers.values():
            merged.extend(driver.usage_snapshot().inbounds)
        return UsageSnapshotModel(inbounds=merged)

    def online_users(self, core: str | None = None) -> list[str]:
        if core:
            return self.get(core).online_users()
        users: list[str] = []
        for driver in self._drivers.values():
            users.extend(driver.online_users())
        return sorted(set(users))

    def _info(self, driver: CoreDriver) -> CoreInfo:
        return CoreInfo(
            key=driver.key,
            label=driver.label,
            installed=driver.installed(),
            running=driver.running(),
            version=driver.version(),
            capabilities=driver.capabilities(),
            enabled=driver.key in self.settings.cores(),
        )
