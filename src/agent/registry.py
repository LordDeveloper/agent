from typing import Any

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.amnezia import AmneziaDriver
from agent.drivers.base import CoreDriver
from agent.drivers.l2tp import L2tpDriver
from agent.drivers.openvpn import OpenVpnDriver
from agent.drivers.wireguard import WireGuardDriver
from agent.drivers.xray import XrayDriver
from agent.errors import AgentError
from agent.models import CoreInfo, UsageSnapshotModel
from agent.routing import resolve_core_key
from agent.support.online_traffic import collect_online_traffic, traffic_from_snapshot


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
            "l2tp": L2tpDriver,
            "openvpn": OpenVpnDriver,
        }
        for key, factory in factories.items():
            self._drivers[key] = factory(settings, audit, store)

    def list_cores(self) -> list[CoreInfo]:
        return [self._info(driver) for driver in self._drivers.values()]

    def has(self, key: str) -> bool:
        resolved = resolve_core_key(key) or ""
        return resolved in self._drivers

    def get(self, key: str, *, require_enabled: bool = True) -> CoreDriver:
        resolved = resolve_core_key(key) or ""
        driver = self._drivers.get(resolved)
        if driver is None:
            raise AgentError("CONFIG_NOT_FOUND", f"Core [{key}] is not enabled", 404)
        if require_enabled and resolved not in self.settings.cores():
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
        for rows in self.online_users_by_core().values():
            users.extend(rows)
        return sorted(set(users))

    def online_users_by_core(self) -> dict[str, list[str]]:
        enabled = set(self.settings.cores())
        out: dict[str, list[str]] = {}
        for key, driver in self._drivers.items():
            if enabled and key not in enabled:
                out[key] = []
                continue
            try:
                out[key] = driver.online_users()
            except AgentError:
                out[key] = []
        return out

    def online_ips(self, core: str | None = None) -> dict[str, Any]:
        if core:
            return self.get(core).online_ips_map()
        return self.online_ips_by_core()

    def online_ips_by_core(self) -> dict[str, Any]:
        enabled = set(self.settings.cores())
        out: dict[str, Any] = {}
        for key, driver in self._drivers.items():
            if enabled and key not in enabled:
                out[key] = {}
                continue
            try:
                out[key] = driver.online_ips_map()
            except AgentError:
                out[key] = {}
        return out

    def online_traffic(self, core: str | None = None) -> dict[str, dict[str, int]]:
        return collect_online_traffic(self, resolve_core_key(core) if core else None)

    def online_traffic_by_core(self) -> dict[str, dict[str, dict[str, int]]]:
        enabled = set(self.settings.cores())
        out: dict[str, dict[str, dict[str, int]]] = {}
        for key, driver in self._drivers.items():
            if enabled and key not in enabled:
                out[key] = {}
                continue
            try:
                fn = getattr(driver, "online_traffic", None)
                if callable(fn):
                    rows = fn()
                else:
                    from agent.support.online_traffic import online_traffic_from_snapshot

                    rows = online_traffic_from_snapshot(driver)
                out[key] = rows if isinstance(rows, dict) else {}
            except AgentError:
                out[key] = {}
        return out

    def live_stats(self) -> dict[str, Any]:
        """One walk per enabled core: snapshot + online users + ips + traffic."""
        enabled = set(self.settings.cores())
        cores: dict[str, Any] = {}
        flat_online_users: list[str] = []
        flat_online_traffic: dict[str, dict[str, int]] = {}
        flat_inbounds: list = []
        flat_ips: dict[str, Any] = {}

        for key, driver in self._drivers.items():
            if enabled and key not in enabled:
                cores[key] = self._empty_live_core()
                continue

            try:
                snapshot = driver.usage_snapshot()
            except AgentError:
                cores[key] = self._empty_live_core()
                continue

            try:
                online = list(driver.online_users())
            except AgentError:
                online = []

            try:
                ips = driver.online_ips_map()
            except AgentError:
                ips = {}

            if not isinstance(ips, dict):
                ips = {}

            snapshot_dump = snapshot.model_dump()
            traffic = traffic_from_snapshot(snapshot, online)
            cores[key] = {
                "online_users": online,
                "ips": ips,
                "traffic": traffic,
                "snapshot": snapshot_dump,
            }
            flat_online_users.extend(online)
            for email, row in traffic.items():
                flat_online_traffic[str(email)] = row
            flat_inbounds.extend(snapshot_dump.get("inbounds") or [])
            for email, row in ips.items():
                flat_ips[str(email)] = row

        return {
            "cores": cores,
            "online_users": sorted(set(flat_online_users)),
            "online": {"users": flat_online_traffic},
            "snapshot": {"inbounds": flat_inbounds},
            "ips": flat_ips,
        }

    def _empty_live_core(self) -> dict[str, Any]:
        return {
            "online_users": [],
            "ips": {},
            "traffic": {},
            "snapshot": {"inbounds": []},
        }

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
