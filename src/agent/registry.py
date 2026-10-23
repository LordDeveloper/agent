from typing import Any

from agent.asyncutil import gather_independent, maybe_await
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
from agent.support.online_traffic import traffic_from_snapshot


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

    async def list_cores(self) -> list[CoreInfo]:
        infos = await gather_independent(*(self._info(driver) for driver in self._drivers.values()))
        return [info for info in infos if isinstance(info, CoreInfo)]

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

    def enabled_drivers(self) -> list[tuple[str, CoreDriver]]:
        enabled = set(self.settings.cores())
        rows: list[tuple[str, CoreDriver]] = []
        for key, driver in self._drivers.items():
            if enabled and key not in enabled:
                continue
            rows.append((key, driver))
        return rows

    async def usage_snapshot(self, core: str | None = None) -> UsageSnapshotModel:
        if core:
            return await maybe_await(self.get(core).usage_snapshot())
        snapshots = await gather_independent(
            *(maybe_await(driver.usage_snapshot()) for _key, driver in self.enabled_drivers()),
            return_exceptions=True,
        )
        merged: list = []
        for snapshot in snapshots:
            if isinstance(snapshot, Exception) or not hasattr(snapshot, "inbounds"):
                continue
            merged.extend(snapshot.inbounds)
        return UsageSnapshotModel(inbounds=merged)

    async def online_users(self, core: str | None = None) -> list[str]:
        if core:
            return list(await maybe_await(self.get(core).online_users()))
        users: list[str] = []
        for rows in (await self.online_users_by_core()).values():
            users.extend(rows)
        return sorted(set(users))

    async def online_users_by_core(self) -> dict[str, list[str]]:
        enabled = set(self.settings.cores())
        keys = list(self._drivers)
        results = await gather_independent(
            *(self._online_users_for(key, self._drivers[key], enabled) for key in keys)
        )
        return {
            key: rows if isinstance(rows, list) else []
            for key, rows in zip(keys, results)
        }

    async def _online_users_for(
        self,
        key: str,
        driver: CoreDriver,
        enabled: set[str],
    ) -> list[str]:
        if enabled and key not in enabled:
            return []
        try:
            return list(await maybe_await(driver.online_users()))
        except AgentError:
            return []

    async def online_ips(self, core: str | None = None) -> dict[str, Any]:
        if core:
            return await maybe_await(self.get(core).online_ips_map())
        return await self.online_ips_by_core()

    async def online_ips_by_core(self) -> dict[str, Any]:
        enabled = set(self.settings.cores())
        keys = list(self._drivers)
        results = await gather_independent(
            *(self._online_ips_for(key, self._drivers[key], enabled) for key in keys)
        )
        return {
            key: rows if isinstance(rows, dict) else {}
            for key, rows in zip(keys, results)
        }

    async def _online_ips_for(
        self,
        key: str,
        driver: CoreDriver,
        enabled: set[str],
    ) -> dict[str, Any]:
        if enabled and key not in enabled:
            return {}
        try:
            ips = await maybe_await(driver.online_ips_map())
        except AgentError:
            return {}
        return ips if isinstance(ips, dict) else {}

    async def online_traffic(self, core: str | None = None) -> dict[str, dict[str, int]]:
        if core:
            return await self._online_traffic_for(self.get(core))
        merged: dict[str, dict[str, int]] = {}
        parts = await gather_independent(
            *(self._online_traffic_for(driver) for _key, driver in self.enabled_drivers()),
            return_exceptions=True,
        )
        for rows in parts:
            if not isinstance(rows, dict):
                continue
            for email, stats in rows.items():
                merged[str(email)] = stats
        return merged

    async def online_traffic_by_core(self) -> dict[str, dict[str, dict[str, int]]]:
        enabled = set(self.settings.cores())
        keys = list(self._drivers)
        results = await gather_independent(
            *(self._online_traffic_core(key, self._drivers[key], enabled) for key in keys)
        )
        return {
            key: rows if isinstance(rows, dict) else {}
            for key, rows in zip(keys, results)
        }

    async def _online_traffic_core(
        self,
        key: str,
        driver: CoreDriver,
        enabled: set[str],
    ) -> dict[str, dict[str, int]]:
        if enabled and key not in enabled:
            return {}
        try:
            return await self._online_traffic_for(driver)
        except AgentError:
            return {}

    async def _online_traffic_for(self, driver: CoreDriver) -> dict[str, dict[str, int]]:
        fn = getattr(driver, "online_traffic", None)
        if callable(fn):
            rows = await maybe_await(fn())
            return rows if isinstance(rows, dict) else {}
        from agent.support.online_traffic import online_traffic_from_snapshot

        return await online_traffic_from_snapshot(driver)

    async def live_stats(self) -> dict[str, Any]:
        """One walk per enabled core: snapshot + online users + ips + traffic."""
        enabled = set(self.settings.cores())
        keys = list(self._drivers)
        parts = await gather_independent(
            *(self._live_core(key, self._drivers[key], enabled) for key in keys)
        )
        cores: dict[str, Any] = {}
        flat_online_users: list[str] = []
        flat_online_traffic: dict[str, dict[str, int]] = {}
        flat_inbounds: list = []
        flat_ips: dict[str, Any] = {}

        for key, payload in zip(keys, parts):
            if not isinstance(payload, dict):
                payload = self._empty_live_core()
            cores[key] = payload
            flat_online_users.extend(payload.get("online_users") or [])
            for email, row in (payload.get("traffic") or {}).items():
                flat_online_traffic[str(email)] = row
            flat_inbounds.extend((payload.get("snapshot") or {}).get("inbounds") or [])
            for email, row in (payload.get("ips") or {}).items():
                flat_ips[str(email)] = row

        return {
            "cores": cores,
            "online_users": sorted(set(flat_online_users)),
            "online": {"users": flat_online_traffic},
            "snapshot": {"inbounds": flat_inbounds},
            "ips": flat_ips,
        }

    async def _live_core(self, key: str, driver: CoreDriver, enabled: set[str]) -> dict[str, Any]:
        if enabled and key not in enabled:
            return self._empty_live_core()

        snapshot_r, online_r, ips_r = await gather_independent(
            maybe_await(driver.usage_snapshot()),
            maybe_await(driver.online_users()),
            maybe_await(driver.online_ips_map()),
            return_exceptions=True,
        )
        if isinstance(snapshot_r, Exception):
            return self._empty_live_core()

        online = list(online_r) if not isinstance(online_r, Exception) else []
        ips = ips_r if isinstance(ips_r, dict) else {}
        snapshot_dump = snapshot_r.model_dump()
        traffic = traffic_from_snapshot(snapshot_r, online)
        return {
            "online_users": online,
            "ips": ips,
            "traffic": traffic,
            "snapshot": snapshot_dump,
        }

    def _empty_live_core(self) -> dict[str, Any]:
        return {
            "online_users": [],
            "ips": {},
            "traffic": {},
            "snapshot": {"inbounds": []},
        }

    async def _info(self, driver: CoreDriver) -> CoreInfo:
        try:
            running = bool(await maybe_await(driver.running()))
        except Exception:
            running = False
        try:
            version = await maybe_await(driver.version())
        except Exception:
            version = None
        try:
            installed = bool(driver.installed())
        except Exception:
            installed = False
        return CoreInfo(
            key=driver.key,
            label=driver.label,
            installed=installed,
            running=running,
            version=version,
            capabilities=driver.capabilities(),
            enabled=driver.key in self.settings.cores(),
        )
