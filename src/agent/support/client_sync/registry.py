from __future__ import annotations

from typing import Any, Callable

from agent.drivers.base import CoreDriver

AdapterFactory = Callable[[CoreDriver], Any]

_ADAPTERS: dict[str, AdapterFactory] = {}


def register_adapter(core_key: str, factory: AdapterFactory) -> None:
    _ADAPTERS[core_key.strip().lower()] = factory


def list_registered_cores() -> list[str]:
    return sorted(_ADAPTERS.keys())


def adapter_for_core(driver: CoreDriver) -> Any | None:
    factory = _ADAPTERS.get(getattr(driver, 'key', '').strip().lower())
    if factory is None:
        return None
    return factory(driver)


def _bootstrap() -> None:
    from agent.support.client_sync.adapters import ensure_adapters_registered

    ensure_adapters_registered()


_bootstrap()
