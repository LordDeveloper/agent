from __future__ import annotations

from typing import Any

from agent.drivers.base import CoreDriver
from agent.support.client_identity import panel_client_response
from agent.support.client_sync.registry import register_adapter


class _BaseAdapter:
    def __init__(self, driver: CoreDriver) -> None:
        self.driver = driver

    def normalize_batch_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return dict(row)

    def verify_row(self, desired: dict[str, Any], live: dict[str, Any] | None) -> list[str]:
        if live is None:
            return ['missing_on_agent']
        issues: list[str] = []
        for key in ('node_id', 'id', 'email'):
            if key not in desired:
                continue
            expected = str(desired.get(key) or '').strip()
            if expected == '':
                continue
            actual = str(live.get(key) or '').strip()
            if actual and expected.lower() != actual.lower():
                issues.append(key)
        return issues


def ensure_adapters_registered() -> None:
    for core in ('xray', 'wireguard', 'amnezia', 'l2tp', 'openvpn'):
        register_adapter(core, _BaseAdapter)


def panel_response(row: dict[str, Any]) -> dict[str, Any]:
    return panel_client_response(row)
