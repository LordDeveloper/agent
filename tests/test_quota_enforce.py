"""Quota enforcement must stay inside each driver's write batch cap."""

from types import SimpleNamespace

import pytest

from agent.errors import AgentError
from agent.support.quota import _QUOTA_WRITE_BATCH, enforce_driver_quotas


def _client(index: int, **extra) -> dict:
    row = {
        "id": f"id-{index}",
        "email": f"user-{index}@example",
        "is_enabled": True,
        "volume": 1000,
        "incoming": 0,
        "outgoing": 0,
        "_incoming": 0,
        "_outgoing": 0,
    }
    row.update(extra)
    return row


def _snapshot(clients: list[dict], *, incoming: int = 0, outgoing: int = 0):
    usage = [
        SimpleNamespace(
            email=client["email"],
            id=client["id"],
            incoming=incoming,
            outgoing=outgoing,
        )
        for client in clients
    ]
    return SimpleNamespace(inbounds=[SimpleNamespace(clients=usage)])


class _Xray:
    key = "xray"

    def __init__(self, clients: list[dict], *, live_in: int = 0, live_out: int = 0):
        self.clients = clients
        self.batches: list[list[dict]] = []
        self._snapshot = _snapshot(clients, incoming=live_in, outgoing=live_out)

    async def running(self) -> bool:
        return True

    def cached_usage_snapshot(self):
        return self._snapshot

    async def list_quota_inbounds(self):
        return [{"id": "in-1", "clients": self.clients}]

    def _clients_of(self, inbound):
        return inbound["clients"]

    async def batch_clients(self, inbound_id, clients, *, mode="update"):
        assert inbound_id == "in-1"
        assert mode == "update"
        if len(clients) > _QUOTA_WRITE_BATCH:
            raise AgentError(
                "PAYLOAD_TOO_LARGE",
                f"client batch limit is {_QUOTA_WRITE_BATCH} per request",
                413,
            )
        self.batches.append(list(clients))
        return {"ok": True, "failed": 0}


def test_write_batch_matches_driver_cap():
    assert _QUOTA_WRITE_BATCH == 200


@pytest.mark.asyncio
async def test_xray_reseed_is_split_at_the_driver_batch_cap():
    count = _QUOTA_WRITE_BATCH + 1
    clients = [_client(i, incoming=50) for i in range(count)]
    driver = _Xray(clients, live_in=50)

    disabled = await enforce_driver_quotas(driver)

    assert disabled == 0
    assert [len(batch) for batch in driver.batches] == [_QUOTA_WRITE_BATCH, 1]
    assert sum(len(batch) for batch in driver.batches) == count


@pytest.mark.asyncio
async def test_xray_disable_is_split_at_the_driver_batch_cap():
    count = _QUOTA_WRITE_BATCH + 1
    clients = [_client(i, volume=100) for i in range(count)]
    driver = _Xray(clients, live_in=150)

    disabled = await enforce_driver_quotas(driver)

    assert disabled == count
    assert [len(batch) for batch in driver.batches] == [_QUOTA_WRITE_BATCH, 1]
    assert all(row["is_enabled"] is False for batch in driver.batches for row in batch)
