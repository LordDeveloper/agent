from __future__ import annotations

from agent.auth_scope import set_current_scope
from agent.database.models.client import Client
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.traffic.service import TrafficService


class FakeDriver:
    key = "xray"

    def __init__(self, clients):
        self._clients = clients

    def usage_snapshot(self):
        return UsageSnapshotModel(
            inbounds=[InboundUsageModel(id=1, tag="in", clients=self._clients)]
        )


class FakeRegistry:
    def __init__(self, driver):
        self.settings = type("S", (), {"cores": lambda self: ["xray"]})()
        self._driver = driver

    def get(self, core: str):
        return self._driver


async def test_each_token_keeps_its_own_pending_queue(store):
    created = await store.create_auth_token("region", "region-secret")
    assert await store.scope_for_token("region-secret") == created["id"]
    assert await store.scope_for_token("missing") is None

    async with store._runtime.writing() as session:
        session.add(Client(core_id="xray", id="region-node", scope=created["id"], role="peer"))
        await session.commit()

    traffic = TrafficService(store)
    primary = ClientUsageModel(id="primary-node", email="primary@example.com", incoming=1_000, outgoing=0)
    region = ClientUsageModel(id="region-node", email="region@example.com", incoming=1_000, outgoing=0)
    driver = FakeDriver([primary, region])
    registry = FakeRegistry(driver)

    await traffic.sample_all(registry)
    primary.incoming = 1_100
    region.incoming = 1_500
    await traffic.sample_all(registry)

    set_current_scope("default")
    default_users = (await traffic.pending_payload())["users"]
    assert default_users["primary-node"]["downlink"] == 100
    assert "region-node" not in default_users

    set_current_scope(created["id"])
    region_users = (await traffic.pending_payload())["users"]
    assert region_users["region-node"]["downlink"] == 500
    assert "primary-node" not in region_users
