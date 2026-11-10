from __future__ import annotations

from agent.auth_scope import filter_visible, set_current_scope, set_request_isolation
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


async def test_each_token_owns_its_interfaces_and_xray_inbounds(store):
    created = await store.create_auth_token("region", "region-secret")
    set_request_isolation(True)
    try:
        set_current_scope("default")
        await store.put_doc(
            "wireguard",
            "interface",
            "1",
            {"id": 1, "name": "wg-primary", "peers": [{"id": "peer-primary", "node_id": "peer-primary"}]},
        )
        await store.put_doc("mullvad", "location", "de", {"id": "de", "country": "de"})
        set_current_scope(created["id"])
        await store.put_doc(
            "wireguard",
            "interface",
            "2",
            {"id": 2, "name": "wg-region", "peers": [{"id": "peer-region", "node_id": "peer-region"}]},
        )
        await store.bind_resource_scope("xray", "inbound", "inbound-9")
        await store.put_doc(
            "mullvad",
            "interface",
            "de-exit",
            {"id": "de-exit", "name": "de", "peers": [{"id": "mv-peer", "node_id": "mv-peer"}]},
        )

        rows = await store.list_docs("wireguard", "interface")
        visible = filter_visible(rows, "wireguard")
        assert [row["name"] for row in visible] == ["wg-region"]
        assert await store.get_doc("mullvad", "location", "de") is not None
        mullvad = await store.get_doc("mullvad", "interface", "de-exit")
        assert mullvad["scope"] == "default"
        assert await store.resource_scope("xray", "inbound", "inbound-9") == created["id"]

        scopes = await store.client_scopes()
        assert scopes[("wireguard", "peer-region")] == created["id"]
        assert scopes[("wireguard", "peer-primary")] == "default"
        assert scopes[("mullvad", "mv-peer")] == "default"

        set_current_scope("default")
        await store.put_doc("wireguard", "interface", "2", {"id": 2, "name": "hijack"})
        kept = await store.get_doc("wireguard", "interface", "2")
        assert kept["name"] == "wg-region"
        assert filter_visible(await store.list_docs("wireguard", "interface"), "wireguard")[0]["name"] == "wg-primary"
        assert (await store.get_doc("mullvad", "interface", "de-exit"))["name"] == "de"
    finally:
        set_request_isolation(False)
        set_current_scope("default")
