from agent.drivers.base import CoreDriver
from agent.support.online_traffic import online_traffic_from_snapshot


class _Driver:
    key = "test"

    def __init__(self, online: list[str], snapshot):
        self._online = online
        self._snapshot = snapshot

    def online_users(self):
        return self._online

    def usage_snapshot(self):
        return self._snapshot


def test_online_traffic_from_snapshot():
    from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel

    snap = UsageSnapshotModel(
        inbounds=[
            InboundUsageModel(
                id="wg0",
                tag="wg0",
                incoming=100,
                outgoing=200,
                clients=[
                    ClientUsageModel(id="a", email="a@x.com", incoming=50, outgoing=25),
                    ClientUsageModel(id="b", email="b@x.com", incoming=999, outgoing=999),
                ],
            )
        ]
    )
    driver = _Driver(["a@x.com"], snap)
    rows = online_traffic_from_snapshot(driver)  # type: ignore[arg-type]
    assert rows["a@x.com"] == {"uplink": 25, "downlink": 50}
    assert "b@x.com" not in rows
