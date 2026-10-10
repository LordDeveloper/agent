from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support.online_traffic import traffic_from_snapshot


def test_traffic_from_snapshot_indexes_id_and_email():
    snapshot = UsageSnapshotModel(
        inbounds=[
            InboundUsageModel(
                id=1,
                tag="vless",
                incoming=20,
                outgoing=10,
                clients=[
                    ClientUsageModel(
                        id="uuid-1",
                        email="alpha",
                        incoming=20,
                        outgoing=10,
                    )
                ],
            )
        ]
    )

    traffic = traffic_from_snapshot(snapshot, ["alpha", "uuid-1"])

    assert traffic["alpha"] == {"uplink": 10, "downlink": 20}
    assert traffic["uuid-1"] == {"uplink": 10, "downlink": 20}


def test_traffic_from_snapshot_skips_offline_clients():
    snapshot = UsageSnapshotModel(
        inbounds=[
            InboundUsageModel(
                id=1,
                tag="vless",
                incoming=20,
                outgoing=10,
                clients=[
                    ClientUsageModel(id="offline", email="gone", incoming=20, outgoing=10),
                ],
            )
        ]
    )

    assert traffic_from_snapshot(snapshot, ["online-only"]) == {"online-only": {}}
