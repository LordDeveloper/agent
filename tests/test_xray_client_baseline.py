from agent.drivers.xray import clients_already_on_inbound


def test_new_client_does_not_query_live_counters():
    clients = [{"email": "new@test", "id": "uuid-new", "_incoming": 0, "_outgoing": 0}]

    assert clients_already_on_inbound(clients, {}, {}) == []


def test_existing_email_still_queries_live_counters():
    row = {"email": "kept@test", "id": "uuid-kept"}

    assert clients_already_on_inbound(
        [row],
        {"kept@test": {"email": "kept@test"}},
        {},
    ) == [row]
