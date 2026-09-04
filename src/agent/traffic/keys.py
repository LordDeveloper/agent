from __future__ import annotations

from agent.models import ClientUsageModel


def client_key(client: ClientUsageModel) -> str:
    for candidate in (client.email, client.id):
        label = str(candidate or "").strip()
        if label:
            return label
    return ""
