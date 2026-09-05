from __future__ import annotations

from agent.models import ClientUsageModel


def client_key(client: ClientUsageModel) -> str:
    """Canonical billing key shared by Xray, WireGuard, and Amnezia (panel node_id)."""
    for candidate in (client.id, client.email):
        label = str(candidate or "").strip()
        if label:
            return label
    return ""
