from __future__ import annotations

from agent.models import ClientUsageModel


def client_key(client: ClientUsageModel) -> str:
    """Billing key. Callers set ``id`` to the panel node_id and nothing else."""
    return str(client.id or "").strip()
