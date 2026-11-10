from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import event

from agent.database.models.client import Client
from agent.database.models.interface import Interface
from agent.database.models.quota import Quota
from agent.database.models.server import Server


def _touch_updated_at(target, *_args) -> None:
    target.updated_at = datetime.now(timezone.utc).isoformat()


def register_listeners() -> None:
    for model in (Client, Interface, Server, Quota):
        event.listen(model, "before_insert", _touch_updated_at, propagate=True)
        event.listen(model, "before_update", _touch_updated_at, propagate=True)
