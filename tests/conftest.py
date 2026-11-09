from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent.config import AgentSettings
from agent.db import Store
from agent.support.quota import configure_quota_settings


@pytest.fixture(autouse=True)
def _enable_local_volume_quota_for_legacy_tests():
    """Existing quota tests opt into the old enforcer. Production default is panel-owned cutoff."""
    configure_quota_settings(AgentSettings(enforce_local_volume_quota=True))
    yield


@pytest.fixture
async def store(tmp_path):
    db = Store(tmp_path / "agent.db")
    await db.open()
    try:
        yield db
    finally:
        await db.close()


def open_store(path: str | Path) -> Store:
    """Sync helper for tests that still use plain def fixtures."""
    db = Store(path)
    asyncio.run(db.open())
    return db
