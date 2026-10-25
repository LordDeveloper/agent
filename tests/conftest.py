from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent.db import Store


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
