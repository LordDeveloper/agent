from __future__ import annotations

import json
from typing import Any

from sqlalchemy import delete, select

from agent.database.json_codec import decode_json, encode_json
from agent.database.models.core_meta import CoreMeta
from agent.database.session import DatabaseRuntime


class MetaService:
    def __init__(self, runtime: DatabaseRuntime):
        self._runtime = runtime

    async def get_meta(self, core: str, key: str, default: Any = None) -> Any:
        async with self._runtime.reading() as session:
            row = await session.get(CoreMeta, (core, key))
            if row is None:
                return default
            return await decode_json(row.value)

    async def set_meta(self, core: str, key: str, value: Any) -> None:
        payload = await encode_json(value)
        async with self._runtime.writing() as session:
            row = await session.get(CoreMeta, (core, key))
            if row is None:
                session.add(CoreMeta(core=core, key=key, value=payload))
            else:
                row.value = payload
            await session.commit()

    async def dump_meta(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (await session.execute(select(CoreMeta).order_by(CoreMeta.core, CoreMeta.key))).scalars().all()
            dumped: list[dict[str, Any]] = []
            for row in rows:
                try:
                    value = await decode_json(row.value)
                except (TypeError, json.JSONDecodeError):
                    continue
                dumped.append({"core": row.core, "key": row.key, "value": value})
            return dumped

    async def replace_all_meta(self, rows: list[dict[str, Any]]) -> int:
        prepared: list[tuple[str, str, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            core = str(row.get("core") or "").strip()
            key = str(row.get("key") or "").strip()
            if not core or not key or len(core) > 64 or len(key) > 128 or "value" not in row:
                continue
            prepared.append((core, key, await encode_json(row.get("value"))))
        async with self._runtime.writing() as session:
            await session.execute(delete(CoreMeta))
            for core, key, payload in prepared:
                session.add(CoreMeta(core=core, key=key, value=payload))
            await session.commit()
            return len(prepared)
