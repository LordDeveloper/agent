from __future__ import annotations

import asyncio
import json
from typing import Any

JSON_OFFLOAD_BYTES = 64 * 1024


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def loads(raw: str) -> Any:
    return json.loads(raw)


def json_is_large(value: Any) -> bool:
    if isinstance(value, str):
        return len(value) >= JSON_OFFLOAD_BYTES
    if isinstance(value, list):
        return len(value) >= 32
    if isinstance(value, dict):
        for item in value.values():
            if isinstance(item, str) and len(item) >= JSON_OFFLOAD_BYTES:
                return True
            if isinstance(item, list) and len(item) >= 32:
                return True
            if isinstance(item, dict):
                for nested in item.values():
                    if isinstance(nested, list) and len(nested) >= 32:
                        return True
                    if isinstance(nested, str) and len(nested) >= JSON_OFFLOAD_BYTES:
                        return True
    return False


async def encode_json(value: Any) -> str:
    if json_is_large(value):
        return await asyncio.to_thread(dumps, value)
    return dumps(value)


async def decode_json(raw: str | None) -> Any:
    if raw is None or raw == "":
        return None
    text = str(raw)
    if len(text) >= JSON_OFFLOAD_BYTES:
        return await asyncio.to_thread(loads, text)
    return loads(text)
