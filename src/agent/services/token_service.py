from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError

from agent.database.models.auth_token import AuthToken
from agent.database.session import DatabaseRuntime


class TokenService:
    def __init__(self, runtime: DatabaseRuntime):
        self._runtime = runtime

    async def list_tokens(self) -> list[dict[str, Any]]:
        async with self._runtime.reading() as session:
            rows = (await session.execute(select(AuthToken).order_by(AuthToken.created_at, AuthToken.name))).scalars().all()
            return [
                {
                    "id": row.id,
                    "name": row.name,
                    "token": row.token,
                    "created_at": row.created_at,
                }
                for row in rows
            ]

    async def create_token(self, name: str, token: str) -> dict[str, Any]:
        label = str(name or "").strip()
        secret = str(token or "").strip()
        if not label or not secret:
            raise ValueError("name and token are required")
        row = AuthToken(
            id=secrets.token_hex(8),
            name=label[:128],
            token=secret,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        async with self._runtime.writing() as session:
            session.add(row)
            await session.commit()
        return {"id": row.id, "name": row.name, "token": row.token, "created_at": row.created_at}

    async def delete_token(self, token_id: str) -> bool:
        async with self._runtime.writing() as session:
            result = await session.execute(delete(AuthToken).where(AuthToken.id == str(token_id or "").strip()))
            await session.commit()
            return bool(result.rowcount)

    async def scope_for_token(self, token: str) -> str | None:
        secret = str(token or "").strip()
        if not secret:
            return None
        try:
            async with self._runtime.reading() as session:
                row = (
                    await session.execute(select(AuthToken).where(AuthToken.token == secret))
                ).scalar_one_or_none()
        except OperationalError:
            return None
        if row is None:
            return None
        return str(row.id)
