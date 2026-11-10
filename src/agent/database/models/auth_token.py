from __future__ import annotations

from sqlalchemy import String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from agent.database.base import Base


class AuthToken(Base):
    """An extra API token. Each one is a separate server scope on this agent."""

    __tablename__ = "auth_tokens"
    __table_args__ = {"sqlite_with_rowid": False}

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )
