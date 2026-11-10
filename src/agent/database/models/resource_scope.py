from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from agent.database.base import Base


class ResourceScope(Base):
    """Which auth token owns one Xray inbound. Missing rows stay on the primary token."""

    __tablename__ = "resource_scopes"
    __table_args__ = {"sqlite_with_rowid": False}

    core_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), primary_key=True)
    resource_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="default", server_default="default")
