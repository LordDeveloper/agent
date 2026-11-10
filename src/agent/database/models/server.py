from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agent.database.base import Base


class Server(Base):
    __tablename__ = "servers"
    __table_args__ = {"sqlite_with_rowid": False}

    core_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("cores.id", ondelete="CASCADE"),
        primary_key=True,
    )
    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="default", server_default="default")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )

    core: Mapped["Core"] = relationship(back_populates="servers")  # noqa: F821
    clients: Mapped[list["Client"]] = relationship(  # noqa: F821
        back_populates="server",
        cascade="all, delete-orphan",
        foreign_keys="Client.parent_server_core_id",
    )
