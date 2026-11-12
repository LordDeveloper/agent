from __future__ import annotations

from sqlalchemy import ForeignKey, ForeignKeyConstraint, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agent.database.base import Base


class Quota(Base):
    __tablename__ = "quotas"
    __table_args__ = (
        ForeignKeyConstraint(
            ["core_id", "client_id"],
            ["clients.core_id", "clients.id"],
            ondelete="CASCADE",
        ),
        Index("quotas_by_core", "core_id", "client_id"),
        Index("ix_quotas_by_client_id", "client_id"),
        {"sqlite_with_rowid": False},
    )

    core_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("cores.id", ondelete="CASCADE"),
        primary_key=True,
    )
    client_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    volume: Mapped[int | None] = mapped_column(Integer, nullable=True)
    baseline_incoming: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    baseline_outgoing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_connection: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inbound_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    inbound_tag: Mapped[str | None] = mapped_column(String(256), nullable=True)
    email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    protocol_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_enabled: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )

    core: Mapped["Core"] = relationship(  # noqa: F821
        back_populates="quotas",
        overlaps="quota,client",
    )
    client: Mapped["Client"] = relationship(  # noqa: F821
        back_populates="quota",
        foreign_keys=(core_id, client_id),
        primaryjoin="and_(Quota.core_id == Client.core_id, Quota.client_id == Client.id)",
        overlaps="core,quotas",
    )
