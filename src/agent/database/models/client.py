from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, ForeignKeyConstraint, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agent.database.base import Base

PARENT_INTERFACE = "interface"
PARENT_SERVER = "server"
PARENT_NONE = ""


class Client(Base):
    __tablename__ = "clients"
    __table_args__ = (
        ForeignKeyConstraint(
            ("parent_interface_core_id", "parent_interface_id"),
            ("interfaces.core_id", "interfaces.id"),
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ("parent_server_core_id", "parent_server_id"),
            ("servers.core_id", "servers.id"),
            ondelete="SET NULL",
        ),
        Index("clients_by_core", "core_id", "id"),
        Index("clients_by_email", "core_id", "email"),
        Index("clients_by_parent_iface", "parent_interface_core_id", "parent_interface_id"),
        Index("clients_by_parent_server", "parent_server_core_id", "parent_server_id"),
        {"sqlite_with_rowid": False},
    )

    core_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("cores.id", ondelete="CASCADE"),
        primary_key=True,
    )
    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    parent_type: Mapped[str] = mapped_column(String(32), nullable=False, default=PARENT_NONE)
    parent_interface_core_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_interface_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    parent_server_core_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_server_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    disabled_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="peer")
    meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )

    core: Mapped["Core"] = relationship(back_populates="clients")  # noqa: F821
    interface: Mapped["Interface | None"] = relationship(  # noqa: F821
        back_populates="clients",
        foreign_keys=(parent_interface_core_id, parent_interface_id),
    )
    server: Mapped["Server | None"] = relationship(  # noqa: F821
        back_populates="clients",
        foreign_keys=(parent_server_core_id, parent_server_id),
    )
    quota: Mapped["Quota | None"] = relationship(  # noqa: F821
        back_populates="client",
        uselist=False,
        cascade="all, delete-orphan",
    )
