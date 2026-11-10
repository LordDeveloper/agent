from __future__ import annotations

from sqlalchemy import Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from agent.database.base import Base


class TrafficAck(Base):
    __tablename__ = "traffic_ack"
    __table_args__ = {"sqlite_with_rowid": False}

    scope: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    core: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    incoming: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outgoing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )


class TrafficPending(Base):
    __tablename__ = "traffic_pending"
    __table_args__ = {"sqlite_with_rowid": False}

    scope: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    core: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    delta_incoming: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delta_outgoing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_incoming: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_outgoing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=func.datetime("now"),
    )


class TrafficIdentity(Base):
    __tablename__ = "traffic_identity"
    __table_args__ = {"sqlite_with_rowid": False}

    scope: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    core: Mapped[str] = mapped_column(String(64), primary_key=True)
    alias: Mapped[str] = mapped_column(String(512), primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
