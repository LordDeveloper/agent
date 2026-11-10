from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agent.database.base import Base

DEFAULT_CORE_KEYS = ("xray", "wireguard", "amnezia", "l2tp", "openvpn", "mullvad")


class Core(Base):
    __tablename__ = "cores"
    __table_args__ = {"sqlite_with_rowid": False}

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    clients: Mapped[list["Client"]] = relationship(  # noqa: F821
        back_populates="core",
        cascade="all, delete-orphan",
    )
    servers: Mapped[list["Server"]] = relationship(  # noqa: F821
        back_populates="core",
        cascade="all, delete-orphan",
    )
    interfaces: Mapped[list["Interface"]] = relationship(  # noqa: F821
        back_populates="core",
        cascade="all, delete-orphan",
    )
    quotas: Mapped[list["Quota"]] = relationship(  # noqa: F821
        back_populates="core",
        cascade="all, delete-orphan",
        overlaps="quota,client",
    )
