from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agent.database.base import Base


class CoreMeta(Base):
    __tablename__ = "meta"
    __table_args__ = {"sqlite_with_rowid": False}

    core: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
