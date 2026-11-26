"""Reserve a pending fetch with a ticks row instead of a timestamp on each chunk.

Revision ID: 014
Revises: 013
Create Date: 2026-11-26
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _columns(table: str) -> set[str]:
    if not _has_table(table):
        return set()
    return {col["name"] for col in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    if not _has_table(table):
        return set()
    return {idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    if _has_table("traffic_pending_chunk"):
        columns = _columns("traffic_pending_chunk")
        if "ticked_at" in columns:
            op.drop_column("traffic_pending_chunk", "ticked_at")
        if "tick" in columns and "tick_id" not in columns:
            op.alter_column("traffic_pending_chunk", "tick", new_column_name="tick_id")
        if "tick_id" not in _columns("traffic_pending_chunk"):
            op.add_column("traffic_pending_chunk", sa.Column("tick_id", sa.BigInteger(), nullable=True))
        if "ix_traffic_pending_chunk_tick" not in _indexes("traffic_pending_chunk"):
            op.execute(
                sa.text(
                    "CREATE INDEX ix_traffic_pending_chunk_tick "
                    "ON traffic_pending_chunk (scope, tick_id) "
                    "WHERE tick_id IS NOT NULL"
                )
            )
    if not _has_table("ticks"):
        op.create_table(
            "ticks",
            sa.Column("id", sa.BigInteger(), primary_key=True),
            sa.Column("scope", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.Text(), nullable=False),
            sqlite_with_rowid=False,
        )
        op.create_index("ix_ticks_created", "ticks", ["created_at"])


def downgrade() -> None:
    if _has_table("ticks"):
        op.drop_index("ix_ticks_created", table_name="ticks")
        op.drop_table("ticks")
    if not _has_table("traffic_pending_chunk"):
        return
    if "ix_traffic_pending_chunk_tick" in _indexes("traffic_pending_chunk"):
        op.drop_index("ix_traffic_pending_chunk_tick", table_name="traffic_pending_chunk")
    columns = _columns("traffic_pending_chunk")
    if "tick_id" in columns:
        op.drop_column("traffic_pending_chunk", "tick_id")
