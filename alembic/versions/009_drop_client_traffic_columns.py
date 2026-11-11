"""Remove kernel cursor columns from clients (cursor is in-memory in agent work).

Revision ID: 009
Revises: 008
Create Date: 2026-11-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_table("clients"):
        return
    cols = _columns("clients")
    drop: list[str] = []
    for name in ("incoming", "outgoing", "traffic_sample_incoming", "traffic_sample_outgoing"):
        if name in cols:
            drop.append(name)
    if not drop:
        return
    with op.batch_alter_table("clients") as batch:
        for name in drop:
            batch.drop_column(name)


def downgrade() -> None:
    if not _has_table("clients"):
        return
    cols = _columns("clients")
    if "incoming" in cols:
        return
    with op.batch_alter_table("clients") as batch:
        batch.add_column(sa.Column("incoming", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("outgoing", sa.Integer(), nullable=True))
