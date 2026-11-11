"""Drop traffic_sample_state; kernel cursor lives on clients.incoming/outgoing only.

Revision ID: 008
Revises: 007
Create Date: 2026-11-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if _has_table("traffic_sample_state"):
        op.drop_table("traffic_sample_state")

    if not _has_table("clients"):
        return
    cols = _columns("clients")
    if "traffic_sample_incoming" in cols and "incoming" not in cols:
        with op.batch_alter_table("clients") as batch:
            batch.alter_column("traffic_sample_incoming", new_column_name="incoming")
            batch.alter_column("traffic_sample_outgoing", new_column_name="outgoing")
    elif "incoming" not in cols:
        with op.batch_alter_table("clients") as batch:
            batch.add_column(sa.Column("incoming", sa.Integer(), nullable=True))
            batch.add_column(sa.Column("outgoing", sa.Integer(), nullable=True))


def downgrade() -> None:
    if _has_table("clients"):
        cols = _columns("clients")
        if "incoming" in cols and "traffic_sample_incoming" not in cols:
            with op.batch_alter_table("clients") as batch:
                batch.alter_column("incoming", new_column_name="traffic_sample_incoming")
                batch.alter_column("outgoing", new_column_name="traffic_sample_outgoing")

    if not _has_table("traffic_sample_state"):
        op.create_table(
            "traffic_sample_state",
            sa.Column("scope", sa.String(length=64), primary_key=True),
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("client_key", sa.String(length=512), primary_key=True),
            sa.Column("incoming", sa.Integer(), nullable=True),
            sa.Column("outgoing", sa.Integer(), nullable=True),
        )
