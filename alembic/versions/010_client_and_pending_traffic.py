"""clients.incoming/outgoing cursors; pending rows FK to clients.

Revision ID: 010
Revises: 009
Create Date: 2026-11-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if _has_table("clients"):
        cols = _columns("clients")
        with op.batch_alter_table("clients") as batch:
            if "incoming" not in cols:
                batch.add_column(sa.Column("incoming", sa.Integer(), nullable=True))
            if "outgoing" not in cols:
                batch.add_column(sa.Column("outgoing", sa.Integer(), nullable=True))


def downgrade() -> None:
    if not _has_table("clients"):
        return
    cols = _columns("clients")
    with op.batch_alter_table("clients") as batch:
        if "incoming" in cols:
            batch.drop_column("incoming")
        if "outgoing" in cols:
            batch.drop_column("outgoing")
