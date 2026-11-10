"""Per-token ownership of interfaces, servers, and Xray inbounds.

Revision ID: 004
Revises: 003
Create Date: 2026-11-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _has_column(table: str, column: str) -> bool:
    if not _has_table(table):
        return False
    return column in {col["name"] for col in sa.inspect(op.get_bind()).get_columns(table)}


def _add_scope(table: str) -> None:
    if _has_table(table) and not _has_column(table, "scope"):
        op.add_column(
            table,
            sa.Column("scope", sa.String(length=64), nullable=False, server_default="default"),
        )


def upgrade() -> None:
    _add_scope("interfaces")
    _add_scope("servers")
    if not _has_table("resource_scopes"):
        op.create_table(
            "resource_scopes",
            sa.Column("core_id", sa.String(length=64), primary_key=True),
            sa.Column("kind", sa.String(length=64), primary_key=True),
            sa.Column("resource_id", sa.String(length=512), primary_key=True),
            sa.Column("scope", sa.String(length=64), nullable=False, server_default="default"),
            sqlite_with_rowid=False,
        )


def downgrade() -> None:
    pass
