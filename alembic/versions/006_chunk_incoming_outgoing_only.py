"""Pending chunks store only billable incoming/outgoing bytes.

Revision ID: 006
Revises: 005
Create Date: 2026-11-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        return

    cols = _columns("traffic_pending_chunk")
    if "incoming" in cols and "delta_incoming" not in cols:
        return

    op.create_table(
        "traffic_pending_chunk_v2",
        sa.Column("scope", sa.String(length=64), primary_key=True),
        sa.Column("chunk_id", sa.String(length=36), primary_key=True),
        sa.Column("core", sa.String(length=64), nullable=False),
        sa.Column("client_key", sa.String(length=512), nullable=False),
        sa.Column("incoming", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outgoing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sampled_at", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_traffic_pending_chunk_v2_client",
        "traffic_pending_chunk_v2",
        ["scope", "core", "client_key"],
    )

    bind = op.get_bind()
    bind.execute(
        sa.text(
            "INSERT INTO traffic_pending_chunk_v2 "
            "(scope, chunk_id, core, client_key, incoming, outgoing, sampled_at) "
            "SELECT scope, chunk_id, core, client_key, "
            "delta_incoming, delta_outgoing, sampled_at "
            "FROM traffic_pending_chunk"
        )
    )
    op.drop_index("ix_traffic_pending_chunk_client", table_name="traffic_pending_chunk")
    op.drop_table("traffic_pending_chunk")
    op.rename_table("traffic_pending_chunk_v2", "traffic_pending_chunk")
    op.execute("DROP INDEX IF EXISTS ix_traffic_pending_chunk_v2_client")
    op.create_index(
        "ix_traffic_pending_chunk_client",
        "traffic_pending_chunk",
        ["scope", "core", "client_key"],
    )


def downgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        return

    cols = _columns("traffic_pending_chunk")
    if "delta_incoming" in cols:
        return

    op.create_table(
        "traffic_pending_chunk_old",
        sa.Column("scope", sa.String(length=64), primary_key=True),
        sa.Column("chunk_id", sa.String(length=36), primary_key=True),
        sa.Column("core", sa.String(length=64), nullable=False),
        sa.Column("client_key", sa.String(length=512), nullable=False),
        sa.Column("delta_incoming", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delta_outgoing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_incoming", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_outgoing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sampled_at", sa.Text(), nullable=False),
    )
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "INSERT INTO traffic_pending_chunk_old "
            "(scope, chunk_id, core, client_key, delta_incoming, delta_outgoing, "
            "current_incoming, current_outgoing, sampled_at) "
            "SELECT scope, chunk_id, core, client_key, incoming, outgoing, 0, 0, sampled_at "
            "FROM traffic_pending_chunk"
        )
    )
    op.drop_index("ix_traffic_pending_chunk_client", table_name="traffic_pending_chunk")
    op.drop_table("traffic_pending_chunk")
    op.rename_table("traffic_pending_chunk_old", "traffic_pending_chunk")
    op.create_index(
        "ix_traffic_pending_chunk_client",
        "traffic_pending_chunk",
        ["scope", "core", "client_key"],
    )
