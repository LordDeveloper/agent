"""Append-only pending chunks (one row per sample tick).

Revision ID: 005
Revises: 004
Create Date: 2026-11-11
"""

from __future__ import annotations

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        op.create_table(
            "traffic_pending_chunk",
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
        op.create_index(
            "ix_traffic_pending_chunk_client",
            "traffic_pending_chunk",
            ["scope", "core", "client_key"],
        )

    if _has_table("traffic_pending") and _has_table("traffic_pending_chunk"):
        bind = op.get_bind()
        rows = bind.execute(
            sa.text(
                "SELECT scope, core, client_key, delta_incoming, delta_outgoing, "
                "current_incoming, current_outgoing, updated_at FROM traffic_pending"
            )
        ).fetchall()
        for row in rows:
            chunk_id = str(uuid.uuid4())
            bind.execute(
                sa.text(
                    "INSERT OR IGNORE INTO traffic_pending_chunk "
                    "(scope, chunk_id, core, client_key, delta_incoming, delta_outgoing, "
                    "current_incoming, current_outgoing, sampled_at) "
                    "VALUES (:scope, :chunk_id, :core, :client_key, :din, :dout, :cin, :cout, :sampled_at)"
                ),
                {
                    "scope": row[0],
                    "chunk_id": chunk_id,
                    "core": row[1],
                    "client_key": row[2],
                    "din": row[3],
                    "dout": row[4],
                    "cin": row[5],
                    "cout": row[6],
                    "sampled_at": row[7] or "",
                },
            )


def downgrade() -> None:
    if _has_table("traffic_pending_chunk"):
        op.drop_index("ix_traffic_pending_chunk_client", table_name="traffic_pending_chunk")
        op.drop_table("traffic_pending_chunk")
