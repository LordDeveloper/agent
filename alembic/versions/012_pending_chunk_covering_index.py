"""Covering index for pending-chunk sums and ordered reads.

Revision ID: 012
Revises: 011
Create Date: 2026-11-25
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "012"
down_revision: Union[str, None] = "011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _indexes(table: str) -> set[str]:
    if not _has_table(table):
        return set()
    return {idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        return
    if "ix_traffic_pending_chunk_totals" not in _indexes("traffic_pending_chunk"):
        op.create_index(
            "ix_traffic_pending_chunk_totals",
            "traffic_pending_chunk",
            ["scope", "core", "client_key", "sampled_at", "incoming", "outgoing", "chunk_id"],
        )
    if "ix_traffic_pending_chunk_client" in _indexes("traffic_pending_chunk"):
        op.drop_index("ix_traffic_pending_chunk_client", table_name="traffic_pending_chunk")


def downgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        return
    if "ix_traffic_pending_chunk_client" not in _indexes("traffic_pending_chunk"):
        op.create_index(
            "ix_traffic_pending_chunk_client",
            "traffic_pending_chunk",
            ["scope", "core", "client_key"],
        )
    if "ix_traffic_pending_chunk_totals" in _indexes("traffic_pending_chunk"):
        op.drop_index("ix_traffic_pending_chunk_totals", table_name="traffic_pending_chunk")
