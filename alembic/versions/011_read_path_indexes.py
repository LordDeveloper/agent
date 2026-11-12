"""Indexes for traffic cursor reads and client lookups.

Revision ID: 011
Revises: 010
Create Date: 2026-11-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _indexes(table: str) -> set[str]:
    if not _has_table(table):
        return set()
    return {idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)}


def _ensure(table: str, name: str, columns: list[str]) -> None:
    if not _has_table(table) or name in _indexes(table):
        return
    op.create_index(name, table, columns)


def _drop(table: str, name: str) -> None:
    if name in _indexes(table):
        op.drop_index(name, table_name=table)


def upgrade() -> None:
    _ensure("clients", "ix_clients_scope_cursor", ["scope", "core_id", "id", "incoming", "outgoing"])
    _ensure("clients", "ix_clients_cursor", ["core_id", "id", "incoming", "outgoing"])
    _ensure("clients", "ix_clients_by_id", ["id"])
    _ensure("clients", "ix_clients_email", ["email"])
    _ensure("clients", "ix_clients_by_role", ["core_id", "role"])
    _ensure("quotas", "ix_quotas_by_client_id", ["client_id"])
    _ensure("traffic_ack", "ix_traffic_ack_client", ["scope", "client_key"])
    _ensure("traffic_pending", "ix_traffic_pending_client", ["scope", "client_key"])
    _ensure("traffic_pending_chunk", "ix_traffic_pending_chunk_client", ["scope", "core", "client_key"])


def downgrade() -> None:
    _drop("traffic_pending", "ix_traffic_pending_client")
    _drop("traffic_ack", "ix_traffic_ack_client")
    _drop("quotas", "ix_quotas_by_client_id")
    _drop("clients", "ix_clients_by_role")
    _drop("clients", "ix_clients_email")
    _drop("clients", "ix_clients_by_id")
    _drop("clients", "ix_clients_cursor")
    _drop("clients", "ix_clients_scope_cursor")
