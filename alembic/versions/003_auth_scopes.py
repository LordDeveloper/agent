"""Separate pending books per auth token.

Revision ID: 003
Revises: 002
Create Date: 2026-11-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _has_column(table: str, column: str) -> bool:
    return column in {col["name"] for col in sa.inspect(op.get_bind()).get_columns(table)}


def _rebuild(table: str, create_sql: str, columns: list[str]) -> None:
    """Add scope to the primary key. Existing rows stay on the primary token."""
    if not _has_table(table) or _has_column(table, "scope"):
        return
    new = f"{table}_scoped"
    op.execute(sa.text(create_sql.format(table=new)))
    copied = ", ".join(columns)
    op.execute(sa.text(f"INSERT INTO {new} (scope, {copied}) SELECT 'default', {copied} FROM {table}"))
    op.execute(sa.text(f"DROP TABLE {table}"))
    op.execute(sa.text(f"ALTER TABLE {new} RENAME TO {table}"))


def upgrade() -> None:
    if not _has_table("auth_tokens"):
        op.create_table(
            "auth_tokens",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("token", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sa.UniqueConstraint("token"),
            sqlite_with_rowid=False,
        )
    if _has_table("clients") and not _has_column("clients", "scope"):
        op.add_column(
            "clients",
            sa.Column("scope", sa.String(length=64), nullable=False, server_default="default"),
        )
    _rebuild(
        "traffic_ack",
        """
        CREATE TABLE {table} (
            scope VARCHAR(64) NOT NULL DEFAULT 'default',
            core VARCHAR(64) NOT NULL,
            client_key VARCHAR(512) NOT NULL,
            incoming INTEGER NOT NULL DEFAULT 0,
            outgoing INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (scope, core, client_key)
        ) WITHOUT ROWID
        """,
        ["core", "client_key", "incoming", "outgoing", "updated_at"],
    )
    _rebuild(
        "traffic_pending",
        """
        CREATE TABLE {table} (
            scope VARCHAR(64) NOT NULL DEFAULT 'default',
            core VARCHAR(64) NOT NULL,
            client_key VARCHAR(512) NOT NULL,
            delta_incoming INTEGER NOT NULL DEFAULT 0,
            delta_outgoing INTEGER NOT NULL DEFAULT 0,
            current_incoming INTEGER NOT NULL DEFAULT 0,
            current_outgoing INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (scope, core, client_key)
        ) WITHOUT ROWID
        """,
        [
            "core",
            "client_key",
            "delta_incoming",
            "delta_outgoing",
            "current_incoming",
            "current_outgoing",
            "updated_at",
        ],
    )
    _rebuild(
        "traffic_identity",
        """
        CREATE TABLE {table} (
            scope VARCHAR(64) NOT NULL DEFAULT 'default',
            core VARCHAR(64) NOT NULL,
            alias VARCHAR(512) NOT NULL,
            canonical_key VARCHAR(512) NOT NULL,
            PRIMARY KEY (scope, core, alias)
        ) WITHOUT ROWID
        """,
        ["core", "alias", "canonical_key"],
    )


def downgrade() -> None:
    pass
