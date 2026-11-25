"""Per-client pending totals so billing does not sum every chunk.

Revision ID: 013
Revises: 012
Create Date: 2026-11-25

SQLite has no loose index scan. ``GROUP BY client LIMIT 100`` still reads
every pending chunk before it can return the first hundred clients.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INSERT = """
CREATE TRIGGER IF NOT EXISTS traffic_pending_chunk_insert
AFTER INSERT ON traffic_pending_chunk
BEGIN
    INSERT INTO traffic_pending_client (scope, core, client_key, incoming, outgoing, chunk_count)
    VALUES (NEW.scope, NEW.core, NEW.client_key, NEW.incoming, NEW.outgoing, 1)
    ON CONFLICT (scope, core, client_key) DO UPDATE SET
        incoming = incoming + excluded.incoming,
        outgoing = outgoing + excluded.outgoing,
        chunk_count = chunk_count + 1;
END
"""

_DELETE = """
CREATE TRIGGER IF NOT EXISTS traffic_pending_chunk_delete
AFTER DELETE ON traffic_pending_chunk
BEGIN
    UPDATE traffic_pending_client
    SET incoming = incoming - OLD.incoming,
        outgoing = outgoing - OLD.outgoing,
        chunk_count = chunk_count - 1
    WHERE scope = OLD.scope AND core = OLD.core AND client_key = OLD.client_key;
    DELETE FROM traffic_pending_client
    WHERE scope = OLD.scope AND core = OLD.core AND client_key = OLD.client_key
      AND chunk_count <= 0;
END
"""


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("traffic_pending_chunk"):
        return
    if not _has_table("traffic_pending_client"):
        op.create_table(
            "traffic_pending_client",
            sa.Column("scope", sa.String(length=64), primary_key=True),
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("client_key", sa.String(length=512), primary_key=True),
            sa.Column("incoming", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("outgoing", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("chunk_count", sa.Integer(), nullable=False, server_default="0"),
            sqlite_with_rowid=False,
        )
    op.execute(
        sa.text(
            "INSERT INTO traffic_pending_client "
            "(scope, core, client_key, incoming, outgoing, chunk_count) "
            "SELECT scope, core, client_key, "
            "coalesce(sum(incoming), 0), coalesce(sum(outgoing), 0), count(*) "
            "FROM traffic_pending_chunk "
            "GROUP BY scope, core, client_key "
            "ON CONFLICT (scope, core, client_key) DO UPDATE SET "
            "incoming = excluded.incoming, "
            "outgoing = excluded.outgoing, "
            "chunk_count = excluded.chunk_count"
        )
    )
    op.execute(sa.text(_INSERT))
    op.execute(sa.text(_DELETE))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("DROP TRIGGER IF EXISTS traffic_pending_chunk_insert")
    bind.exec_driver_sql("DROP TRIGGER IF EXISTS traffic_pending_chunk_delete")
    if _has_table("traffic_pending_client"):
        op.drop_table("traffic_pending_client")
