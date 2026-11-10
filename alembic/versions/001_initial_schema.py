"""Initial relational schema (idempotent with legacy agent databases).

Revision ID: 001
Revises:
Create Date: 2026-03-23
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    if not _has_table("cores"):
        op.create_table(
            "cores",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sqlite_with_rowid=False,
        )
    if not _has_table("meta"):
        op.create_table(
            "meta",
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("key", sa.String(length=128), primary_key=True),
            sa.Column("value", sa.Text(), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("servers"):
        op.create_table(
            "servers",
            sa.Column("core_id", sa.String(length=64), sa.ForeignKey("cores.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("id", sa.String(length=512), primary_key=True),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("interfaces"):
        op.create_table(
            "interfaces",
            sa.Column("core_id", sa.String(length=64), sa.ForeignKey("cores.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("id", sa.String(length=512), primary_key=True),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("clients"):
        op.create_table(
            "clients",
            sa.Column("core_id", sa.String(length=64), sa.ForeignKey("cores.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("id", sa.String(length=512), primary_key=True),
            sa.Column("parent_type", sa.String(length=32), nullable=False, server_default=""),
            sa.Column("parent_interface_core_id", sa.String(length=64), nullable=True),
            sa.Column("parent_interface_id", sa.String(length=512), nullable=True),
            sa.Column("parent_server_core_id", sa.String(length=64), nullable=True),
            sa.Column("parent_server_id", sa.String(length=512), nullable=True),
            sa.Column("email", sa.String(length=512), nullable=True),
            sa.Column("name", sa.String(length=512), nullable=True),
            sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("disabled_reason", sa.Text(), nullable=True),
            sa.Column("disabled_at", sa.Text(), nullable=True),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="peer"),
            sa.Column("meta", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
        op.create_index("clients_by_core", "clients", ["core_id", "id"])
        op.create_index("clients_by_email", "clients", ["core_id", "email"])
        op.create_index("clients_by_parent_iface", "clients", ["parent_interface_core_id", "parent_interface_id"])
        op.create_index("clients_by_parent_server", "clients", ["parent_server_core_id", "parent_server_id"])
    if not _has_table("quotas"):
        op.create_table(
            "quotas",
            sa.Column("core_id", sa.String(length=64), sa.ForeignKey("cores.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("client_id", sa.String(length=512), primary_key=True),
            sa.Column("volume", sa.Integer(), nullable=True),
            sa.Column("baseline_incoming", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("baseline_outgoing", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("expires_at", sa.Text(), nullable=True),
            sa.Column("max_connection", sa.Integer(), nullable=True),
            sa.Column("inbound_id", sa.String(length=128), nullable=True),
            sa.Column("inbound_tag", sa.String(length=256), nullable=True),
            sa.Column("email", sa.String(length=512), nullable=True),
            sa.Column("protocol_id", sa.String(length=512), nullable=True),
            sa.Column("is_enabled", sa.Integer(), nullable=True),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sa.ForeignKeyConstraint(
                ["core_id", "client_id"],
                ["clients.core_id", "clients.id"],
                ondelete="CASCADE",
            ),
            sqlite_with_rowid=False,
        )
        op.create_index("quotas_by_core", "quotas", ["core_id", "client_id"])
    if not _has_table("core_artifacts"):
        op.create_table(
            "core_artifacts",
            sa.Column("core_id", sa.String(length=64), primary_key=True),
            sa.Column("kind", sa.String(length=64), primary_key=True),
            sa.Column("artifact_id", sa.String(length=512), primary_key=True),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("audit_log"):
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("ts", sa.Text(), nullable=False),
            sa.Column("action", sa.String(length=128), nullable=False),
            sa.Column("resource", sa.String(length=512), nullable=False),
            sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        )
    if not _has_table("traffic_ack"):
        op.create_table(
            "traffic_ack",
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("client_key", sa.String(length=512), primary_key=True),
            sa.Column("incoming", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("outgoing", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("traffic_pending"):
        op.create_table(
            "traffic_pending",
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("client_key", sa.String(length=512), primary_key=True),
            sa.Column("delta_incoming", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("delta_outgoing", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("current_incoming", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("current_outgoing", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("traffic_identity"):
        op.create_table(
            "traffic_identity",
            sa.Column("core", sa.String(length=64), primary_key=True),
            sa.Column("alias", sa.String(length=512), primary_key=True),
            sa.Column("canonical_key", sa.String(length=512), nullable=False),
            sqlite_with_rowid=False,
        )
    if not _has_table("documents"):
        op.create_table(
            "documents",
            sa.Column("core", sa.Text(), nullable=False),
            sa.Column("kind", sa.Text(), nullable=False),
            sa.Column("doc_id", sa.Text(), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
            sa.Column("updated_at", sa.Text(), server_default=sa.text("(datetime('now'))"), nullable=False),
            sa.PrimaryKeyConstraint("core", "kind", "doc_id"),
            sqlite_with_rowid=False,
        )

    for core in ("xray", "wireguard", "amnezia", "l2tp", "openvpn", "mullvad"):
        op.execute(sa.text("INSERT OR IGNORE INTO cores (id) VALUES (:id)").bindparams(id=core))


def downgrade() -> None:
    for table in (
        "traffic_identity",
        "traffic_pending",
        "traffic_ack",
        "audit_log",
        "core_artifacts",
        "quotas",
        "clients",
        "interfaces",
        "servers",
        "meta",
        "cores",
    ):
        if _has_table(table):
            op.drop_table(table)
