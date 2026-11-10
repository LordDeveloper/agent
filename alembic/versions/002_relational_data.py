"""Migrate legacy documents rows into relational tables.

Revision ID: 002
Revises: 001
Create Date: 2026-03-23
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent.database.legacy_transform import migrate_documents_to_relational  # noqa: E402


def upgrade() -> None:
    bind = op.get_bind()
    migrate_documents_to_relational(bind)


def downgrade() -> None:
    pass
