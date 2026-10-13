"""Governed rule drafts, approvals and immutable registry versions."""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"


def upgrade():
    op.create_table(
        "rule_drafts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("candidate_id", sa.String(36), sa.ForeignKey("candidates.id"), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
    )
    op.create_index("ix_rule_drafts_candidate_id", "rule_drafts", ["candidate_id"])
    op.create_table(
        "rule_registries",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
    )
    op.create_table(
        "rule_approvals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("draft_id", sa.String(64), sa.ForeignKey("rule_drafts.id"), nullable=False),
        sa.Column(
            "registry_id", sa.String(64), sa.ForeignKey("rule_registries.id"), nullable=False
        ),
        sa.Column("request_key", sa.String(200), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.UniqueConstraint("draft_id"),
    )
    op.create_index("ix_rule_approvals_draft_id", "rule_approvals", ["draft_id"])


def downgrade():
    op.drop_table("rule_approvals")
    op.drop_table("rule_registries")
    op.drop_table("rule_drafts")
