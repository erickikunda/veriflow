"""Runtime Joern profile drafts, executed fixture tests and approvals in their own tables."""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"


def upgrade():
    # Additive only: rebuilding rule_drafts would break rule_approvals foreign keys on SQLite.
    op.create_table(
        "profile_drafts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
    )
    op.create_table(
        "profile_tests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("draft_id", sa.String(64), sa.ForeignKey("profile_drafts.id"), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
    )
    op.create_index("ix_profile_tests_draft_id", "profile_tests", ["draft_id"])
    # A draft may be approved again after it was disabled, so draft_id is not unique here.
    op.create_table(
        "profile_approvals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("draft_id", sa.String(64), sa.ForeignKey("profile_drafts.id"), nullable=False),
        sa.Column(
            "registry_id", sa.String(64), sa.ForeignKey("rule_registries.id"), nullable=False
        ),
        sa.Column("request_key", sa.String(200), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
    )
    op.create_index("ix_profile_approvals_draft_id", "profile_approvals", ["draft_id"])


def downgrade():
    op.drop_table("profile_approvals")
    op.drop_table("profile_tests")
    op.drop_table("profile_drafts")
