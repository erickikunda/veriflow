"""Durable replay-first LLM discovery request provenance."""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"


def upgrade():
    op.create_table(
        "discovery_calls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("attempt_id", sa.String(36), sa.ForeignKey("scan_attempts.id"), nullable=False),
        sa.Column("request_key", sa.String(200), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("charged_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "request_key"),
    )
    op.create_index("ix_discovery_calls_run_id", "discovery_calls", ["run_id"])
    op.create_index("ix_discovery_calls_attempt_id", "discovery_calls", ["attempt_id"])


def downgrade():
    op.drop_table("discovery_calls")
