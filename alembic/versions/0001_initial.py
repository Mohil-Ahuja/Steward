"""Initial schema: policies, revisions, tool catalogue, audit chain, approvals, usage.

Revision ID: 0001
Revises:
Create Date: 2026-08-24
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("server", sa.String(300), nullable=False),
        sa.Column("tool", sa.String(300), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("obligations", sa.JSON(), nullable=False),
        sa.Column("max_risk_tier", sa.String(20), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_policies_subject", "policies", ["subject"])
    # The engine's hot path filters on (active, subject) for every decision.
    op.create_index("ix_policies_active_subject", "policies", ["active", "subject"])

    op.create_table(
        "policy_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("changed_by", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
    )
    op.create_index("ix_policy_revisions_policy_id", "policy_revisions", ["policy_id"])

    op.create_table(
        "tool_descriptors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("server", sa.String(300), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("title", sa.String(300), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("input_schema", sa.JSON(), nullable=False),
        sa.Column("output_schema", sa.JSON(), nullable=True),
        sa.Column("annotations", sa.JSON(), nullable=False),
        # Live hashes track upstream on every discovery.
        sa.Column("descriptor_hash", sa.String(64), nullable=False),
        sa.Column("description_hash", sa.String(64), nullable=False),
        sa.Column("schema_hash", sa.String(64), nullable=False),
        # Pinned hashes move only on explicit re-approval. Drift between the
        # two is the rug-pull signal.
        sa.Column("pinned_descriptor_hash", sa.String(64), nullable=True),
        sa.Column("pinned_description_hash", sa.String(64), nullable=True),
        sa.Column("pinned_schema_hash", sa.String(64), nullable=True),
        sa.Column("pinned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pinned_by", sa.String(200), nullable=True),
        sa.Column("risk_tier", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("risk_rationale", sa.JSON(), nullable=False),
        sa.Column("pinned", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("quarantined", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("server", "name", name="uq_tool_identity"),
    )
    op.create_index("ix_tool_descriptors_server", "tool_descriptors", ["server"])
    op.create_index("ix_tool_descriptors_descriptor_hash", "tool_descriptors", ["descriptor_hash"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        # Unique, gapless sequence: a hole in it is itself evidence.
        sa.Column("sequence", sa.Integer(), nullable=False, unique=True),
        sa.Column("correlation_id", sa.String(100), nullable=False),
        sa.Column("session_id", sa.String(100), nullable=True),
        sa.Column("principal", sa.String(200), nullable=False),
        sa.Column("server", sa.String(300), nullable=False),
        sa.Column("tool", sa.String(300), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.String(60), nullable=False, server_default="unspecified"),
        sa.Column("risk_tier", sa.String(20), nullable=True),
        sa.Column("matched_policy_ids", sa.JSON(), nullable=False),
        sa.Column("obligations_applied", sa.JSON(), nullable=False),
        sa.Column("downstream_status", sa.String(30), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_events_sequence", "audit_events", ["sequence"])
    op.create_index("ix_audit_events_correlation_id", "audit_events", ["correlation_id"])
    op.create_index("ix_audit_events_session_id", "audit_events", ["session_id"])
    op.create_index("ix_audit_events_principal", "audit_events", ["principal"])
    op.create_index("ix_audit_events_decision", "audit_events", ["decision"])
    op.create_index("ix_audit_events_reason_code", "audit_events", ["reason_code"])
    op.create_index("ix_audit_events_entry_hash", "audit_events", ["entry_hash"])
    op.create_index("ix_audit_principal_created", "audit_events", ["principal", "created_at"])

    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("correlation_id", sa.String(100), nullable=False),
        sa.Column("principal", sa.String(200), nullable=False),
        sa.Column("server", sa.String(300), nullable=False),
        sa.Column("tool", sa.String(300), nullable=False),
        # Stored so the approval can be bound to the exact arguments a human
        # saw; without this, approving a small refund authorises a large one.
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("risk_tier", sa.String(20), nullable=True),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("decided_by", sa.String(200), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_approval_requests_correlation_id", "approval_requests", ["correlation_id"])
    op.create_index("ix_approval_requests_principal", "approval_requests", ["principal"])
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])

    op.create_table(
        "usage_counters",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("principal", sa.String(200), nullable=False),
        sa.Column("counter_key", sa.String(400), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("amount", sa.Float(), nullable=False, server_default="0"),
        # Concurrent appends to the same window collide here rather than
        # silently double-spending a limit.
        sa.UniqueConstraint(
            "principal", "counter_key", "window_start", name="uq_usage_window"
        ),
    )
    op.create_index("ix_usage_counters_principal", "usage_counters", ["principal"])
    op.create_index("ix_usage_counters_counter_key", "usage_counters", ["counter_key"])
    op.create_index("ix_usage_counters_window_start", "usage_counters", ["window_start"])


def downgrade() -> None:
    op.drop_table("usage_counters")
    op.drop_table("approval_requests")
    op.drop_table("audit_events")
    op.drop_table("tool_descriptors")
    op.drop_table("policy_revisions")
    op.drop_table("policies")
