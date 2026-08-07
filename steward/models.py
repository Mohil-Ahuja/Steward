"""SQLAlchemy models for the policy store, tool catalogue and audit chain."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Policy(Base):
    """A single grant or prohibition.

    A policy is keyed on (subject, server, tool) patterns plus optional
    argument ``conditions``. Matching policies are combined by the engine using
    deny-override semantics with a numeric ``priority`` tiebreak.
    """

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    version: Mapped[int] = mapped_column(Integer, default=1)
    effect: Mapped[str] = mapped_column(String(10))  # allow | deny

    subject: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str] = mapped_column(String(300))
    tool: Mapped[str] = mapped_column(String(300))

    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    # Obligations attach *requirements* to an allow decision: redaction,
    # human approval, rate limits, budget ceilings, argument clamping.
    obligations: Mapped[dict] = mapped_column(JSON, default=dict)

    # Highest-risk tier this policy is willing to authorise. A policy that
    # matches a tool above its ceiling does not grant.
    max_risk_tier: Mapped[str | None] = mapped_column(String(20), nullable=True)

    priority: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_policies_active_subject", "active", "subject"),)


class PolicyRevision(Base):
    """Immutable snapshot of a policy at each version, enabling rollback."""

    __tablename__ = "policy_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    change_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class ToolDescriptor(Base):
    """Pinned view of an upstream MCP tool.

    Steward records the hash of every tool's description and input schema the
    first time it is seen. If an upstream server later mutates a tool
    definition -- the "rug pull" / tool-poisoning class of MCP attack -- the
    hash no longer matches the pin and calls are refused until re-approved.
    """

    __tablename__ = "tool_descriptors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server: Mapped[str] = mapped_column(String(300), index=True)
    name: Mapped[str] = mapped_column(String(300))

    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    output_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # MCP tool annotations (readOnlyHint / destructiveHint / ...). Untrusted.
    annotations: Mapped[dict] = mapped_column(JSON, default=dict)

    # Hashes of the definition as it stands upstream right now.
    descriptor_hash: Mapped[str] = mapped_column(String(64), index=True)
    description_hash: Mapped[str] = mapped_column(String(64))
    schema_hash: Mapped[str] = mapped_column(String(64))

    # Hashes captured at the moment an operator approved the tool. Drift
    # between these and the live hashes above is the rug-pull signal; keeping
    # both means we can say *which* half of the definition changed.
    pinned_descriptor_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pinned_description_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pinned_schema_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pinned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pinned_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    risk_tier: Mapped[str] = mapped_column(String(20), default="unknown")
    risk_rationale: Mapped[list] = mapped_column(JSON, default=list)

    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("server", "name", name="uq_tool_identity"),)


class AuditEvent(Base):
    """Append-only, hash-chained record of every authorization decision.

    ``prev_hash`` links each row to its predecessor and ``entry_hash`` is an
    HMAC over the canonical payload, so any edit, deletion or reordering of
    history is detectable by :func:`steward.audit.chain.verify_chain`.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    sequence: Mapped[int] = mapped_column(Integer, index=True, unique=True)

    correlation_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str | None] = mapped_column(String(100), index=True, nullable=True)

    principal: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str] = mapped_column(String(300))
    tool: Mapped[str] = mapped_column(String(300))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)

    decision: Mapped[str] = mapped_column(String(20), index=True)  # allowed|denied|error
    reason: Mapped[str] = mapped_column(Text)
    reason_code: Mapped[str] = mapped_column(String(60), default="unspecified", index=True)
    risk_tier: Mapped[str | None] = mapped_column(String(20), nullable=True)

    matched_policy_ids: Mapped[list] = mapped_column(JSON, default=list)
    obligations_applied: Mapped[list] = mapped_column(JSON, default=list)

    downstream_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_audit_principal_created", "principal", "created_at"),)


class ApprovalRequest(Base):
    """A pending human-in-the-loop decision raised by a ``require_approval``
    obligation. Surfaced to the agent as an MCP ``input_required`` result."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    correlation_id: Mapped[str] = mapped_column(String(100), index=True)
    principal: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str] = mapped_column(String(300))
    tool: Mapped[str] = mapped_column(String(300))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_tier: Mapped[str | None] = mapped_column(String(20), nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageCounter(Base):
    """Sliding-window consumption ledger backing rate-limit and budget
    obligations. One row per (principal, scope key, window start)."""

    __tablename__ = "usage_counters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    principal: Mapped[str] = mapped_column(String(200), index=True)
    counter_key: Mapped[str] = mapped_column(String(400), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer, default=0)
    amount: Mapped[float] = mapped_column(Float, default=0.0)

    __table_args__ = (
        UniqueConstraint("principal", "counter_key", "window_start", name="uq_usage_window"),
    )
