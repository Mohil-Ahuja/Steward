"""Audit subsystem: redaction plus a tamper-evident hash chain."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditEvent
from .chain import (
    GENESIS_HASH,
    ChainBreak,
    ChainReport,
    append_event,
    checkpoint,
    compute_entry_hash,
    verify_chain,
    verify_events,
)
from .redaction import REDACTED, redact, redact_text

__all__ = [
    "ChainBreak",
    "ChainReport",
    "GENESIS_HASH",
    "REDACTED",
    "append_event",
    "checkpoint",
    "compute_entry_hash",
    "record",
    "redact",
    "redact_text",
    "verify_chain",
    "verify_events",
]


async def record(
    session: AsyncSession,
    *,
    principal: str,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    decision: str,
    reason: str,
    reason_code: str = "unspecified",
    policy_ids: Sequence[str] = (),
    obligations_applied: Sequence[str] = (),
    risk_tier: str | None = None,
    correlation_id: str | None = None,
    session_id: str | None = None,
    downstream_status: str | None = None,
    latency_ms: int | None = None,
    redact_paths: frozenset[str] | None = None,
) -> AuditEvent:
    """Redact, then append to the chain.

    Redaction happens here rather than at the call site so that no code path
    can write an audit row without passing through it.
    """
    from ..config import get_settings

    settings = get_settings()
    safe_arguments = redact(
        arguments,
        settings.redaction_keys,
        scan_values=settings.audit_redact_value_patterns,
        extra_paths=redact_paths,
    )

    return await append_event(
        session,
        correlation_id=correlation_id or str(uuid.uuid4()),
        session_id=session_id,
        principal=principal,
        server=server,
        tool=tool,
        arguments=safe_arguments,
        decision=decision,
        reason=reason,
        reason_code=reason_code,
        matched_policy_ids=list(policy_ids),
        obligations_applied=list(obligations_applied),
        risk_tier=risk_tier,
        downstream_status=downstream_status,
        latency_ms=latency_ms,
    )
