"""Tamper-evident audit log.

An audit trail is only evidence if altering it is detectable. A plain table is
not: anyone with database access can update a row, delete an inconvenient
denial, or reorder history, and nothing about the result looks wrong.

Every event here is therefore linked into a hash chain. Each row stores the
hash of its predecessor and an HMAC over its own canonical payload *including*
that predecessor hash. Three properties follow:

* **Modification** changes the row's own hash, so it stops matching what its
  successor recorded as ``prev_hash``.
* **Deletion** removes a link, so the chain no longer joins up.
* **Reordering** breaks the sequence-to-hash correspondence.

Because the digest is an HMAC rather than a bare SHA-256, an attacker who can
write to the database still cannot forge a valid replacement chain without the
key -- which is why ``STEWARD_AUDIT_CHAIN_KEY`` belongs in a secret manager and
not in the same database as the log.

The chain proves *internal* consistency. It cannot prove that a segment was
never wholesale replaced, so :func:`checkpoint` emits a head digest intended to
be published somewhere the database operator does not control (an append-only
store, a log-shipping sink, or simply an operator's inbox).
"""

from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..canonical import canonical_json
from ..models import AuditEvent

#: Hash recorded as the predecessor of the very first event.
GENESIS_HASH = "0" * 64

_PROCESS_KEY: str | None = None


def _chain_key() -> bytes:
    """Resolve the HMAC key, generating an ephemeral one if unconfigured.

    A generated key still detects accidental corruption and casual editing
    within a single process lifetime, but it cannot survive a restart, so
    production configuration is checked elsewhere and warned about loudly.
    """
    global _PROCESS_KEY
    from ..config import get_settings

    configured = get_settings().audit_chain_key
    if configured:
        return configured.encode("utf-8")

    if _PROCESS_KEY is None:
        _PROCESS_KEY = os.environ.get("STEWARD_EPHEMERAL_CHAIN_KEY") or secrets.token_hex(32)
    return _PROCESS_KEY.encode("utf-8")


def canonical_payload(
    *,
    sequence: int,
    correlation_id: str,
    principal: str,
    server: str,
    tool: str,
    arguments: Any,
    decision: str,
    reason_code: str,
    matched_policy_ids: Sequence[str],
    downstream_status: str | None,
    prev_hash: str,
    created_at: str,
) -> str:
    """The exact bytes the HMAC covers.

    Only fields that a tamperer would want to change are included, and they are
    serialised canonically so an equivalent record always hashes identically.
    """
    return canonical_json(
        {
            "sequence": sequence,
            "correlation_id": correlation_id,
            "principal": principal,
            "server": server,
            "tool": tool,
            "arguments": arguments,
            "decision": decision,
            "reason_code": reason_code,
            "matched_policy_ids": list(matched_policy_ids),
            "downstream_status": downstream_status,
            "prev_hash": prev_hash,
            "created_at": created_at,
        }
    )


def compute_entry_hash(payload: str, key: bytes | None = None) -> str:
    return hmac.new(key or _chain_key(), payload.encode("utf-8"), sha256).hexdigest()


def event_payload(event: AuditEvent) -> str:
    """Rebuild the canonical payload for a stored row, for verification."""
    created = event.created_at
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return canonical_payload(
        sequence=event.sequence,
        correlation_id=event.correlation_id,
        principal=event.principal,
        server=event.server,
        tool=event.tool,
        arguments=event.arguments,
        decision=event.decision,
        reason_code=event.reason_code,
        matched_policy_ids=event.matched_policy_ids or [],
        downstream_status=event.downstream_status,
        prev_hash=event.prev_hash,
        created_at=created.isoformat() if created else "",
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class ChainBreak:
    sequence: int
    event_id: str
    kind: str  # gap | link_mismatch | hash_mismatch
    detail: str


@dataclass
class ChainReport:
    events_checked: int = 0
    breaks: list[ChainBreak] = field(default_factory=list)
    head_hash: str = GENESIS_HASH
    head_sequence: int = 0

    @property
    def intact(self) -> bool:
        return not self.breaks

    def to_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "events_checked": self.events_checked,
            "head_sequence": self.head_sequence,
            "head_hash": self.head_hash,
            "breaks": [
                {
                    "sequence": item.sequence,
                    "event_id": item.event_id,
                    "kind": item.kind,
                    "detail": item.detail,
                }
                for item in self.breaks
            ],
        }


def verify_events(events: Sequence[AuditEvent], key: bytes | None = None) -> ChainReport:
    """Walk an ordered run of events and report every inconsistency.

    Verification continues past a break rather than stopping at the first one,
    because "the log was edited at sequence 41" is far less useful to an
    incident responder than the full list of everything that moved.
    """
    report = ChainReport()
    expected_prev = GENESIS_HASH
    expected_sequence: int | None = None

    for event in events:
        report.events_checked += 1

        if expected_sequence is not None and event.sequence != expected_sequence:
            report.breaks.append(
                ChainBreak(
                    sequence=event.sequence,
                    event_id=event.id,
                    kind="gap",
                    detail=(
                        f"expected sequence {expected_sequence}, found {event.sequence}: "
                        f"{event.sequence - expected_sequence} event(s) missing"
                    ),
                )
            )

        if event.prev_hash != expected_prev:
            report.breaks.append(
                ChainBreak(
                    sequence=event.sequence,
                    event_id=event.id,
                    kind="link_mismatch",
                    detail=(
                        "prev_hash does not match the preceding event's hash; "
                        "history was reordered or an event was removed"
                    ),
                )
            )

        recomputed = compute_entry_hash(event_payload(event), key)
        if recomputed != event.entry_hash:
            report.breaks.append(
                ChainBreak(
                    sequence=event.sequence,
                    event_id=event.id,
                    kind="hash_mismatch",
                    detail="stored hash does not match the record's contents; the row was edited",
                )
            )

        # Chain forward on what is stored, so one bad row does not cascade a
        # link_mismatch onto every subsequent event.
        expected_prev = event.entry_hash
        expected_sequence = event.sequence + 1
        report.head_hash = event.entry_hash
        report.head_sequence = event.sequence

    return report


async def verify_chain(session: AsyncSession, key: bytes | None = None) -> ChainReport:
    """Verify the persisted chain.

    ``populate_existing`` is essential rather than cosmetic: without it the
    session's identity map would hand back cached objects loaded *before* a
    tamper, and the verifier would cheerfully declare an edited log intact. A
    verification routine must read what is actually stored, never a cache of
    what was once stored.
    """
    statement = (
        select(AuditEvent)
        .order_by(AuditEvent.sequence)
        .execution_options(populate_existing=True)
    )
    result = await session.execute(statement)
    return verify_events(list(result.scalars()), key)


async def checkpoint(session: AsyncSession) -> dict[str, Any]:
    """Head-of-chain digest, for publishing outside the database.

    Anchoring this externally is what upgrades the guarantee from "nobody
    edited the log" to "nobody replaced the log", since a wholesale
    substitution produces a head hash that will not match the anchor.
    """
    report = await verify_chain(session)
    return {
        "head_sequence": report.head_sequence,
        "head_hash": report.head_hash,
        "intact": report.intact,
        "checkpointed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Appending
# ---------------------------------------------------------------------------


async def _chain_head(session: AsyncSession) -> tuple[int, str]:
    """Current (sequence, hash) at the tip of the chain."""
    result = await session.execute(select(func.max(AuditEvent.sequence)))
    max_sequence = result.scalar()
    if max_sequence is None:
        return 0, GENESIS_HASH

    tail = await session.execute(
        select(AuditEvent).where(AuditEvent.sequence == max_sequence)
    )
    event = tail.scalar_one()
    return int(max_sequence), event.entry_hash


async def append_event(
    session: AsyncSession,
    *,
    correlation_id: str,
    principal: str,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    decision: str,
    reason: str,
    reason_code: str,
    matched_policy_ids: Sequence[str] = (),
    obligations_applied: Sequence[str] = (),
    risk_tier: str | None = None,
    downstream_status: str | None = None,
    latency_ms: int | None = None,
    session_id: str | None = None,
    created_at: datetime | None = None,
) -> AuditEvent:
    """Append one event, linking it to the current chain head.

    Sequence allocation reads the current maximum and writes the next value
    under a unique constraint, so two concurrent appends cannot silently share
    a sequence number -- one of them fails and retries. That is adequate for a
    single-writer deployment and honest about its limits: a horizontally scaled
    Steward should serialise appends through one writer or move the chain to a
    dedicated append-only sink.
    """
    max_sequence, prev_hash = await _chain_head(session)
    sequence = max_sequence + 1
    timestamp = created_at or datetime.now(UTC)

    payload = canonical_payload(
        sequence=sequence,
        correlation_id=correlation_id,
        principal=principal,
        server=server,
        tool=tool,
        arguments=arguments,
        decision=decision,
        reason_code=reason_code,
        matched_policy_ids=matched_policy_ids,
        downstream_status=downstream_status,
        prev_hash=prev_hash,
        created_at=timestamp.isoformat(),
    )

    event = AuditEvent(
        sequence=sequence,
        correlation_id=correlation_id,
        session_id=session_id,
        principal=principal,
        server=server,
        tool=tool,
        arguments=arguments,
        decision=decision,
        reason=reason,
        reason_code=reason_code,
        risk_tier=risk_tier,
        matched_policy_ids=list(matched_policy_ids),
        obligations_applied=list(obligations_applied),
        downstream_status=downstream_status,
        latency_ms=latency_ms,
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(payload),
        created_at=timestamp,
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)
    return event
