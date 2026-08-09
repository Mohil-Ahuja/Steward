"""The policy decision point.

Given a principal, a target tool and the arguments of a proposed call, decide
whether it may proceed and under what duties. The ordering below is deliberate
and every branch defaults toward refusal:

1. **Catalogue check.** A tool Steward has never seen cannot be reasoned
   about, so it is refused. This is what makes a newly-appeared upstream tool
   safe by default rather than reachable by default.
2. **Integrity check.** A tool whose pinned description or schema hash has
   drifted is refused until re-approved -- the "rug pull", where a server
   ships a benign tool, waits for approval, then swaps in a malicious
   definition.
3. **Quarantine check.** A tool whose description was found to carry
   agent-directed instructions is refused outright.
4. **Policy matching**, with deny-override: a single matching deny beats any
   number of matching allows. Denial is not a vote.
5. **Risk ceiling.** An allow only grants up to the tier it declares, so a
   policy written for read tools cannot be stretched over a destructive one.
6. **Default deny.** No matching allow means no.

Every outcome carries a machine-readable ``reason_code``. The evaluation
harness groups its metrics by that code, which is what turns "the agent was
blocked" into "the agent was blocked *because the argument constraint held*"
-- a distinction that decides whether a block counts as a defence or an
over-refusal.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Policy, ToolDescriptor
from .conditions import ConditionError, evaluate_conditions
from .obligations import (
    ObligationError,
    Obligations,
    apply_clamp,
    merge_obligations,
    parse_obligations,
)
from .risk import RiskTier


class ReasonCode:
    """Stable identifiers for why a decision came out the way it did."""

    ALLOWED = "allowed"
    ALLOWED_WITH_OBLIGATIONS = "allowed_with_obligations"
    EXPLICIT_DENY = "explicit_deny"
    NO_MATCHING_ALLOW = "no_matching_allow"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_QUARANTINED = "tool_quarantined"
    TOOL_INTEGRITY_FAILED = "tool_integrity_failed"
    RISK_CEILING_EXCEEDED = "risk_ceiling_exceeded"
    MALFORMED_POLICY = "malformed_policy"

    #: Codes that represent a deliberate protective refusal rather than a
    #: simple absence of permission. The eval reports separate the two.
    PROTECTIVE = frozenset(
        {EXPLICIT_DENY, TOOL_QUARANTINED, TOOL_INTEGRITY_FAILED, RISK_CEILING_EXCEEDED}
    )


@dataclass
class PolicyMiss:
    """Why a policy that nearly applied did not, for operator diagnostics."""

    policy_id: str
    policy_name: str
    reason: str


@dataclass
class Decision:
    allowed: bool
    reason: str
    reason_code: str
    matched_policy_ids: list[str] = field(default_factory=list)
    obligations: Obligations = field(default_factory=Obligations)
    risk_tier: RiskTier | None = None
    #: Arguments after clamping. The proxy forwards these, not the originals.
    effective_arguments: dict[str, Any] = field(default_factory=dict)
    clamp_notes: list[str] = field(default_factory=list)
    near_misses: list[PolicyMiss] = field(default_factory=list)

    @property
    def obligation_names(self) -> list[str]:
        return self.obligations.names()

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "matched_policy_ids": list(self.matched_policy_ids),
            "obligations": self.obligation_names,
            "risk_tier": self.risk_tier.label if self.risk_tier else None,
            "clamp_notes": list(self.clamp_notes),
        }


@dataclass
class CallRequest:
    """A proposed tool call awaiting a decision."""

    subject: str
    server: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    #: Free-text justification, when a policy sets ``reason_required``.
    justification: str | None = None


def _aware(value: datetime | None) -> datetime | None:
    """Normalise to UTC-aware; SQLite round-trips datetimes as naive."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _time_valid(policy: Policy, now: datetime) -> tuple[bool, str]:
    not_before = _aware(policy.not_before)
    expires_at = _aware(policy.expires_at)
    if not_before and now < not_before:
        return False, f"not yet in force (starts {not_before.isoformat()})"
    if expires_at and expires_at <= now:
        return False, f"expired at {expires_at.isoformat()}"
    return True, ""


def _subject_matches(pattern: str, subject: str) -> bool:
    # Subjects support globbing so an operator can grant to a fleet
    # ("ingest-worker-*") without enumerating instances.
    return fnmatchcase(subject, pattern)


@dataclass
class _Candidate:
    policy: Policy
    obligations: Obligations


def _sort_key(policy: Policy) -> tuple[int, int, int]:
    """Order matched policies: priority first, then specificity."""
    # Column defaults only materialise on INSERT, so an unflushed Policy can
    # still carry None here; treat that as the default priority.
    text = f"{policy.subject}:{policy.server}:{policy.tool}"
    wildcards = text.count("*") + text.count("?")
    return (-(policy.priority or 0), wildcards, -len(text))


async def load_applicable_policies(
    session: AsyncSession, subject: str
) -> Sequence[Policy]:
    """Fetch active policies that could bind this subject.

    Narrowed in SQL to exact-subject and wildcard-bearing rows so the engine
    does not table-scan the whole policy store on every call; the precise glob
    test still runs in Python.
    """
    statement = select(Policy).where(Policy.active.is_(True))
    result = await session.execute(statement)
    return [
        policy
        for policy in result.scalars()
        if _subject_matches(policy.subject, subject)
    ]


async def get_tool_descriptor(
    session: AsyncSession, server: str, tool: str
) -> ToolDescriptor | None:
    result = await session.execute(
        select(ToolDescriptor).where(
            ToolDescriptor.server == server, ToolDescriptor.name == tool
        )
    )
    return result.scalar_one_or_none()


def evaluate_sync(
    request: CallRequest,
    policies: Iterable[Policy],
    *,
    descriptor: ToolDescriptor | None = None,
    require_known_tool: bool = True,
    enforce_integrity: bool = True,
    now: datetime | None = None,
) -> Decision:
    """Pure decision function -- no I/O, so it is trivially testable.

    Kept separate from the async database wrapper deliberately: the evaluation
    harness runs this millions of times across corpus variants, and it must not
    need a database to do so.
    """
    now = now or datetime.now(UTC)
    arguments = dict(request.arguments)

    # ---- 1-3: catalogue, integrity, quarantine ------------------------
    risk_tier: RiskTier | None = None
    if descriptor is not None:
        risk_tier = RiskTier.parse(descriptor.risk_tier, RiskTier.DESTRUCTIVE)

        if descriptor.quarantined:
            return Decision(
                allowed=False,
                reason=(
                    f"tool {request.server}:{request.tool} is quarantined: "
                    f"{descriptor.quarantine_reason or 'flagged by integrity scan'}"
                ),
                reason_code=ReasonCode.TOOL_QUARANTINED,
                risk_tier=risk_tier,
                effective_arguments=arguments,
            )

        if enforce_integrity and descriptor.pinned:
            from ..mcp.integrity import descriptor_matches_pin

            drift = descriptor_matches_pin(descriptor)
            if drift is not None:
                return Decision(
                    allowed=False,
                    reason=(
                        f"tool {request.server}:{request.tool} changed since it was "
                        f"pinned ({drift}); re-approve it before use"
                    ),
                    reason_code=ReasonCode.TOOL_INTEGRITY_FAILED,
                    risk_tier=risk_tier,
                    effective_arguments=arguments,
                )
    elif require_known_tool:
        return Decision(
            allowed=False,
            reason=(
                f"tool {request.server}:{request.tool} is not in the catalogue; "
                "unknown tools are refused"
            ),
            reason_code=ReasonCode.UNKNOWN_TOOL,
            effective_arguments=arguments,
        )

    # ---- 4: match policies --------------------------------------------
    denies: list[Policy] = []
    allows: list[_Candidate] = []
    near_misses: list[PolicyMiss] = []

    for policy in policies:
        if not _subject_matches(policy.subject, request.subject):
            continue

        valid, why = _time_valid(policy, now)
        if not valid:
            near_misses.append(PolicyMiss(policy.id, policy.name, why))
            continue

        if not fnmatchcase(request.server, policy.server):
            continue
        if not fnmatchcase(request.tool, policy.tool):
            continue

        try:
            outcome = evaluate_conditions(arguments, policy.conditions or {})
        except ConditionError as exc:
            # A policy the engine cannot understand is treated as a deny. A
            # broken allow must never become an unconstrained allow.
            return Decision(
                allowed=False,
                reason=f"policy {policy.name!r} is malformed: {exc}",
                reason_code=ReasonCode.MALFORMED_POLICY,
                matched_policy_ids=[policy.id],
                risk_tier=risk_tier,
                effective_arguments=arguments,
            )

        if not outcome.matched:
            near_misses.append(
                PolicyMiss(
                    policy.id,
                    policy.name,
                    "argument constraints unmet: " + "; ".join(outcome.failures),
                )
            )
            continue

        if policy.effect == "deny":
            denies.append(policy)
            continue

        # ---- 5: risk ceiling -------------------------------------------
        if policy.max_risk_tier and risk_tier is not None:
            try:
                ceiling = RiskTier.parse(policy.max_risk_tier)
            except ValueError as exc:
                return Decision(
                    allowed=False,
                    reason=f"policy {policy.name!r} has an invalid risk ceiling: {exc}",
                    reason_code=ReasonCode.MALFORMED_POLICY,
                    matched_policy_ids=[policy.id],
                    risk_tier=risk_tier,
                    effective_arguments=arguments,
                )
            if risk_tier > ceiling:
                near_misses.append(
                    PolicyMiss(
                        policy.id,
                        policy.name,
                        f"tool risk {risk_tier.label} exceeds policy ceiling "
                        f"{ceiling.label}",
                    )
                )
                continue

        try:
            obligations = parse_obligations(policy.obligations or {})
        except ObligationError as exc:
            return Decision(
                allowed=False,
                reason=f"policy {policy.name!r} has malformed obligations: {exc}",
                reason_code=ReasonCode.MALFORMED_POLICY,
                matched_policy_ids=[policy.id],
                risk_tier=risk_tier,
                effective_arguments=arguments,
            )

        allows.append(_Candidate(policy=policy, obligations=obligations))

    # ---- deny-override --------------------------------------------------
    if denies:
        ordered = sorted(denies, key=_sort_key)
        winner = ordered[0]
        return Decision(
            allowed=False,
            reason=f"denied by policy {winner.name!r}",
            reason_code=ReasonCode.EXPLICIT_DENY,
            matched_policy_ids=[policy.id for policy in ordered]
            + [candidate.policy.id for candidate in allows],
            risk_tier=risk_tier,
            effective_arguments=arguments,
            near_misses=near_misses,
        )

    # ---- 6: default deny ------------------------------------------------
    if not allows:
        detail = ""
        if near_misses:
            detail = "; nearest: " + near_misses[0].reason
        return Decision(
            allowed=False,
            reason=(
                f"no policy grants {request.subject!r} access to "
                f"{request.server}:{request.tool}{detail}"
            ),
            reason_code=ReasonCode.NO_MATCHING_ALLOW,
            risk_tier=risk_tier,
            effective_arguments=arguments,
            near_misses=near_misses,
        )

    ordered_allows = sorted(allows, key=lambda candidate: _sort_key(candidate.policy))
    obligations = merge_obligations([candidate.obligations for candidate in ordered_allows])
    effective_arguments, clamp_notes = apply_clamp(arguments, obligations.clamp)

    reason = f"allowed by policy {ordered_allows[0].policy.name!r}"
    if clamp_notes:
        reason += f" (clamped {', '.join(clamp_notes)})"

    return Decision(
        allowed=True,
        reason=reason,
        reason_code=(
            ReasonCode.ALLOWED_WITH_OBLIGATIONS
            if not obligations.is_empty()
            else ReasonCode.ALLOWED
        ),
        matched_policy_ids=[candidate.policy.id for candidate in ordered_allows],
        obligations=obligations,
        risk_tier=risk_tier,
        effective_arguments=effective_arguments,
        clamp_notes=clamp_notes,
        near_misses=near_misses,
    )


async def evaluate(
    session: AsyncSession,
    request: CallRequest,
    *,
    require_known_tool: bool | None = None,
    enforce_integrity: bool | None = None,
) -> Decision:
    """Database-backed wrapper around :func:`evaluate_sync`."""
    from ..config import get_settings

    settings = get_settings()
    policies = await load_applicable_policies(session, request.subject)
    descriptor = await get_tool_descriptor(session, request.server, request.tool)

    return evaluate_sync(
        request,
        policies,
        descriptor=descriptor,
        require_known_tool=(
            settings.require_known_tool if require_known_tool is None else require_known_tool
        ),
        enforce_integrity=(
            settings.enforce_tool_integrity if enforce_integrity is None else enforce_integrity
        ),
    )
