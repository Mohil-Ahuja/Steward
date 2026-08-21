"""Turning a session of audit events into a feature vector.

The unit of analysis is a *session*, not a call. That choice is the whole
point: every individual call in an enumeration attack is authorised, so any
representation that looks at one call at a time cannot separate the classes no
matter what model sits on top of it.

Features are grouped by the behaviour they are meant to expose:

*Volume and pace* -- how much, how fast. Automation looks different from work.

*Diversity* -- Shannon entropy over the tool distribution, and the ratio of
distinct arguments to calls. A session that hammers one tool with many
different ids is enumerating; one that uses many tools with few repeats is
doing a task.

*Friction* -- the share of calls that were denied. A high denial rate means
something is probing for what it can reach, which is informative regardless of
whether any probe succeeded.

*Risk profile* -- how far up the risk scale the session reached.

Every feature is deliberately cheap and interpretable. They are computed from
the audit log Steward already writes, so the detector needs no extra telemetry
and can be backfilled over history.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from ..policy.risk import RiskTier

FEATURE_NAMES: list[str] = [
    "n_calls",
    "log_duration_s",
    "calls_per_minute",
    "n_distinct_tools",
    "tool_entropy",
    "top_tool_share",
    "distinct_arg_ratio",
    "max_repeat_run",
    "denied_share",
    "distinct_reason_codes",
    "max_risk_tier",
    "mean_risk_tier",
    "write_share",
    "injection_flag_share",
    "distinct_servers",
    "mean_latency_ms",
]


@dataclass
class SessionEvent:
    """One audited call, in the shape the featuriser needs."""

    tool: str
    server: str
    decision: str
    timestamp: datetime
    arguments: dict[str, Any] = field(default_factory=dict)
    reason_code: str = "allowed"
    risk_tier: str | None = None
    latency_ms: int | None = None
    injection_flagged: bool = False


def _entropy(counts: Sequence[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _max_repeat_run(tools: Sequence[str]) -> int:
    """Longest run of consecutive calls to the same tool."""
    longest = current = 0
    previous: str | None = None
    for tool in tools:
        current = current + 1 if tool == previous else 1
        longest = max(longest, current)
        previous = tool
    return longest


def _identifier_values(arguments: dict[str, Any]) -> tuple[Any, ...]:
    """Argument values that look like they name a specific resource.

    Enumeration is characterised by many distinct *identifiers* against one
    tool, so the ratio is computed over id-shaped arguments rather than over
    all arguments -- otherwise a varying free-text ``message`` looks the same
    as a walk through a customer table.
    """
    interesting: list[Any] = []
    for key, value in sorted(arguments.items()):
        lowered = str(key).lower()
        if lowered.endswith(("_id", "id", "key", "path", "invoice", "contact")):
            interesting.append(value)
    return tuple(interesting)


def extract_features(events: Sequence[SessionEvent]) -> np.ndarray:
    """Featurise one session. Returns a vector aligned with FEATURE_NAMES."""
    if not events:
        return np.zeros(len(FEATURE_NAMES))

    ordered = sorted(events, key=lambda event: event.timestamp)
    n_calls = len(ordered)

    span = (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()
    duration = max(span, 1e-3)

    tools = [event.tool for event in ordered]
    tool_counts = Counter(tools)
    identifiers = {_identifier_values(event.arguments) for event in ordered}

    denied = sum(1 for event in ordered if event.decision != "allowed")
    reason_codes = {event.reason_code for event in ordered}

    tiers: list[int] = []
    for event in ordered:
        try:
            tiers.append(int(RiskTier.parse(event.risk_tier, RiskTier.READ)))
        except ValueError:
            tiers.append(int(RiskTier.READ))

    writes = sum(1 for tier in tiers if tier >= int(RiskTier.WRITE))
    flagged = sum(1 for event in ordered if event.injection_flagged)
    latencies = [event.latency_ms for event in ordered if event.latency_ms is not None]

    return np.array(
        [
            float(n_calls),
            math.log1p(duration),
            n_calls / (duration / 60.0),
            float(len(tool_counts)),
            _entropy(list(tool_counts.values())),
            max(tool_counts.values()) / n_calls,
            len(identifiers) / n_calls,
            float(_max_repeat_run(tools)),
            denied / n_calls,
            float(len(reason_codes)),
            float(max(tiers)),
            float(sum(tiers) / n_calls),
            writes / n_calls,
            flagged / n_calls,
            float(len({event.server for event in ordered})),
            float(sum(latencies) / len(latencies)) if latencies else 0.0,
        ],
        dtype=float,
    )


def feature_matrix(sessions: Sequence[Sequence[SessionEvent]]) -> np.ndarray:
    if not sessions:
        return np.zeros((0, len(FEATURE_NAMES)))
    return np.vstack([extract_features(session) for session in sessions])


def explain(vector: np.ndarray, weights: np.ndarray, top_k: int = 5) -> list[dict[str, Any]]:
    """The features that pushed one session's score, largest first.

    An alert an analyst cannot interrogate gets ignored, so the detector ships
    its reasoning alongside its score.
    """
    contributions = vector * weights
    order = np.argsort(-np.abs(contributions))[:top_k]
    return [
        {
            "feature": FEATURE_NAMES[index],
            "value": float(vector[index]),
            "weight": float(weights[index]),
            "contribution": float(contributions[index]),
        }
        for index in order
    ]


async def sessions_from_audit(session_factory: Any, *, limit: int = 10_000) -> dict[str, list[SessionEvent]]:
    """Rebuild sessions from persisted audit events.

    This is the production path: the detector consumes exactly the log Steward
    already writes, so it can be trained on real traffic without adding any new
    instrumentation.
    """
    from sqlalchemy import select

    from ..models import AuditEvent

    grouped: dict[str, list[SessionEvent]] = {}
    async with session_factory() as db:
        rows = (
            await db.execute(
                select(AuditEvent).order_by(AuditEvent.sequence).limit(limit)
            )
        ).scalars()

        for row in rows:
            key = row.session_id or row.correlation_id
            grouped.setdefault(key, []).append(
                SessionEvent(
                    tool=row.tool,
                    server=row.server,
                    decision=row.decision,
                    timestamp=row.created_at,
                    arguments=row.arguments or {},
                    reason_code=row.reason_code,
                    risk_tier=row.risk_tier,
                    latency_ms=row.latency_ms,
                    injection_flagged=any(
                        str(item).startswith("injection_detected")
                        for item in (row.obligations_applied or [])
                    ),
                )
            )
    return grouped
