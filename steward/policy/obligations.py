"""Obligations: requirements attached to an *allow* decision.

Real authorization is rarely a bare yes. "Yes, but redact the customer's email
from the audit record", "yes, but no more than 10 times an hour", "yes, but a
human signs off above $500", "yes, but strip instructions out of whatever the
tool returns". Each of those is an obligation -- a duty the enforcement point
must discharge before, during, or after the call. A decision whose obligations
cannot be discharged is not an allow.

**Combining rule.** When several allow policies match the same call, their
obligations are *unioned* and numeric limits are reduced to the strictest
value. This follows XACML's treatment of obligations on permit rules, and it is
the only safe direction: if adding a second, broader grant could relax a limit
imposed by the first, an author could weaken a control by accident simply by
writing another policy. Obligations only ever tighten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .risk import RiskTier


class ObligationError(ValueError):
    """Raised for a malformed obligation block."""


SUPPORTED_OBLIGATIONS = {
    "redact_arguments",
    "redact_results",
    "require_approval",
    "rate_limit",
    "budget",
    "clamp",
    "max_result_bytes",
    "sanitize_results",
    "reason_required",
}


@dataclass(frozen=True)
class RateLimit:
    """At most ``calls`` invocations per ``per_seconds`` sliding window."""

    calls: int
    per_seconds: int
    # What the window is keyed on: "tool" (default), "server", or "principal".
    scope: str = "tool"

    def key_for(self, server: str, tool: str) -> str:
        if self.scope == "principal":
            return "*"
        if self.scope == "server":
            return server
        return f"{server}:{tool}"

    def stricter_than(self, other: RateLimit) -> bool:
        # Compare as a rate; fewer calls per second is stricter.
        return (self.calls / self.per_seconds) < (other.calls / other.per_seconds)


@dataclass(frozen=True)
class Budget:
    """Cap the summed value of a numeric argument over a window.

    A per-call ``amount <= 100`` bound does not stop an agent issuing two
    hundred refunds of 100 each. A budget does.
    """

    field_path: str
    max_total: float
    per_seconds: int
    scope: str = "tool"

    def key_for(self, server: str, tool: str) -> str:
        if self.scope == "principal":
            return f"budget:{self.field_path}"
        if self.scope == "server":
            return f"budget:{server}:{self.field_path}"
        return f"budget:{server}:{tool}:{self.field_path}"


@dataclass(frozen=True)
class ApprovalRule:
    """When a human must sign off before the call proceeds."""

    # Approval is required when the tool's tier is at or above this bound.
    above_tier: RiskTier = RiskTier.SENSITIVE
    always: bool = False
    prompt: str | None = None

    def applies_to(self, tier: RiskTier) -> bool:
        return self.always or tier >= self.above_tier


@dataclass(frozen=True)
class Obligations:
    """The combined duties attached to an allow decision."""

    redact_arguments: frozenset[str] = frozenset()
    redact_results: frozenset[str] = frozenset()
    require_approval: ApprovalRule | None = None
    rate_limit: RateLimit | None = None
    budget: Budget | None = None
    clamp: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_result_bytes: int | None = None
    sanitize_results: bool = False
    reason_required: bool = False

    def is_empty(self) -> bool:
        return not any(
            [
                self.redact_arguments,
                self.redact_results,
                self.require_approval,
                self.rate_limit,
                self.budget,
                self.clamp,
                self.max_result_bytes,
                self.sanitize_results,
                self.reason_required,
            ]
        )

    def names(self) -> list[str]:
        """Short labels for the audit record."""
        applied: list[str] = []
        if self.redact_arguments:
            applied.append("redact_arguments")
        if self.redact_results:
            applied.append("redact_results")
        if self.require_approval:
            applied.append("require_approval")
        if self.rate_limit:
            applied.append("rate_limit")
        if self.budget:
            applied.append("budget")
        if self.clamp:
            applied.append("clamp")
        if self.max_result_bytes:
            applied.append("max_result_bytes")
        if self.sanitize_results:
            applied.append("sanitize_results")
        if self.reason_required:
            applied.append("reason_required")
        return applied


def _as_str_set(value: Any, name: str) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, (list, tuple, set)):
        return frozenset(str(item) for item in value)
    raise ObligationError(f"{name!r} expects a string or list of strings")


def _as_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ObligationError(f"{name!r} expects a positive number")
    number = int(value)
    if number <= 0:
        raise ObligationError(f"{name!r} must be greater than zero")
    return number


def parse_obligations(raw: dict[str, Any] | None) -> Obligations:
    """Build an :class:`Obligations` from a policy's JSON block."""
    if not raw:
        return Obligations()
    if not isinstance(raw, dict):
        raise ObligationError("obligations must be an object")

    unknown = sorted(set(raw) - SUPPORTED_OBLIGATIONS)
    if unknown:
        raise ObligationError(
            f"unknown obligation(s) {unknown}; supported: {sorted(SUPPORTED_OBLIGATIONS)}"
        )

    redact_arguments = (
        _as_str_set(raw["redact_arguments"], "redact_arguments")
        if "redact_arguments" in raw
        else frozenset()
    )
    redact_results = (
        _as_str_set(raw["redact_results"], "redact_results")
        if "redact_results" in raw
        else frozenset()
    )

    approval: ApprovalRule | None = None
    if "require_approval" in raw:
        spec = raw["require_approval"]
        if spec is True:
            approval = ApprovalRule(always=True)
        elif isinstance(spec, dict):
            approval = ApprovalRule(
                above_tier=RiskTier.parse(spec.get("above_tier"), RiskTier.SENSITIVE),
                always=bool(spec.get("always", False)),
                prompt=spec.get("prompt"),
            )
        elif spec not in (False, None):
            raise ObligationError("'require_approval' expects true or an object")

    rate_limit: RateLimit | None = None
    if "rate_limit" in raw:
        spec = raw["rate_limit"]
        if not isinstance(spec, dict):
            raise ObligationError("'rate_limit' expects an object")
        scope = str(spec.get("scope", "tool"))
        if scope not in {"tool", "server", "principal"}:
            raise ObligationError("rate_limit scope must be tool, server or principal")
        rate_limit = RateLimit(
            calls=_as_positive_int(spec.get("calls"), "rate_limit.calls"),
            per_seconds=_as_positive_int(spec.get("per_seconds"), "rate_limit.per_seconds"),
            scope=scope,
        )

    budget: Budget | None = None
    if "budget" in raw:
        spec = raw["budget"]
        if not isinstance(spec, dict):
            raise ObligationError("'budget' expects an object")
        field_path = spec.get("field")
        if not isinstance(field_path, str) or not field_path:
            raise ObligationError("'budget.field' must name the numeric argument to sum")
        max_total = spec.get("max_total")
        if isinstance(max_total, bool) or not isinstance(max_total, (int, float)):
            raise ObligationError("'budget.max_total' expects a number")
        scope = str(spec.get("scope", "tool"))
        if scope not in {"tool", "server", "principal"}:
            raise ObligationError("budget scope must be tool, server or principal")
        budget = Budget(
            field_path=field_path,
            max_total=float(max_total),
            per_seconds=_as_positive_int(spec.get("per_seconds"), "budget.per_seconds"),
            scope=scope,
        )

    clamp = raw.get("clamp") or {}
    if clamp and not isinstance(clamp, dict):
        raise ObligationError("'clamp' expects an object mapping argument -> bounds")
    for key, bounds in clamp.items():
        if not isinstance(bounds, dict) or not ({"max", "min"} & set(bounds)):
            raise ObligationError(f"clamp[{key!r}] expects a 'min' and/or 'max' bound")

    max_result_bytes = (
        _as_positive_int(raw["max_result_bytes"], "max_result_bytes")
        if "max_result_bytes" in raw
        else None
    )

    return Obligations(
        redact_arguments=redact_arguments,
        redact_results=redact_results,
        require_approval=approval,
        rate_limit=rate_limit,
        budget=budget,
        clamp=dict(clamp),
        max_result_bytes=max_result_bytes,
        sanitize_results=bool(raw.get("sanitize_results", False)),
        reason_required=bool(raw.get("reason_required", False)),
    )


def merge_obligations(items: list[Obligations]) -> Obligations:
    """Combine obligations from every matching allow policy, strictest wins."""
    if not items:
        return Obligations()
    if len(items) == 1:
        return items[0]

    redact_arguments: frozenset[str] = frozenset()
    redact_results: frozenset[str] = frozenset()
    approval: ApprovalRule | None = None
    rate_limit: RateLimit | None = None
    budget: Budget | None = None
    clamp: dict[str, dict[str, Any]] = {}
    max_result_bytes: int | None = None
    sanitize = False
    reason_required = False

    for item in items:
        redact_arguments |= item.redact_arguments
        redact_results |= item.redact_results
        sanitize = sanitize or item.sanitize_results
        reason_required = reason_required or item.reason_required

        if item.require_approval:
            if approval is None:
                approval = item.require_approval
            else:
                # Stricter = triggers more often: always wins, else lower bound.
                approval = ApprovalRule(
                    above_tier=min(approval.above_tier, item.require_approval.above_tier),
                    always=approval.always or item.require_approval.always,
                    prompt=approval.prompt or item.require_approval.prompt,
                )

        if item.rate_limit and (
            rate_limit is None or item.rate_limit.stricter_than(rate_limit)
        ):
            rate_limit = item.rate_limit

        if item.budget and (budget is None or item.budget.max_total < budget.max_total):
            budget = item.budget

        for key, bounds in item.clamp.items():
            existing = clamp.setdefault(key, {})
            if "max" in bounds:
                existing["max"] = min(existing.get("max", bounds["max"]), bounds["max"])
            if "min" in bounds:
                existing["min"] = max(existing.get("min", bounds["min"]), bounds["min"])

        if item.max_result_bytes is not None:
            max_result_bytes = (
                item.max_result_bytes
                if max_result_bytes is None
                else min(max_result_bytes, item.max_result_bytes)
            )

    return Obligations(
        redact_arguments=redact_arguments,
        redact_results=redact_results,
        require_approval=approval,
        rate_limit=rate_limit,
        budget=budget,
        clamp=clamp,
        max_result_bytes=max_result_bytes,
        sanitize_results=sanitize,
        reason_required=reason_required,
    )


def apply_clamp(arguments: dict[str, Any], clamp: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Rewrite out-of-range arguments to their bound instead of denying.

    Clamping trades a hard failure for a quieter, still-safe outcome: an agent
    asking for 10,000 rows under a 100-row ceiling gets 100 rows rather than an
    error it will simply retry. Every rewrite is reported so the audit record
    shows the call that actually ran, not the one that was requested.
    """
    if not clamp:
        return arguments, []

    adjusted = dict(arguments)
    notes: list[str] = []
    for key, bounds in clamp.items():
        if key not in adjusted:
            continue
        value = adjusted[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        original = value
        if "max" in bounds and value > bounds["max"]:
            value = bounds["max"]
        if "min" in bounds and value < bounds["min"]:
            value = bounds["min"]
        if value != original:
            adjusted[key] = value
            notes.append(f"{key}: {original} -> {value}")
    return adjusted, notes
