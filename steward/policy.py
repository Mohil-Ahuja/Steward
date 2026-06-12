from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Policy
from .schemas import CheckRequest, Decision


def _matches(value: str, pattern: str) -> bool:
    return fnmatchcase(value, pattern)


def _conditions_match(arguments: dict[str, Any], conditions: dict[str, Any]) -> bool:
    for key, expected in conditions.items():
        actual = arguments.get(key)
        if isinstance(expected, dict):
            if "equals" in expected and actual != expected["equals"]:
                return False
            if "in" in expected and actual not in expected["in"]:
                return False
            if "max" in expected and (not isinstance(actual, (int, float)) or actual > expected["max"]):
                return False
            if "min" in expected and (not isinstance(actual, (int, float)) or actual < expected["min"]):
                return False
            if expected.get("required") and key not in arguments:
                return False
        elif actual != expected:
            return False
    return True


async def evaluate(session: AsyncSession, request: CheckRequest) -> Decision:
    result = await session.execute(select(Policy).where(Policy.active.is_(True)))
    applicable: list[Policy] = []
    now = datetime.now(UTC)
    for policy in result.scalars():
        expires = policy.expires_at
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if policy.subject not in ("*", request.subject) or not _matches(request.server, policy.server):
            continue
        if not _matches(request.tool, policy.tool) or (expires and expires <= now):
            continue
        if _conditions_match(request.arguments, policy.conditions):
            applicable.append(policy)
    ids = [p.id for p in applicable]
    if any(p.effect == "deny" for p in applicable):
        return Decision(allowed=False, reason="explicit deny policy matched", matched_policy_ids=ids)
    if any(p.effect == "allow" for p in applicable):
        return Decision(allowed=True, reason="allow policy matched", matched_policy_ids=ids)
    return Decision(allowed=False, reason="no allow policy matched", matched_policy_ids=ids)
