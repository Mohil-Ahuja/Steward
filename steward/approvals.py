"""Human-in-the-loop approval for high-risk calls.

The MCP specification is direct about this: "there SHOULD always be a human in
the loop with the ability to deny tool invocations." An autonomous agent that
can issue a refund at three in the morning with nobody watching is a policy
choice, not an inevitability, and ``require_approval`` is how an operator
declines to make it.

The interesting design question is how to *tell* the agent it is waiting. The
naive answer -- return an error -- is wrong, because an agent reads an error as
"that failed, try something else" and will route around the control, often by
finding a less-guarded tool that achieves the same end.

MCP provides the right primitive. A ``tools/call`` may return
``resultType: "input_required"`` carrying an ``elicitation/create`` request and
an opaque ``requestState``. The call is not failed, it is *suspended*: the
agent is told more input is needed and given a token to retry with. Steward
uses that channel for approval, so pausing for a human is expressed in the
protocol's own vocabulary rather than bolted on beside it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ApprovalRequest

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"


@dataclass
class ApprovalOutcome:
    status: str
    request: ApprovalRequest | None = None
    detail: str = ""

    @property
    def is_approved(self) -> bool:
        return self.status == APPROVED

    @property
    def is_pending(self) -> bool:
        return self.status == PENDING


async def create_request(
    session: AsyncSession,
    *,
    correlation_id: str,
    principal: str,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    risk_tier: str | None = None,
    justification: str | None = None,
    ttl_seconds: int = 900,
) -> ApprovalRequest:
    """Raise a pending approval and return its handle."""
    request = ApprovalRequest(
        correlation_id=correlation_id,
        principal=principal,
        server=server,
        tool=tool,
        arguments=arguments,
        risk_tier=risk_tier,
        justification=justification,
        status=PENDING,
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
    )
    session.add(request)
    await session.commit()
    await session.refresh(request)
    return request


async def get_request(session: AsyncSession, request_id: str) -> ApprovalRequest | None:
    result = await session.execute(
        select(ApprovalRequest)
        .where(ApprovalRequest.id == request_id)
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def resolve(
    session: AsyncSession,
    request_id: str,
    *,
    approved: bool,
    decided_by: str,
    note: str | None = None,
) -> ApprovalRequest:
    """Record an operator's decision."""
    request = await get_request(session, request_id)
    if request is None:
        raise KeyError(f"unknown approval request {request_id!r}")

    if request.status != PENDING:
        raise ValueError(
            f"approval {request_id!r} is already {request.status}; decisions are final"
        )

    expires = request.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires and expires <= datetime.now(UTC):
        request.status = EXPIRED
        await session.commit()
        raise ValueError(f"approval {request_id!r} expired before it was decided")

    request.status = APPROVED if approved else REJECTED
    request.decided_by = decided_by
    request.decision_note = note
    request.decided_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(request)
    return request


def approval_fingerprint(arguments: dict[str, Any]) -> str:
    """Stable digest of the arguments an approval was granted for."""
    from .canonical import canonical_json, sha256_hex

    return sha256_hex(canonical_json(arguments or {}))


async def check_token(
    session: AsyncSession,
    token: str | None,
    *,
    principal: str,
    server: str,
    tool: str,
    arguments: dict[str, Any] | None = None,
) -> ApprovalOutcome:
    """Validate an approval token presented on a retried call.

    The token is bound to the principal, the exact tool, **and the exact
    arguments** it was granted for. All three parts matter:

    * without principal binding, one agent's approval authorises another's;
    * without tool binding, an approval to issue a refund becomes an approval
      to delete a record -- a confused-deputy escalation manufactured by the
      very control meant to prevent one;
    * without argument binding, an operator approving a refund of 120 has
      unknowingly approved a refund of 9,999, since the agent chooses the
      arguments on the retry. This last one is the easiest to miss and the
      most damaging: the human sees a reasonable request, clicks approve, and
      authorises something they never saw.
    """
    if not token:
        return ApprovalOutcome(status=PENDING, detail="no approval token presented")

    request = await get_request(session, token)
    if request is None:
        return ApprovalOutcome(status=REJECTED, detail="approval token is not recognised")

    if request.principal != principal or request.server != server or request.tool != tool:
        return ApprovalOutcome(
            status=REJECTED,
            request=request,
            detail=(
                "approval token was issued for a different principal or tool "
                "and cannot be replayed here"
            ),
        )

    if arguments is not None and approval_fingerprint(request.arguments) != approval_fingerprint(
        arguments
    ):
        return ApprovalOutcome(
            status=REJECTED,
            request=request,
            detail=(
                "approval was granted for different arguments; the call must be "
                "re-approved as it now stands"
            ),
        )

    expires = request.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires and expires <= datetime.now(UTC) and request.status == PENDING:
        request.status = EXPIRED
        await session.commit()
        return ApprovalOutcome(status=EXPIRED, request=request, detail="approval expired")

    if request.status == APPROVED:
        return ApprovalOutcome(status=APPROVED, request=request, detail="approved")
    if request.status == REJECTED:
        return ApprovalOutcome(
            status=REJECTED,
            request=request,
            detail=request.decision_note or "an operator refused this call",
        )
    if request.status == EXPIRED:
        return ApprovalOutcome(status=EXPIRED, request=request, detail="approval expired")

    return ApprovalOutcome(status=PENDING, request=request, detail="awaiting an operator")


async def list_pending(
    session: AsyncSession, *, principal: str | None = None, limit: int = 100
) -> list[ApprovalRequest]:
    statement = (
        select(ApprovalRequest)
        .where(ApprovalRequest.status == PENDING)
        .order_by(ApprovalRequest.created_at.desc())
        .limit(limit)
        .execution_options(populate_existing=True)
    )
    if principal:
        statement = statement.where(ApprovalRequest.principal == principal)
    return list((await session.execute(statement)).scalars())


def input_required_result(
    request: ApprovalRequest, prompt: str | None = None
) -> dict[str, Any]:
    """Render a pending approval as an MCP ``input_required`` tool result.

    Shaped to the multi-round-trip pattern: the agent receives an elicitation
    describing what is being held and why, plus a ``requestState`` to send back
    on the retry. The call is suspended, not failed.
    """
    message = prompt or (
        f"Calling {request.server}:{request.tool} needs operator approval "
        f"(risk tier: {request.risk_tier or 'unknown'}). "
        "The call is held until a human decides."
    )
    return {
        "resultType": "input_required",
        "inputRequests": {
            "steward_approval": {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": message,
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "approval_token": {
                                "type": "string",
                                "description": (
                                    "Approval id to present on retry once an "
                                    "operator has decided."
                                ),
                            }
                        },
                        "required": ["approval_token"],
                    },
                },
            }
        },
        "requestState": request.id,
        "_meta": {
            "steward/approvalId": request.id,
            "steward/expiresAt": (
                request.expires_at.isoformat() if request.expires_at else None
            ),
        },
    }
