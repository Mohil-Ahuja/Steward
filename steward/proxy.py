from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import record
from .policy import evaluate
from .schemas import CheckRequest

DownstreamCall = Callable[[str, dict[str, Any]], Awaitable[Any]]


async def authorize_and_call(session: AsyncSession, request: CheckRequest, downstream: DownstreamCall) -> Any:
    decision = await evaluate(session, request)
    if not decision.allowed:
        await record(session, principal=request.subject, server=request.server, tool=request.tool,
                     arguments=request.arguments, decision="denied", reason=decision.reason,
                     policy_ids=decision.matched_policy_ids)
        raise HTTPException(status_code=403, detail=decision.reason)
    try:
        result = await downstream(request.tool, request.arguments)
        await record(session, principal=request.subject, server=request.server, tool=request.tool,
                     arguments=request.arguments, decision="allowed", reason=decision.reason,
                     policy_ids=decision.matched_policy_ids, downstream_status="success")
        return result
    except Exception:
        await record(session, principal=request.subject, server=request.server, tool=request.tool,
                     arguments=request.arguments, decision="allowed", reason=decision.reason,
                     policy_ids=decision.matched_policy_ids, downstream_status="error")
        raise
