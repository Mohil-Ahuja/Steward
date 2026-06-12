import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .models import AuditEvent


def redact(value: Any) -> Any:
    keys = get_settings().redaction_keys
    if isinstance(value, dict):
        return {k: "[REDACTED]" if k.lower() in keys else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


async def record(session: AsyncSession, *, principal: str, server: str, tool: str,
                 arguments: dict, decision: str, reason: str, policy_ids: list[str],
                 correlation_id: str | None = None, downstream_status: str | None = None,
                 started: float | None = None) -> AuditEvent:
    event = AuditEvent(correlation_id=correlation_id or str(uuid.uuid4()), principal=principal,
                       server=server, tool=tool, arguments=redact(arguments), decision=decision,
                       reason=reason, matched_policy_ids=policy_ids,
                       downstream_status=downstream_status,
                       latency_ms=round((time.perf_counter() - started) * 1000) if started else None)
    session.add(event)
    await session.commit()
    await session.refresh(event)
    return event

