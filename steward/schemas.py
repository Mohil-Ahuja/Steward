from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    name: str
    effect: Literal["allow", "deny"]
    subject: str
    server: str
    tool: str
    conditions: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class PolicyOut(PolicyCreate):
    id: str
    version: int
    active: bool

    model_config = {"from_attributes": True}


class CheckRequest(BaseModel):
    subject: str
    server: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    allowed: bool
    reason: str
    matched_policy_ids: list[str] = Field(default_factory=list)


class AuditOut(BaseModel):
    id: str
    correlation_id: str
    principal: str
    server: str
    tool: str
    arguments: dict[str, Any]
    decision: str
    reason: str
    matched_policy_ids: list[str]
    downstream_status: str | None
    latency_ms: int | None
    created_at: datetime

    model_config = {"from_attributes": True}

