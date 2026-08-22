"""Pydantic request/response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .policy.conditions import ConditionError, validate_conditions
from .policy.obligations import ObligationError, parse_obligations
from .policy.risk import RiskTier


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    effect: Literal["allow", "deny"]
    subject: str = Field(min_length=1, max_length=200)
    server: str = Field(min_length=1, max_length=300)
    tool: str = Field(min_length=1, max_length=300)
    conditions: dict[str, Any] = Field(default_factory=dict)
    obligations: dict[str, Any] = Field(default_factory=dict)
    max_risk_tier: str | None = None
    priority: int = 0
    tags: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    expires_at: datetime | None = None

    # Validation happens at authoring time on purpose. A policy that only
    # fails when it is first evaluated fails during an incident, in a code
    # path whose correct behaviour is to deny -- so a typo silently becomes an
    # outage rather than a rejected write.
    @field_validator("conditions")
    @classmethod
    def _check_conditions(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_conditions(value)
        except ConditionError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("obligations")
    @classmethod
    def _check_obligations(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            parse_obligations(value)
        except ObligationError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("max_risk_tier")
    @classmethod
    def _check_tier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            RiskTier.parse(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @model_validator(mode="after")
    def _check_window(self) -> PolicyCreate:
        if self.not_before and self.expires_at and self.expires_at <= self.not_before:
            raise ValueError("expires_at must be after not_before")
        return self


class PolicyUpdate(BaseModel):
    description: str | None = None
    effect: Literal["allow", "deny"] | None = None
    conditions: dict[str, Any] | None = None
    obligations: dict[str, Any] | None = None
    max_risk_tier: str | None = None
    priority: int | None = None
    tags: list[str] | None = None
    expires_at: datetime | None = None
    active: bool | None = None
    change_note: str | None = None


class PolicyOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    version: int
    effect: str
    subject: str
    server: str
    tool: str
    conditions: dict[str, Any]
    obligations: dict[str, Any]
    max_risk_tier: str | None
    priority: int
    tags: list[str]
    not_before: datetime | None
    expires_at: datetime | None
    active: bool
    created_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CheckRequest(BaseModel):
    subject: str
    server: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    justification: str | None = None


class DecisionOut(BaseModel):
    allowed: bool
    reason: str
    reason_code: str
    matched_policy_ids: list[str] = Field(default_factory=list)
    obligations: list[str] = Field(default_factory=list)
    risk_tier: str | None = None
    clamp_notes: list[str] = Field(default_factory=list)
    near_misses: list[dict[str, str]] = Field(default_factory=list)


class ToolOut(BaseModel):
    id: str
    server: str
    name: str
    title: str | None
    description: str | None
    risk_tier: str
    risk_rationale: list[str]
    annotations: dict[str, Any]
    pinned: bool
    quarantined: bool
    quarantine_reason: str | None
    descriptor_hash: str
    pinned_descriptor_hash: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    #: Populated by the route when the live hash has drifted from the pin.
    drift: str | None = None

    model_config = {"from_attributes": True}


class AuditOut(BaseModel):
    id: str
    sequence: int
    correlation_id: str
    session_id: str | None
    principal: str
    server: str
    tool: str
    arguments: dict[str, Any]
    decision: str
    reason: str
    reason_code: str
    risk_tier: str | None
    matched_policy_ids: list[str]
    obligations_applied: list[str]
    downstream_status: str | None
    latency_ms: int | None
    prev_hash: str
    entry_hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ApprovalOut(BaseModel):
    id: str
    correlation_id: str
    principal: str
    server: str
    tool: str
    arguments: dict[str, Any]
    risk_tier: str | None
    justification: str | None
    status: str
    decided_by: str | None
    decision_note: str | None
    expires_at: datetime
    created_at: datetime
    decided_at: datetime | None

    model_config = {"from_attributes": True}


class ApprovalDecision(BaseModel):
    approved: bool
    note: str | None = None


class ScopeAnalysisRequest(BaseModel):
    """Ask whether one set of scopes is contained by another."""

    held: list[str]
    requested: list[str]


class ScopeAnalysisOut(BaseModel):
    granted: list[str]
    refused: list[str]
    redundant: list[dict[str, str]] = Field(default_factory=list)


class DiscoveryOut(BaseModel):
    servers_contacted: list[str]
    servers_failed: dict[str, str]
    added: int
    drifted: int
    quarantined: int
    changes: list[dict[str, Any]]


class ChainVerificationOut(BaseModel):
    intact: bool
    events_checked: int
    head_sequence: int
    head_hash: str
    breaks: list[dict[str, Any]]
