"""FastAPI application: control plane, MCP gateway endpoint, audit access.

Routes are split by plane and every mutating control-plane route carries a role
dependency. Nothing here is reachable anonymously except ``/health``.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from . import approvals as approvals_module
from . import audit as audit_module
from .auth import (
    Operator,
    current_principal_context,
    require_admin,
    require_auditor,
    require_author,
)
from .config import get_settings
from .db import SessionLocal, get_session, init_db
from .mcp.gateway import Principal, StewardGateway
from .mcp.integrity import descriptor_matches_pin
from .mcp.jsonrpc import ErrorCode, JsonRpcError, error_response
from .mcp.registry import UpstreamRegistry, catalogue, discover, pin_tool, set_quarantine
from .models import AuditEvent, Policy, PolicyRevision
from .policy import CallRequest, Scope, ScopeError, attenuate, evaluate, find_redundant
from .schemas import (
    ApprovalDecision,
    ApprovalOut,
    AuditOut,
    ChainVerificationOut,
    CheckRequest,
    DecisionOut,
    DiscoveryOut,
    PolicyCreate,
    PolicyOut,
    PolicyUpdate,
    ScopeAnalysisOut,
    ScopeAnalysisRequest,
    ToolOut,
)

SessionDep = Annotated[AsyncSession, Depends(get_session)]

#: Registry of upstream MCP servers, wired at startup.
registry: UpstreamRegistry = UpstreamRegistry()
gateway: StewardGateway | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global gateway
    settings = get_settings()
    await init_db()

    # With nothing configured, fall back to the bundled in-process fleet so a
    # fresh checkout is immediately explorable. Never in production.
    if not registry.names and not settings.is_production:
        for name, server in _mock_fleet().items():
            registry.register_in_process(name, server)

    gateway = StewardGateway(registry, SessionLocal)

    if registry.names:
        async with SessionLocal() as session:
            await discover(session, registry, trust_annotations=settings.trust_tool_annotations)

    yield
    await registry.close()


def _mock_fleet() -> dict[str, Any]:
    from .mcp.mock_servers import build_all_servers

    return build_all_servers()


app = FastAPI(
    title="Steward",
    version="1.0.0",
    description=(
        "Per-action authorization, obligations and tamper-evident audit for "
        "LLM agents using the Model Context Protocol."
    ),
    lifespan=lifespan,
)


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Control plane: policies
# ---------------------------------------------------------------------------


@app.post("/v1/policies", response_model=PolicyOut, status_code=201, tags=["policies"])
async def create_policy(
    payload: PolicyCreate,
    session: SessionDep,
    operator: Operator = Depends(require_author),
):
    policy = Policy(
        **payload.model_dump(),
        active=True,
        version=1,
        created_by=operator.key_id,
    )
    session.add(policy)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a policy named {payload.name!r} already exists",
        ) from exc

    await session.refresh(policy)
    await _snapshot(session, policy, operator, "created")
    return policy


@app.get("/v1/policies", response_model=list[PolicyOut], tags=["policies"])
async def list_policies(
    session: SessionDep,
    _: Operator = Depends(require_auditor),
    subject: str | None = Query(default=None),
    active_only: bool = Query(default=False),
):
    statement = select(Policy).order_by(Policy.created_at)
    if subject:
        statement = statement.where(Policy.subject == subject)
    if active_only:
        statement = statement.where(Policy.active.is_(True))
    return list((await session.execute(statement)).scalars())


@app.patch("/v1/policies/{policy_id}", response_model=PolicyOut, tags=["policies"])
async def update_policy(
    policy_id: str,
    payload: PolicyUpdate,
    session: SessionDep,
    operator: Operator = Depends(require_author),
):
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")

    changes = payload.model_dump(exclude_unset=True, exclude={"change_note"})
    if not changes:
        return policy

    for key, value in changes.items():
        setattr(policy, key, value)
    policy.version += 1
    await session.commit()
    await session.refresh(policy)
    await _snapshot(session, policy, operator, payload.change_note or "updated")
    return policy


@app.delete("/v1/policies/{policy_id}", status_code=204, tags=["policies"])
async def revoke_policy(
    policy_id: str,
    session: SessionDep,
    operator: Operator = Depends(require_author),
):
    """Soft-revoke. History is never deleted, so the audit trail stays whole."""
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")
    policy.active = False
    policy.version += 1
    await session.commit()
    await _snapshot(session, policy, operator, "revoked")


@app.get("/v1/policies/{policy_id}/revisions", tags=["policies"])
async def policy_revisions(
    policy_id: str, session: SessionDep, _: Operator = Depends(require_auditor)
) -> list[dict[str, Any]]:
    result = await session.execute(
        select(PolicyRevision)
        .where(PolicyRevision.policy_id == policy_id)
        .order_by(PolicyRevision.version)
    )
    return [
        {
            "version": revision.version,
            "snapshot": revision.snapshot,
            "change_note": revision.change_note,
            "changed_by": revision.changed_by,
            "created_at": revision.created_at,
        }
        for revision in result.scalars()
    ]


@app.post("/v1/policies/{policy_id}/rollback/{version}", response_model=PolicyOut, tags=["policies"])
async def rollback_policy(
    policy_id: str,
    version: int,
    session: SessionDep,
    operator: Operator = Depends(require_admin),
):
    """Restore a policy to an earlier revision.

    Rolling back writes a *new* forward revision rather than rewinding
    history: an auditor must be able to see that a rollback happened, and
    when.
    """
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")

    revision = (
        await session.execute(
            select(PolicyRevision).where(
                PolicyRevision.policy_id == policy_id, PolicyRevision.version == version
            )
        )
    ).scalar_one_or_none()
    if revision is None:
        raise HTTPException(status_code=404, detail=f"no revision {version} for this policy")

    snapshot = revision.snapshot or {}
    for key in (
        "effect", "subject", "server", "tool", "conditions", "obligations",
        "max_risk_tier", "priority", "tags", "active", "description",
    ):
        if key in snapshot:
            setattr(policy, key, snapshot[key])
    policy.version += 1
    await session.commit()
    await session.refresh(policy)
    await _snapshot(session, policy, operator, f"rolled back to v{version}")
    return policy


async def _snapshot(
    session: AsyncSession, policy: Policy, operator: Operator, note: str
) -> None:
    session.add(
        PolicyRevision(
            policy_id=policy.id,
            version=policy.version,
            snapshot={
                "effect": policy.effect,
                "subject": policy.subject,
                "server": policy.server,
                "tool": policy.tool,
                "conditions": policy.conditions,
                "obligations": policy.obligations,
                "max_risk_tier": policy.max_risk_tier,
                "priority": policy.priority,
                "tags": policy.tags,
                "active": policy.active,
                "description": policy.description,
            },
            change_note=note,
            changed_by=operator.key_id,
        )
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@app.post("/v1/check", response_model=DecisionOut, tags=["decisions"])
async def check(
    payload: CheckRequest, session: SessionDep, _: Operator = Depends(require_auditor)
):
    """Evaluate a hypothetical call without executing it.

    Deliberately behind auth: an open endpoint that reports exactly which
    calls would be permitted is a policy-enumeration oracle.
    """
    decision = await evaluate(
        session,
        CallRequest(
            subject=payload.subject,
            server=payload.server,
            tool=payload.tool,
            arguments=payload.arguments,
            justification=payload.justification,
        ),
    )
    return DecisionOut(
        allowed=decision.allowed,
        reason=decision.reason,
        reason_code=decision.reason_code,
        matched_policy_ids=decision.matched_policy_ids,
        obligations=decision.obligation_names,
        risk_tier=decision.risk_tier.label if decision.risk_tier else None,
        clamp_notes=decision.clamp_notes,
        near_misses=[
            {"policy": miss.policy_name, "reason": miss.reason}
            for miss in decision.near_misses
        ],
    )


@app.post("/v1/scopes/analyse", response_model=ScopeAnalysisOut, tags=["decisions"])
async def analyse_scopes(
    payload: ScopeAnalysisRequest, _: Operator = Depends(require_auditor)
):
    """Attenuate a requested scope set against what the caller holds."""
    try:
        held = [Scope.parse(item) for item in payload.held]
        requested = [Scope.parse(item) for item in payload.requested]
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    granted = attenuate(held, requested)
    granted_set = {str(scope) for scope in granted}
    return ScopeAnalysisOut(
        granted=sorted(granted_set),
        refused=sorted({str(scope) for scope in requested} - granted_set),
        redundant=[
            {"redundant": str(narrow), "subsumed_by": str(broad)}
            for narrow, broad in find_redundant(held)
        ],
    )


# ---------------------------------------------------------------------------
# Tool catalogue
# ---------------------------------------------------------------------------


@app.post("/v1/tools/discover", response_model=DiscoveryOut, tags=["tools"])
async def run_discovery(
    session: SessionDep, operator: Operator = Depends(require_author)
):
    report = await discover(
        session, registry, trust_annotations=get_settings().trust_tool_annotations
    )
    return DiscoveryOut(**report.to_dict())


@app.get("/v1/tools", response_model=list[ToolOut], tags=["tools"])
async def list_tools(
    session: SessionDep,
    _: Operator = Depends(require_auditor),
    server: str | None = Query(default=None),
):
    descriptors = await catalogue(session, server=server)
    output: list[ToolOut] = []
    for descriptor in descriptors:
        item = ToolOut.model_validate(descriptor)
        item.drift = descriptor_matches_pin(descriptor) if descriptor.pinned else None
        output.append(item)
    return output


@app.post("/v1/tools/{server}/{tool}/pin", response_model=ToolOut, tags=["tools"])
async def approve_tool(
    server: str,
    tool: str,
    session: SessionDep,
    operator: Operator = Depends(require_admin),
):
    """Approve a tool's current definition, freezing it against drift."""
    try:
        descriptor = await pin_tool(session, server, tool, approved_by=operator.key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ToolOut.model_validate(descriptor)


@app.post("/v1/tools/{server}/{tool}/quarantine", response_model=ToolOut, tags=["tools"])
async def quarantine_tool(
    server: str,
    tool: str,
    session: SessionDep,
    operator: Operator = Depends(require_admin),
    quarantined: bool = Query(default=True),
    reason: str | None = Query(default=None),
):
    try:
        descriptor = await set_quarantine(
            session, server, tool, quarantined=quarantined, reason=reason
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ToolOut.model_validate(descriptor)


# ---------------------------------------------------------------------------
# MCP gateway
# ---------------------------------------------------------------------------


@app.post("/mcp", tags=["gateway"])
async def mcp_endpoint(request: Request) -> Any:
    """Streamable HTTP MCP endpoint that agents connect to.

    This is the data plane: agents speak ordinary MCP here and receive a
    scope-filtered catalogue and policy-checked calls.
    """
    if gateway is None:  # pragma: no cover - only before startup completes
        raise HTTPException(status_code=503, detail="gateway not ready")

    subject, claims = await current_principal_context(request)

    try:
        message = await request.json()
    except (json.JSONDecodeError, ValueError):
        return error_response(None, JsonRpcError(ErrorCode.PARSE_ERROR, "invalid JSON"))

    principal = Principal(
        subject=subject,
        session_id=request.headers.get("mcp-session-id"),
        claims=claims,
    )

    try:
        response = await gateway.handle(message, principal)
    except JsonRpcError as exc:
        return error_response(message.get("id"), exc)

    return response or {}


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


@app.get("/v1/approvals", response_model=list[ApprovalOut], tags=["approvals"])
async def list_approvals(
    session: SessionDep,
    _: Operator = Depends(require_auditor),
    principal: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
):
    return await approvals_module.list_pending(session, principal=principal, limit=limit)


@app.post("/v1/approvals/{request_id}", response_model=ApprovalOut, tags=["approvals"])
async def decide_approval(
    request_id: str,
    decision: ApprovalDecision,
    session: SessionDep,
    operator: Operator = Depends(require_author),
):
    try:
        return await approvals_module.resolve(
            session,
            request_id,
            approved=decision.approved,
            decided_by=operator.key_id,
            note=decision.note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@app.get("/v1/audit", response_model=list[AuditOut], tags=["audit"])
async def read_audit(
    session: SessionDep,
    _: Operator = Depends(require_auditor),
    principal: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    reason_code: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=100, le=500),
):
    statement = (
        select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(limit)
    )
    if principal:
        statement = statement.where(AuditEvent.principal == principal)
    if decision:
        statement = statement.where(AuditEvent.decision == decision)
    if reason_code:
        statement = statement.where(AuditEvent.reason_code == reason_code)
    if since:
        statement = statement.where(AuditEvent.created_at >= since)
    return list((await session.execute(statement)).scalars())


@app.get("/v1/audit/verify", response_model=ChainVerificationOut, tags=["audit"])
async def verify_audit(session: SessionDep, _: Operator = Depends(require_auditor)):
    """Recompute the hash chain and report any tampering."""
    report = await audit_module.verify_chain(session)
    return ChainVerificationOut(**report.to_dict())


@app.get("/v1/audit/checkpoint", tags=["audit"])
async def audit_checkpoint(session: SessionDep, _: Operator = Depends(require_auditor)):
    """Head-of-chain digest, for anchoring outside this database."""
    return await audit_module.checkpoint(session)
