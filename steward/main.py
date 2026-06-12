from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import current_principal
from .db import get_session, init_db
from .models import AuditEvent, Policy
from .policy import evaluate
from .proxy import authorize_and_call
from .schemas import AuditOut, CheckRequest, Decision, PolicyCreate, PolicyOut

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Steward", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/policies", response_model=PolicyOut, status_code=201)
async def create_policy(payload: PolicyCreate, session: SessionDep):
    policy = Policy(**payload.model_dump())
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


@app.get("/v1/policies", response_model=list[PolicyOut])
async def list_policies(session: SessionDep):
    return list((await session.execute(select(Policy).order_by(Policy.created_at))).scalars())


@app.delete("/v1/policies/{policy_id}", status_code=204)
async def revoke_policy(policy_id: str, session: SessionDep):
    policy = await session.get(Policy, policy_id)
    if policy:
        policy.active = False
        await session.commit()


@app.post("/v1/check", response_model=Decision)
async def check(payload: CheckRequest, session: SessionDep):
    return await evaluate(session, payload)


@app.post("/v1/proxy/{server}/tools/{tool}")
async def proxy_call(server: str, tool: str, payload: dict, request: Request,
                     session: SessionDep):
    principal = await current_principal(request)
    call = CheckRequest(subject=principal, server=server, tool=tool, arguments=payload)
    # The transport adapter is deliberately injected at deployment time. The MVP returns
    # the authorized call envelope until a downstream MCP connector is configured.
    async def configured_downstream(name: str, arguments: dict):
        return {"tool": name, "arguments": arguments, "status": "authorized"}
    return await authorize_and_call(session, call, configured_downstream)


@app.get("/v1/audit", response_model=list[AuditOut])
async def audit(session: SessionDep, principal: str | None = Query(default=None),
                limit: int = Query(default=100, le=500)):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if principal:
        query = query.where(AuditEvent.principal == principal)
    return list((await session.execute(query)).scalars())
