import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from steward.db import Base
from steward.models import Policy
from steward.policy import evaluate
from steward.schemas import CheckRequest


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        yield db
    await engine.dispose()


async def add(session, **kwargs):
    session.add(Policy(name=kwargs.pop("name", "p"), **kwargs))
    await session.commit()


@pytest.mark.asyncio
async def test_allow_and_default_deny(session):
    await add(session, effect="allow", subject="agent-a", server="crm", tool="contacts.read")
    assert (await evaluate(session, CheckRequest(subject="agent-a", server="crm", tool="contacts.read"))).allowed
    assert not (await evaluate(session, CheckRequest(subject="agent-a", server="crm", tool="contacts.delete"))).allowed


@pytest.mark.asyncio
async def test_deny_overrides_allow(session):
    await add(session, name="allow", effect="allow", subject="*", server="crm", tool="*")
    await add(session, name="deny", effect="deny", subject="agent-a", server="crm", tool="contacts.delete")
    decision = await evaluate(session, CheckRequest(subject="agent-a", server="crm", tool="contacts.delete"))
    assert not decision.allowed
    assert len(decision.matched_policy_ids) == 2


@pytest.mark.asyncio
async def test_argument_constraint(session):
    await add(session, effect="allow", subject="agent-a", server="billing", tool="refund",
              conditions={"amount": {"max": 100}})
    assert (await evaluate(session, CheckRequest(subject="agent-a", server="billing", tool="refund", arguments={"amount": 50}))).allowed
    assert not (await evaluate(session, CheckRequest(subject="agent-a", server="billing", tool="refund", arguments={"amount": 101}))).allowed

