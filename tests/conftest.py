"""Shared fixtures.

Every test gets its own in-memory database and its own mock server fleet, so
no test can observe state another left behind. Rate limits and pins in
particular are stateful enough that shared fixtures produce order-dependent
failures that are miserable to debug.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

# Set before any steward import so the memoised Settings pick it up.
os.environ.setdefault("AUDIT_CHAIN_KEY", "test-chain-key")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("ALLOW_UNAUTHENTICATED_CONTROL_PLANE", "true")

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from steward.db import Base  # noqa: E402
from steward.mcp.mock_servers import build_all_servers  # noqa: E402
from steward.mcp.registry import UpstreamRegistry  # noqa: E402


@pytest_asyncio.fixture
async def engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def session(session_factory):
    async with session_factory() as db:
        yield db


@pytest.fixture
def servers():
    return build_all_servers()


@pytest.fixture
def registry(servers):
    registry = UpstreamRegistry()
    for name, server in servers.items():
        registry.register_in_process(name, server)
    return registry
