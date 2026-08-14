"""Upstream registry: discovery, risk classification, pinning, quarantine.

The registry is the bridge between what upstream servers *say* they offer and
what Steward is willing to let an agent reach. Discovery is where a tool
definition first crosses the trust boundary, so it is where classification and
integrity checks belong.

The refresh flow for each discovered tool is:

1. Hash the definition canonically.
2. Classify its risk from evidence the server cannot forge in its favour.
3. Scan the description for instructions aimed at the agent; quarantine it if
   any are found.
4. If the tool is pinned and its hash moved, flag the drift and leave the pin
   alone -- the enforcement point refuses the tool until a human re-approves.

Point 4 is the subtle one. A naive implementation would update the stored hash
on every refresh, which would make the pin describe whatever the server most
recently said and defeat the whole mechanism.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ToolDescriptor
from ..policy.risk import classify_tool
from .client import UpstreamClient, UpstreamTool, build_transport
from .integrity import hash_tool_definition


@dataclass
class ToolChange:
    server: str
    tool: str
    kind: str  # added | unchanged | drifted | quarantined | recovered
    detail: str = ""


@dataclass
class DiscoveryReport:
    servers_contacted: list[str] = field(default_factory=list)
    servers_failed: dict[str, str] = field(default_factory=dict)
    changes: list[ToolChange] = field(default_factory=list)

    @property
    def added(self) -> list[ToolChange]:
        return [change for change in self.changes if change.kind == "added"]

    @property
    def drifted(self) -> list[ToolChange]:
        return [change for change in self.changes if change.kind == "drifted"]

    @property
    def quarantined(self) -> list[ToolChange]:
        return [change for change in self.changes if change.kind == "quarantined"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "servers_contacted": list(self.servers_contacted),
            "servers_failed": dict(self.servers_failed),
            "added": len(self.added),
            "drifted": len(self.drifted),
            "quarantined": len(self.quarantined),
            "changes": [
                {"server": c.server, "tool": c.tool, "kind": c.kind, "detail": c.detail}
                for c in self.changes
            ],
        }


class UpstreamRegistry:
    """Holds the configured upstream servers and their clients."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._specs: dict[str, dict[str, Any]] = {}
        self._clients: dict[str, UpstreamClient] = {}
        self._timeout = timeout

    def register(self, name: str, spec: dict[str, Any]) -> None:
        self._specs[name] = dict(spec)
        self._clients.pop(name, None)

    def register_in_process(self, name: str, server: Any) -> None:
        self.register(name, {"transport": "inproc", "server": server})

    @property
    def names(self) -> list[str]:
        return sorted(self._specs)

    def client(self, name: str) -> UpstreamClient:
        if name not in self._specs:
            raise KeyError(f"unknown upstream server {name!r}")
        if name not in self._clients:
            transport = build_transport(self._specs[name])
            self._clients[name] = UpstreamClient(name, transport, timeout=self._timeout)
        return self._clients[name]

    async def close(self) -> None:
        for client in self._clients.values():
            await client.close()
        self._clients.clear()

    @classmethod
    def from_config(cls, entries: Iterable[dict[str, Any]], timeout: float = 30.0) -> UpstreamRegistry:
        registry = cls(timeout=timeout)
        for entry in entries:
            name = entry.get("name")
            if not name:
                raise ValueError("upstream entry requires a 'name'")
            registry.register(str(name), entry)
        return registry

    @classmethod
    def with_mock_fleet(cls) -> UpstreamRegistry:
        """Registry wired to the bundled in-process servers."""
        from .mock_servers import build_all_servers

        registry = cls()
        for name, server in build_all_servers().items():
            registry.register_in_process(name, server)
        return registry


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def upsert_tool(
    session: AsyncSession,
    tool: UpstreamTool,
    *,
    trust_annotations: bool = False,
    auto_quarantine: bool = True,
) -> ToolChange:
    """Record or refresh one tool, applying integrity and quarantine rules."""
    hashes = hash_tool_definition(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        annotations=tool.annotations,
    )
    assessment = classify_tool(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        annotations=tool.annotations,
        trust_annotations=trust_annotations,
    )

    existing = (
        await session.execute(
            select(ToolDescriptor).where(
                ToolDescriptor.server == tool.server, ToolDescriptor.name == tool.name
            )
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)

    if existing is None:
        descriptor = ToolDescriptor(
            server=tool.server,
            name=tool.name,
            title=tool.title,
            description=tool.description,
            input_schema=tool.input_schema,
            output_schema=tool.output_schema,
            annotations=tool.annotations,
            descriptor_hash=hashes.descriptor,
            description_hash=hashes.description,
            schema_hash=hashes.schema,
            risk_tier=assessment.tier.label,
            risk_rationale=list(assessment.rationale),
            pinned=False,
            quarantined=bool(assessment.poisoned and auto_quarantine),
            quarantine_reason=(
                "description contains agent-directed instructions: "
                + ", ".join(sorted({f.signal for f in assessment.injection_findings}))
                if assessment.poisoned
                else None
            ),
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(descriptor)
        kind = "quarantined" if descriptor.quarantined else "added"
        return ToolChange(
            server=tool.server,
            tool=tool.name,
            kind=kind,
            detail=descriptor.quarantine_reason or f"risk={assessment.tier.label}",
        )

    drifted = existing.pinned and existing.pinned_descriptor_hash not in (None, hashes.descriptor)

    # The live view always tracks upstream. The *pin* never moves on its own --
    # only an explicit re-approval updates it.
    existing.title = tool.title
    existing.description = tool.description
    existing.input_schema = tool.input_schema
    existing.output_schema = tool.output_schema
    existing.annotations = tool.annotations
    existing.descriptor_hash = hashes.descriptor
    existing.description_hash = hashes.description
    existing.schema_hash = hashes.schema
    existing.risk_tier = assessment.tier.label
    existing.risk_rationale = list(assessment.rationale)
    existing.last_seen_at = now

    if assessment.poisoned and auto_quarantine and not existing.quarantined:
        existing.quarantined = True
        existing.quarantine_reason = (
            "description contains agent-directed instructions: "
            + ", ".join(sorted({f.signal for f in assessment.injection_findings}))
        )
        return ToolChange(
            server=tool.server,
            tool=tool.name,
            kind="quarantined",
            detail=existing.quarantine_reason,
        )

    if drifted:
        return ToolChange(
            server=tool.server,
            tool=tool.name,
            kind="drifted",
            detail="definition changed after pinning; calls refused until re-approved",
        )

    return ToolChange(
        server=tool.server, tool=tool.name, kind="unchanged", detail=assessment.tier.label
    )


async def discover(
    session: AsyncSession,
    registry: UpstreamRegistry,
    *,
    servers: Iterable[str] | None = None,
    trust_annotations: bool = False,
    auto_quarantine: bool = True,
) -> DiscoveryReport:
    """Refresh the tool catalogue from every configured upstream."""
    report = DiscoveryReport()
    targets = list(servers) if servers is not None else registry.names

    for name in targets:
        try:
            client = registry.client(name)
            tools = await client.list_tools()
        except Exception as exc:
            # One unreachable server must not abort discovery of the rest;
            # a partial catalogue is far better than none.
            report.servers_failed[name] = f"{type(exc).__name__}: {exc}"
            continue

        report.servers_contacted.append(name)
        for tool in tools:
            report.changes.append(
                await upsert_tool(
                    session,
                    tool,
                    trust_annotations=trust_annotations,
                    auto_quarantine=auto_quarantine,
                )
            )

    await session.commit()
    return report


async def pin_tool(
    session: AsyncSession, server: str, tool: str, *, approved_by: str | None = None
) -> ToolDescriptor:
    """Approve a tool's current definition, freezing it against future drift."""
    descriptor = (
        await session.execute(
            select(ToolDescriptor).where(
                ToolDescriptor.server == server, ToolDescriptor.name == tool
            )
        )
    ).scalar_one_or_none()

    if descriptor is None:
        raise KeyError(f"unknown tool {server}:{tool}")

    descriptor.pinned = True
    descriptor.pinned_descriptor_hash = descriptor.descriptor_hash
    descriptor.pinned_description_hash = descriptor.description_hash
    descriptor.pinned_schema_hash = descriptor.schema_hash
    descriptor.pinned_at = datetime.now(UTC)
    descriptor.pinned_by = approved_by
    await session.commit()
    await session.refresh(descriptor)
    return descriptor


async def set_quarantine(
    session: AsyncSession, server: str, tool: str, *, quarantined: bool, reason: str | None = None
) -> ToolDescriptor:
    descriptor = (
        await session.execute(
            select(ToolDescriptor).where(
                ToolDescriptor.server == server, ToolDescriptor.name == tool
            )
        )
    ).scalar_one_or_none()
    if descriptor is None:
        raise KeyError(f"unknown tool {server}:{tool}")

    descriptor.quarantined = quarantined
    descriptor.quarantine_reason = reason if quarantined else None
    await session.commit()
    await session.refresh(descriptor)
    return descriptor


async def catalogue(
    session: AsyncSession, *, server: str | None = None
) -> list[ToolDescriptor]:
    statement = select(ToolDescriptor).order_by(ToolDescriptor.server, ToolDescriptor.name)
    if server:
        statement = statement.where(ToolDescriptor.server == server)
    result = await session.execute(statement.execution_options(populate_existing=True))
    return list(result.scalars())
