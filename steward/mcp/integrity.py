"""Tool-definition integrity: canonical hashing and rug-pull detection.

MCP tool definitions are mutable at the server's discretion. The protocol even
provides ``notifications/tools/list_changed`` so servers can tell clients the
catalogue moved. That flexibility creates an attack the community calls a *rug
pull*: publish a benign tool, wait for a human to approve it, then silently
swap the description or schema for a malicious one. Because the tool's *name*
never changes, a name-based allowlist keeps letting it through.

Steward defends against this by pinning. When an operator approves a tool, the
exact bytes of its definition are hashed and stored. Every subsequent
discovery re-hashes the live definition and compares. Any difference means the
tool is no longer the thing that was approved, so it stops being callable until
a human looks again.

Hashing must be canonical or it is worthless -- two semantically identical
definitions that differ only in key order would read as drift and bury real
findings in noise. :func:`canonical_json` fixes an ordering and separator
convention so the hash depends on content alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..canonical import canonical_json, sha256_hex

# Fields of a tool definition that are security-relevant. ``title`` and
# ``icons`` are presentation only and deliberately excluded: a server
# re-theming its UI should not invalidate every pin and train operators to
# click through drift warnings.
SIGNIFICANT_FIELDS = ("name", "description", "inputSchema", "outputSchema", "annotations")


_sha256 = sha256_hex

__all__ = [
    "DescriptorHashes",
    "SIGNIFICANT_FIELDS",
    "canonical_json",
    "descriptor_matches_pin",
    "hash_from_mcp_tool",
    "hash_tool_definition",
]


@dataclass(frozen=True)
class DescriptorHashes:
    descriptor: str
    description: str
    schema: str


def hash_tool_definition(
    *,
    name: str,
    description: str | None = None,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
) -> DescriptorHashes:
    """Compute the pinnable hashes of one tool definition.

    The description and schema are hashed separately as well as jointly, so a
    drift report can name the part that moved instead of just asserting that
    something did.
    """
    description_hash = _sha256(canonical_json(description or ""))
    schema_hash = _sha256(
        canonical_json({"input": input_schema or {}, "output": output_schema or None})
    )
    descriptor_hash = _sha256(
        canonical_json(
            {
                "name": name,
                "description": description or "",
                "inputSchema": input_schema or {},
                "outputSchema": output_schema or None,
                "annotations": annotations or {},
            }
        )
    )
    return DescriptorHashes(
        descriptor=descriptor_hash,
        description=description_hash,
        schema=schema_hash,
    )


def hash_from_mcp_tool(tool: dict[str, Any]) -> DescriptorHashes:
    """Hash a tool object exactly as it arrived over the wire."""
    return hash_tool_definition(
        name=str(tool.get("name", "")),
        description=tool.get("description"),
        input_schema=tool.get("inputSchema"),
        output_schema=tool.get("outputSchema"),
        annotations=tool.get("annotations"),
    )


def descriptor_matches_pin(descriptor: Any) -> str | None:
    """Return a human-readable drift description, or ``None`` if intact.

    Accepts any object exposing the ``ToolDescriptor`` attributes so the pure
    decision path stays free of a database import.
    """
    pinned = getattr(descriptor, "pinned_descriptor_hash", None)
    if not pinned:
        # Marked pinned but never captured: treat as intact rather than
        # blocking. The registry refuses to set ``pinned`` without hashes, so
        # reaching here means a hand-edited row.
        return None

    if pinned == getattr(descriptor, "descriptor_hash", None):
        return None

    changed: list[str] = []
    pinned_description = getattr(descriptor, "pinned_description_hash", None)
    if pinned_description and pinned_description != getattr(descriptor, "description_hash", None):
        changed.append("description")
    pinned_schema = getattr(descriptor, "pinned_schema_hash", None)
    if pinned_schema and pinned_schema != getattr(descriptor, "schema_hash", None):
        changed.append("input schema")

    if not changed:
        # Joint hash moved but neither tracked half did, so the change is in
        # the annotations.
        changed.append("annotations")

    return " and ".join(changed) + " changed since pinning"
