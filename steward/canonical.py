"""Deterministic JSON serialisation, shared by hashing and audit.

Both the tool-integrity pins and the audit hash chain need a byte-stable
encoding: two structurally identical values must produce identical bytes, or
every hash comparison becomes a coin flip on dictionary ordering.

This lives at the package root rather than inside either consumer because both
need it, and importing one subsystem from the other to get it created a cycle
(``audit.chain`` -> ``mcp.integrity`` -> ``mcp.gateway`` -> ``audit``).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialise deterministically: sorted keys, no incidental whitespace."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
