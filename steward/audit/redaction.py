"""Redaction of sensitive values before they reach the audit log.

An audit trail that records every argument verbatim becomes the richest
credential store in the system: it is long-lived, widely readable, and holds
every secret any agent ever passed to any tool. Redaction is what stops the
control that proves safety from becoming the breach.

Two complementary strategies run together:

* **Key-based** -- drop anything filed under a name like ``password`` or
  ``api_key``. Cheap and precise, but blind to a secret passed under an
  innocuous key.
* **Value-based** -- match the *shape* of well-known secret formats (JWTs,
  AWS keys, bearer tokens, card numbers) wherever they appear, including
  inside free text. Catches the case key-matching misses.

Redaction is structure-preserving: an object stays an object and a list stays
a list, so the audit record still shows the *shape* of the call that was made.
Knowing that ``refund`` was invoked with an ``amount`` and a ``card_number``
is exactly the forensic signal you want; knowing the card number is not.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

#: Maximum depth walked when redacting. Bounds work on hostile nested input.
MAX_DEPTH = 12

#: Strings longer than this are truncated in the audit record. A tool argument
#: carrying a megabyte of text is a storage problem, not forensic evidence.
MAX_STRING = 2048

VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # JSON Web Token: three base64url segments.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_header", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.IGNORECASE)),
    # 13-19 digit runs with optional separators, Luhn-checked below.
    ("card_number", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

#: Patterns whose matches are common enough in benign text that redacting them
#: unconditionally would gut the audit trail's usefulness. Enabled separately.
LOW_CONFIDENCE = {"email"}


def _luhn_valid(digits: str) -> bool:
    """Luhn checksum, used to avoid redacting every long number as a card."""
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact_text(text: str, *, include_low_confidence: bool = False) -> str:
    """Replace secret-shaped substrings inside a string."""
    for name, pattern in VALUE_PATTERNS:
        if name in LOW_CONFIDENCE and not include_low_confidence:
            continue

        if name == "card_number":
            # ``label`` is bound as a default so the closure captures this
            # iteration's value rather than the loop variable by reference.
            def replace_card(match: re.Match[str], label: str = name) -> str:
                digits = re.sub(r"\D", "", match.group(0))
                # Only redact runs that actually check out as card numbers, so
                # order IDs and timestamps survive.
                return f"[REDACTED:{label}]" if _luhn_valid(digits) else match.group(0)

            text = pattern.sub(replace_card, text)
        else:
            text = pattern.sub(f"[REDACTED:{name}]", text)
    return text


def redact(
    value: Any,
    keys: set[str],
    *,
    scan_values: bool = True,
    extra_paths: frozenset[str] | None = None,
    include_low_confidence: bool = False,
    _depth: int = 0,
    _path: str = "",
) -> Any:
    """Recursively redact a structure by key name, value shape and path.

    ``extra_paths`` carries per-policy ``redact_arguments`` obligations, which
    are dotted paths rather than bare key names -- that lets one policy redact
    ``customer.email`` without blanking every ``email`` in the system.
    """
    if _depth > MAX_DEPTH:
        return "[TRUNCATED:depth]"

    extra_paths = extra_paths or frozenset()

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            path = f"{_path}.{key}" if _path else str(key)
            if str(key).lower() in keys or path in extra_paths:
                result[key] = REDACTED
            else:
                result[key] = redact(
                    item,
                    keys,
                    scan_values=scan_values,
                    extra_paths=extra_paths,
                    include_low_confidence=include_low_confidence,
                    _depth=_depth + 1,
                    _path=path,
                )
        return result

    if isinstance(value, (list, tuple)):
        return [
            redact(
                item,
                keys,
                scan_values=scan_values,
                extra_paths=extra_paths,
                include_low_confidence=include_low_confidence,
                _depth=_depth + 1,
                _path=f"{_path}[]",
            )
            for item in value[:200]  # bound fan-out on hostile input
        ]

    if isinstance(value, str):
        text = value
        if len(text) > MAX_STRING:
            text = text[:MAX_STRING] + f"...[TRUNCATED:{len(value)} chars]"
        if scan_values:
            text = redact_text(text, include_low_confidence=include_low_confidence)
        return text

    return value
