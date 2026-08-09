"""Argument-level constraint evaluation.

A policy may narrow a grant by constraining the *arguments* of a call, not just
its name. ``billing:refund`` is far too broad a permission; ``billing:refund``
where ``amount <= 100`` and ``currency in [USD, EUR]`` is a real one.

Two rules govern this module, both chosen to fail closed:

1. **Unknown operators never match.** The original implementation walked a
   condition dict and silently ignored keys it did not recognise, so a typo
   (``{"amount": {"maxx": 100}}``) degraded into an unconstrained allow -- the
   worst possible failure direction for an authorization system. Here an
   unrecognised operator raises, and the engine turns that into a deny.
2. **A missing argument fails a constraint.** If a policy bounds ``amount`` and
   the call omits ``amount``, the constraint is unsatisfied. A caller does not
   get to escape a limit by leaving the field out.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlparse

_MISSING = object()

# Bound on regex subject length. Policy-supplied patterns are trusted (an author
# with policy-write rights can already grant anything), but call arguments are
# attacker-controlled, so the matched *subject* is length-capped to blunt
# catastrophic backtracking.
MAX_REGEX_SUBJECT = 4096


class ConditionError(ValueError):
    """Raised for a malformed or unrecognised condition."""


@dataclass(frozen=True)
class ConditionOutcome:
    matched: bool
    failures: tuple[str, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.matched


def resolve_path(arguments: dict[str, Any], path: str) -> Any:
    """Look up a possibly dotted key path, returning ``_MISSING`` if absent.

    Dotted paths let a policy constrain nested structures --
    ``{"payload.recipient.domain": {"equals": "example.com"}}`` -- which real
    MCP tools produce constantly. A literal key containing dots is tried first,
    so flat argument maps keep working unchanged.
    """
    if path in arguments:
        return arguments[path]
    current: Any = arguments
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, (list, tuple)) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None  # bools are ints in Python; never treat them as numeric
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _length(value: Any) -> int | None:
    if isinstance(value, (str, list, tuple, dict, set)):
        return len(value)
    return None


# ---------------------------------------------------------------------------
# Operators: (actual, expected) -> bool. ``actual`` may be _MISSING.
# ---------------------------------------------------------------------------


def _op_equals(actual: Any, expected: Any) -> bool:
    return actual is not _MISSING and actual == expected


def _op_not_equals(actual: Any, expected: Any) -> bool:
    return actual is _MISSING or actual != expected


def _op_in(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'in' expects a list of allowed values")
    return actual is not _MISSING and actual in expected


def _op_not_in(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'not_in' expects a list of forbidden values")
    return actual is _MISSING or actual not in expected


def _numeric(name: str, compare: Callable[[float, float], bool]) -> Callable[[Any, Any], bool]:
    def operator(actual: Any, expected: Any) -> bool:
        bound = _as_number(expected)
        if bound is None:
            raise ConditionError(f"'{name}' expects a numeric bound")
        value = _as_number(actual)
        # A non-numeric or absent argument cannot satisfy a numeric bound.
        return value is not None and compare(value, bound)

    return operator


def _op_required(actual: Any, expected: Any) -> bool:
    return actual is not _MISSING if expected else True


def _op_forbidden(actual: Any, expected: Any) -> bool:
    return actual is _MISSING if expected else True


def _op_regex(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, str):
        raise ConditionError("'regex' expects a pattern string")
    if not isinstance(actual, str) or len(actual) > MAX_REGEX_SUBJECT:
        return False
    try:
        # fullmatch, not search: an anchored match is what a policy author
        # almost always means, and it removes a class of bypass where a benign
        # substring appears somewhere inside a hostile string.
        return re.fullmatch(expected, actual) is not None
    except re.error as exc:
        raise ConditionError(f"invalid regex {expected!r}: {exc}") from exc


def _op_glob(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, str):
        raise ConditionError("'glob' expects a pattern string")
    return isinstance(actual, str) and fnmatchcase(actual, expected)


def _string_test(name: str, test: Callable[[str, str], bool]) -> Callable[[Any, Any], bool]:
    def operator(actual: Any, expected: Any) -> bool:
        if not isinstance(expected, str):
            raise ConditionError(f"'{name}' expects a string")
        return isinstance(actual, str) and test(actual, expected)

    return operator


def _op_not_contains(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, str):
        raise ConditionError("'not_contains' expects a string")
    return True if not isinstance(actual, str) else expected not in actual


def _length_test(name: str, compare: Callable[[int, int], bool]) -> Callable[[Any, Any], bool]:
    def operator(actual: Any, expected: Any) -> bool:
        bound = _as_number(expected)
        if bound is None:
            raise ConditionError(f"'{name}' expects a numeric bound")
        size = _length(actual)
        return size is not None and compare(size, int(bound))

    return operator


_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "array": (list, tuple),
    "object": (dict,),
}


def _op_type(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, str) or expected not in _TYPES:
        raise ConditionError(f"'type' expects one of {sorted(_TYPES)}")
    if actual is _MISSING:
        return False
    if expected in {"number", "integer"} and isinstance(actual, bool):
        return False
    return isinstance(actual, _TYPES[expected])


def _op_subset_of(actual: Any, expected: Any) -> bool:
    """Every element of an array argument must be in the allowed set.

    The array analogue of ``in``. It matters for tools taking lists:
    ``{"fields": {"subset_of": ["id", "name"]}}`` stops an agent widening a
    projection to include ``ssn``.
    """
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'subset_of' expects a list of allowed values")
    if not isinstance(actual, (list, tuple, set)):
        return False
    return set(actual) <= set(expected)


def _op_host_in(actual: Any, expected: Any) -> bool:
    """Constrain the host of a URL-valued argument.

    Exfiltration through a fetch-style tool is a URL problem, so the host is
    compared structurally rather than by substring: ``evil.com/?x=api.internal``
    must not pass a check for ``api.internal``.
    """
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'host_in' expects a list of allowed hosts")
    if not isinstance(actual, str):
        return False
    try:
        host = (urlparse(actual).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    for entry in expected:
        allowed = str(entry).lower().lstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _op_cidr_in(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'cidr_in' expects a list of CIDR blocks")
    if not isinstance(actual, str):
        return False
    try:
        address = ipaddress.ip_address(actual)
    except ValueError:
        return False
    for block in expected:
        try:
            if address in ipaddress.ip_network(str(block), strict=False):
                return True
        except ValueError as exc:
            raise ConditionError(f"invalid CIDR {block!r}: {exc}") from exc
    return False


def _op_path_under(actual: Any, expected: Any) -> bool:
    """Confine a filesystem-path argument beneath allowed prefixes.

    Normalised before comparison, so ``/srv/data/../../etc/passwd`` is judged on
    where it actually lands -- which is the entire point of the check.
    """
    if not isinstance(expected, (list, tuple, set)):
        raise ConditionError("'path_under' expects a list of path prefixes")
    if not isinstance(actual, str):
        return False
    candidate = posixpath.normpath(actual.replace("\\", "/"))
    for prefix in expected:
        root = posixpath.normpath(str(prefix).replace("\\", "/"))
        if candidate == root or candidate.startswith(root.rstrip("/") + "/"):
            return True
    return False


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "in": _op_in,
    "not_in": _op_not_in,
    "min": _numeric("min", lambda value, bound: value >= bound),
    "max": _numeric("max", lambda value, bound: value <= bound),
    "gt": _numeric("gt", lambda value, bound: value > bound),
    "lt": _numeric("lt", lambda value, bound: value < bound),
    "required": _op_required,
    "forbidden": _op_forbidden,
    "regex": _op_regex,
    "glob": _op_glob,
    "prefix": _string_test("prefix", str.startswith),
    "suffix": _string_test("suffix", str.endswith),
    "contains": _string_test("contains", lambda value, needle: needle in value),
    "not_contains": _op_not_contains,
    "max_length": _length_test("max_length", lambda size, bound: size <= bound),
    "min_length": _length_test("min_length", lambda size, bound: size >= bound),
    "type": _op_type,
    "subset_of": _op_subset_of,
    "host_in": _op_host_in,
    "cidr_in": _op_cidr_in,
    "path_under": _op_path_under,
}


def validate_conditions(conditions: dict[str, Any]) -> None:
    """Reject unknown operators at policy-authoring time.

    Catching a typo when the policy is written beats failing closed at 3am, so
    the control plane calls this before persisting a policy.
    """
    if not isinstance(conditions, dict):
        raise ConditionError("conditions must be an object")
    for key, expected in conditions.items():
        if isinstance(expected, dict):
            unknown = sorted(set(expected) - set(OPERATORS))
            if unknown:
                raise ConditionError(
                    f"condition {key!r} uses unknown operator(s) {unknown}; "
                    f"supported: {sorted(OPERATORS)}"
                )


def evaluate_conditions(
    arguments: dict[str, Any], conditions: dict[str, Any]
) -> ConditionOutcome:
    """Evaluate every constraint; all must hold for the policy to match."""
    if not conditions:
        return ConditionOutcome(True)
    if not isinstance(conditions, dict):
        raise ConditionError("conditions must be an object")

    failures: list[str] = []
    for key, expected in conditions.items():
        actual = resolve_path(arguments, key)
        shown = "<absent>" if actual is _MISSING else repr(actual)
        if isinstance(expected, dict):
            for operator_name, operand in expected.items():
                operator = OPERATORS.get(operator_name)
                if operator is None:
                    raise ConditionError(
                        f"condition {key!r} uses unknown operator {operator_name!r}"
                    )
                if not operator(actual, operand):
                    failures.append(f"{key} {operator_name}={operand!r} (actual {shown})")
        elif not _op_equals(actual, expected):
            # A bare value is shorthand for equality.
            failures.append(f"{key} equals={expected!r} (actual {shown})")

    return ConditionOutcome(not failures, tuple(failures))
