"""Scope algebra for MCP tool permissions.

A *scope* names a set of callable actions as ``server:tool``, where each half
is a glob pattern (``*`` = any run of characters, ``?`` = exactly one)::

    crm:contacts.read      one action
    crm:contacts.*         every contacts action on the crm server
    *:*                    everything (a blanket grant)

Matching a concrete call against a scope is the easy half. The interesting
operation is **containment**: given two scopes, does one grant strictly no
more than the other? That question is what turns "least privilege" from a
slogan into something a test can assert, and it powers three features:

* delegation -- an agent may hand a sub-agent only an attenuated subset of
  what it holds itself (:func:`attenuate`);
* redundancy analysis -- a policy whose scope is contained by another
  policy of the same effect is dead weight (:func:`find_redundant`);
* blast-radius reporting -- how much of the tool catalogue a grant reaches.

Glob containment cannot be decided by string comparison: ``a*`` contains
``ab*`` but ``ab*`` does not contain ``a*``, and ``*x`` versus ``x*`` overlap
without either containing the other. So each pattern is compiled to a finite
automaton and containment is decided as ``L(A) - L(B) = empty`` via a product
construction over a symbolic alphabet.

The alphabet trick keeps this finite: two characters that appear literally in
neither pattern are indistinguishable to both, so every such character is
collapsed into a single ``OTHER`` sentinel. The alphabet is therefore at most
``|literals(A) union literals(B)| + 1`` symbols wide.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from itertools import count

SCOPE_SEPARATOR = ":"
OTHER = "\x00other"  # sentinel standing in for "any character not named"

# Transition labels inside the NFA.
_ANY = "\x00any"  # '?' or '*' self-loop: matches one arbitrary character


class ScopeError(ValueError):
    """Raised for a syntactically invalid scope string."""


# ---------------------------------------------------------------------------
# Glob -> NFA
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _NFA:
    start: int
    accepts: frozenset[int]
    # (state, label) -> frozenset(state); label is a literal char or _ANY
    delta: dict[tuple[int, str], frozenset[int]]
    literals: frozenset[str]


def _compile_glob(pattern: str) -> _NFA:
    """Build a Thompson-style NFA for a glob pattern.

    ``*`` becomes a state with an ``_ANY`` self-loop that is also epsilon-
    skippable; epsilon edges are eliminated eagerly by tracking, for each
    construction step, the full set of states reachable without consuming
    input.
    """
    ids = count()
    start = next(ids)
    delta: dict[tuple[int, str], set[int]] = {}
    literals: set[str] = set()

    # ``frontier`` is the epsilon-closure of the current position: every state
    # the machine could be in having consumed the prefix parsed so far.
    frontier: set[int] = {start}
    star_states: set[int] = set()

    def add(src: int, label: str, dst: int) -> None:
        delta.setdefault((src, label), set()).add(dst)

    for char in pattern:
        if char == "*":
            state = next(ids)
            # Every state currently on the frontier may enter the star, and the
            # star may consume any number of characters (self-loop). Because the
            # star is epsilon-skippable it stays on the frontier alongside the
            # states that reached it.
            for src in frontier:
                add(src, _ANY, state)
            add(state, _ANY, state)
            star_states.add(state)
            frontier = frontier | {state}
        elif char == "?":
            state = next(ids)
            for src in frontier:
                add(src, _ANY, state)
            frontier = {state}
        else:
            literals.add(char)
            state = next(ids)
            for src in frontier:
                add(src, char, state)
            frontier = {state}

    return _NFA(
        start=start,
        accepts=frozenset(frontier),
        delta={key: frozenset(value) for key, value in delta.items()},
        literals=frozenset(literals),
    )


def _step(nfa: _NFA, states: frozenset[int], symbol: str) -> frozenset[int]:
    """Advance a set of NFA states over one symbolic alphabet symbol."""
    out: set[int] = set()
    for state in states:
        # A literal transition fires only for that exact character. OTHER never
        # matches a literal edge, which is precisely why collapsing unnamed
        # characters is sound.
        if symbol is not OTHER and symbol != OTHER:
            out |= nfa.delta.get((state, symbol), frozenset())
        out |= nfa.delta.get((state, _ANY), frozenset())
    return frozenset(out)


def _alphabet(*nfas: _NFA) -> list[str]:
    symbols: set[str] = set()
    for nfa in nfas:
        symbols |= set(nfa.literals)
    return sorted(symbols) + [OTHER]


def glob_contains(outer: str, inner: str) -> bool:
    """Return True when every string matching ``inner`` also matches ``outer``.

    Decided by searching the product automaton for a reachable pair whose
    ``inner`` component accepts while the ``outer`` component does not -- such
    a pair is a witness string granted by ``inner`` but not by ``outer``.
    """
    if outer == inner:
        return True

    outer_nfa = _compile_glob(outer)
    inner_nfa = _compile_glob(inner)
    alphabet = _alphabet(outer_nfa, inner_nfa)

    start = (frozenset({inner_nfa.start}), frozenset({outer_nfa.start}))
    seen = {start}
    queue = [start]

    while queue:
        inner_states, outer_states = queue.pop()
        inner_accepts = bool(inner_states & inner_nfa.accepts)
        outer_accepts = bool(outer_states & outer_nfa.accepts)
        if inner_accepts and not outer_accepts:
            return False  # witness found: inner grants something outer does not
        for symbol in alphabet:
            nxt = (
                _step(inner_nfa, inner_states, symbol),
                _step(outer_nfa, outer_states, symbol),
            )
            if not nxt[0]:
                # ``inner`` is dead on this branch; nothing it accepts lies here.
                continue
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return True


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Scope:
    """A ``server:tool`` permission pattern."""

    server: str
    tool: str

    @classmethod
    def parse(cls, raw: str) -> Scope:
        text = raw.strip()
        if not text:
            raise ScopeError("scope must not be empty")
        server, sep, tool = text.partition(SCOPE_SEPARATOR)
        if not sep:
            raise ScopeError(
                f"scope {raw!r} must be 'server:tool' (e.g. 'crm:contacts.read')"
            )
        if not server or not tool:
            raise ScopeError(f"scope {raw!r} has an empty server or tool half")
        if SCOPE_SEPARATOR in tool:
            raise ScopeError(f"scope {raw!r} contains more than one ':' separator")
        return cls(server=server, tool=tool)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.server}{SCOPE_SEPARATOR}{self.tool}"

    # -- matching ----------------------------------------------------------
    def matches(self, server: str, tool: str) -> bool:
        """True when a concrete call falls inside this scope."""
        return fnmatchcase(server, self.server) and fnmatchcase(tool, self.tool)

    # -- algebra -----------------------------------------------------------
    def contains(self, other: Scope) -> bool:
        """True when ``other`` grants no more than this scope.

        A scope denotes the product of two independent glob languages, so
        containment holds exactly when it holds on both halves -- glob
        languages are never empty, so the product cannot collapse.
        """
        return glob_contains(self.server, other.server) and glob_contains(
            self.tool, other.tool
        )

    def is_blanket(self) -> bool:
        """True when this scope reaches every possible action."""
        return self.server == "*" and self.tool == "*"

    def specificity(self) -> tuple[int, int, int]:
        """Rank scopes from broad to narrow.

        Used to order otherwise-equal policies so that the most specific grant
        wins a tiebreak. Fewer wildcards and more literal characters is
        narrower.
        """
        text = str(self)
        wildcards = text.count("*") + text.count("?")
        literals = sum(1 for ch in text if ch not in "*?")
        return (-wildcards, literals, len(text))


def parse_scopes(raw: Iterable[str] | str | None) -> list[Scope]:
    """Parse a whitespace/comma separated scope list (or an iterable of them)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [chunk for chunk in raw.replace(",", " ").split() if chunk]
    else:
        parts = [str(chunk) for chunk in raw]
    return [Scope.parse(part) for part in parts]


def covers(granted: Iterable[Scope], server: str, tool: str) -> bool:
    """True when any granted scope admits the concrete call."""
    return any(scope.matches(server, tool) for scope in granted)


def attenuate(held: Iterable[Scope], requested: Iterable[Scope]) -> list[Scope]:
    """Return the requested scopes that are genuinely within ``held``.

    Delegation must never widen authority: a sub-agent asking for ``crm:*``
    while its parent holds only ``crm:contacts.read`` receives nothing for
    that request. Requests that *are* contained pass through unchanged.
    """
    held_list = list(held)
    return [
        scope
        for scope in requested
        if any(holder.contains(scope) for holder in held_list)
    ]


def find_redundant(scopes: Iterable[Scope]) -> list[tuple[Scope, Scope]]:
    """Find ``(redundant, subsuming)`` pairs within a scope set.

    A grant already implied by a broader grant of the same effect adds no
    authority but does add review burden, so surfacing these keeps policy
    sets honest.
    """
    items = list(scopes)
    pairs: list[tuple[Scope, Scope]] = []
    for i, narrow in enumerate(items):
        for j, broad in enumerate(items):
            if i == j:
                continue
            if not broad.contains(narrow):
                continue
            # Mutual containment means the two are equivalent; keep only one
            # direction so an equivalent pair is not reported twice.
            if narrow.contains(broad) and j > i:
                continue
            pairs.append((narrow, broad))
            break
    return pairs
