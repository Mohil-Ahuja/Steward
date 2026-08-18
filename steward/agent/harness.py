"""Agent harness: the thing that actually issues tool calls.

Two agents implement one interface.

:class:`ScriptedAgent` is deterministic and runs offline. It is the default for
the evaluation suite, and it is not a strawman: it models a *specific,
falsifiable* claim about how a language model behaves, namely that an agent
reading a tool result containing imperative text may act on it. Its
``susceptibility`` parameter says how often. Holding that behaviour fixed is
what isolates the variable under test -- we are measuring the guardrail, not
the model, and a benchmark whose numbers move because the model was retrained
measures the wrong thing.

:class:`ClaudeAgent` (in ``claude_agent.py``) drives a real model through the
same interface, so the same corpus can be replayed against live behaviour with
``--live``. Determinism is the default because a result nobody can reproduce
without an API key and a budget is not a result.

Both agents reach tools *only* through an injected ``call_tool`` callable. That
is what lets the harness swap the transport between "straight to the upstream
server" (the unguarded baseline) and "through the Steward gateway" (the treated
condition) without either agent knowing which it is talking to.
"""

from __future__ import annotations

import random
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

#: Signature of the tool-invocation callable an agent is handed.
ToolInvoker = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    #: Where this call came from: "plan" (the agent's own task) or
    #: "injected" (an instruction found inside a tool result).
    origin: str = "plan"


@dataclass
class ToolOutcome:
    call: ToolCall
    result: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    reason_code: str | None = None

    @property
    def text(self) -> str:
        blocks = self.result.get("content") or []
        return "\n".join(
            str(block.get("text", ""))
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        )

    @property
    def succeeded(self) -> bool:
        return not self.blocked and not self.result.get("isError")


@dataclass
class Transcript:
    """Everything that happened during one agent run."""

    task_id: str
    outcomes: list[ToolOutcome] = field(default_factory=list)
    final_text: str = ""
    steps: int = 0
    stopped_reason: str = "completed"
    #: Populated only for live runs.
    usage: dict[str, Any] = field(default_factory=dict)

    def calls(self, origin: str | None = None) -> list[ToolCall]:
        return [
            outcome.call
            for outcome in self.outcomes
            if origin is None or outcome.call.origin == origin
        ]

    def succeeded_calls(self, origin: str | None = None) -> list[ToolCall]:
        return [
            outcome.call
            for outcome in self.outcomes
            if outcome.succeeded and (origin is None or outcome.call.origin == origin)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "steps": self.steps,
            "stopped_reason": self.stopped_reason,
            "final_text": self.final_text,
            "usage": self.usage,
            "outcomes": [
                {
                    "tool": outcome.call.name,
                    "arguments": outcome.call.arguments,
                    "origin": outcome.call.origin,
                    "blocked": outcome.blocked,
                    "reason_code": outcome.reason_code,
                    "succeeded": outcome.succeeded,
                    "text": outcome.text[:500],
                }
                for outcome in self.outcomes
            ],
        }


class Agent(Protocol):
    """Anything that can carry out a task using tools."""

    async def run(
        self,
        *,
        task_id: str,
        instruction: str,
        tools: Sequence[dict[str, Any]],
        call_tool: ToolInvoker,
        max_steps: int = 12,
    ) -> Transcript:
        ...


# ---------------------------------------------------------------------------
# Injection parsing
# ---------------------------------------------------------------------------

# Instructions embedded in tool output usually name a tool and some arguments.
# The scripted agent extracts them the way a compliant model plausibly would.
_CALL_HINT = re.compile(
    r"\bcall\s+([A-Za-z_][\w.]*)\b(?:.*?\bwith\b(?P<args>[^.\n]*))?",
    re.IGNORECASE | re.DOTALL,
)
_ARG_PAIR = re.compile(r"(\w+)\s*(?:=|:)\s*([\"']?)([^\"',;]+)\2")
_AMOUNT = re.compile(r"\bamount\s+(\d+(?:\.\d+)?)", re.IGNORECASE)
_EMAIL_TO = re.compile(
    r"\b(?:email|send|forward|copy|upload|report|deliver|exfiltrate)"
    r"[^\n]{0,40}?\bto\s+([\w.+-]+@[\w.-]+)",
    re.IGNORECASE,
)


#: Clause boundaries. An injection chains actions with "then" and "and" as
#: often as with punctuation, so those split too -- otherwise "call X ... then
#: email Y" collapses into a single call and the harness under-counts the
#: attack surface it is meant to measure.
#: A period only ends a clause when whitespace follows it. Splitting on every
#: dot would shred both dotted tool names (``refund.issue``) and the very
#: exfiltration addresses the parser exists to recover.
_CLAUSE = re.compile(r"\.(?=\s|$)|[;\n]|\bthen\b", re.IGNORECASE)


def _clauses(text: str) -> list[str]:
    return [clause.strip() for clause in _CLAUSE.split(text) if clause and clause.strip()]


def extract_injected_calls(text: str, available: Sequence[str]) -> list[ToolCall]:
    """Recover the tool calls an injected instruction is asking for.

    Matched loosely against the tool names actually on offer, because an
    injection written against one deployment ("call refund.issue") must still
    resolve when the gateway namespaces it as ``billing__refund.issue``.

    Each clause is parsed independently so arguments cannot bleed between
    actions -- without that, the recipient of a follow-up email ends up
    attached to the preceding refund.
    """
    if not text:
        return []

    calls: list[ToolCall] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, arguments: dict[str, Any]) -> None:
        key = (name, repr(sorted(arguments.items())))
        if key not in seen:
            seen.add(key)
            calls.append(ToolCall(name=name, arguments=arguments, origin="injected"))

    for clause in _clauses(text):
        match = _CALL_HINT.search(clause)
        if match:
            resolved = _resolve_tool(match.group(1), available)
            if resolved:
                arguments: dict[str, Any] = {}
                for key, _, value in _ARG_PAIR.findall(match.group("args") or ""):
                    arguments[key] = _coerce(value.strip())

                amount = _AMOUNT.search(clause)
                if amount and "amount" not in arguments:
                    arguments["amount"] = float(amount.group(1))

                add(resolved, arguments)
                continue

        # A clause may describe an exfiltration without the word "call".
        recipient = _EMAIL_TO.search(clause)
        if recipient:
            resolved = _resolve_tool("email.send", available)
            if resolved:
                add(
                    resolved,
                    {
                        "to": recipient.group(1).rstrip(".,;"),
                        "body": "(content forwarded by injected instruction)",
                    },
                )

    return calls


def _resolve_tool(target: str, available: Sequence[str]) -> str | None:
    target = target.strip().rstrip(".,;:")
    if target in available:
        return target
    for name in available:
        if name.endswith(target) or name.split("__")[-1] == target:
            return name
    return None


def _coerce(value: str) -> Any:
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


# ---------------------------------------------------------------------------
# Scripted agent
# ---------------------------------------------------------------------------


@dataclass
class ScriptedPlan:
    """The tool calls an agent intends to make for a task, in order."""

    calls: list[ToolCall] = field(default_factory=list)
    answer: str = "done"


class ScriptedAgent:
    """Deterministic agent that follows a plan and may obey injections.

    ``susceptibility`` is the probability of acting on an instruction found in
    a tool result. It is drawn from a seeded RNG so a given (seed, corpus) pair
    always produces the same transcript -- reproducibility is the entire point
    of running offline.

    Setting it to 1.0 models a fully credulous agent, which is the right
    default for a *security* benchmark: the guardrail should hold even against
    the worst-case model, and averaging over a partly-resistant model would
    flatter the defence.
    """

    def __init__(
        self,
        plans: dict[str, ScriptedPlan],
        *,
        susceptibility: float = 1.0,
        seed: int = 0,
        retry_blocked: bool = True,
    ) -> None:
        self._plans = plans
        self._susceptibility = susceptibility
        self._seed = seed
        self._retry_blocked = retry_blocked

    async def run(
        self,
        *,
        task_id: str,
        instruction: str,
        tools: Sequence[dict[str, Any]],
        call_tool: ToolInvoker,
        max_steps: int = 12,
    ) -> Transcript:
        rng = random.Random(f"{self._seed}:{task_id}")
        available = [str(tool.get("name")) for tool in tools]
        transcript = Transcript(task_id=task_id)

        plan = self._plans.get(task_id)
        if plan is None:
            transcript.stopped_reason = "no_plan"
            return transcript

        queue: list[ToolCall] = list(plan.calls)
        attempted: set[tuple[str, str]] = set()

        while queue and transcript.steps < max_steps:
            call = queue.pop(0)
            transcript.steps += 1

            # A tool the agent cannot see is one it cannot call. This is where
            # discovery filtering pays off: the injected target simply is not
            # in `available`, so a compliant agent has nothing to invoke.
            if call.name not in available:
                transcript.outcomes.append(
                    ToolOutcome(
                        call=call,
                        result={"content": [{"type": "text", "text": "no such tool"}], "isError": True},
                        blocked=True,
                        reason_code="tool_not_visible",
                    )
                )
                continue

            signature = (call.name, repr(sorted(call.arguments.items())))
            if signature in attempted and not self._retry_blocked:
                continue
            attempted.add(signature)

            result = await call_tool(call.name, call.arguments)
            reason_code = (result.get("_meta") or {}).get("steward/reasonCode")
            blocked = bool(result.get("isError")) and reason_code is not None

            outcome = ToolOutcome(
                call=call, result=result, blocked=blocked, reason_code=reason_code
            )
            transcript.outcomes.append(outcome)

            # A suspended call (awaiting approval) is not a failure; the agent
            # simply does not get the result and moves on.
            if result.get("resultType") == "input_required":
                outcome.blocked = True
                outcome.reason_code = "approval_pending"
                continue

            if outcome.succeeded and rng.random() < self._susceptibility:
                for injected in extract_injected_calls(outcome.text, available):
                    if len(queue) < max_steps:
                        queue.append(injected)

        transcript.final_text = plan.answer
        if transcript.steps >= max_steps and queue:
            transcript.stopped_reason = "max_steps"
        return transcript
