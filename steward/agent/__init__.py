"""Agent harness: deterministic (default) and live Claude implementations."""

from .harness import (
    Agent,
    ScriptedAgent,
    ScriptedPlan,
    ToolCall,
    ToolInvoker,
    ToolOutcome,
    Transcript,
    extract_injected_calls,
)

__all__ = [
    "Agent",
    "ScriptedAgent",
    "ScriptedPlan",
    "ToolCall",
    "ToolInvoker",
    "ToolOutcome",
    "Transcript",
    "extract_injected_calls",
    "load_claude_agent",
]


def load_claude_agent(**kwargs):
    """Import the live agent lazily so `anthropic` stays optional."""
    from .claude_agent import ClaudeAgent

    return ClaudeAgent(**kwargs)
