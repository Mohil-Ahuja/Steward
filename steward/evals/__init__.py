"""Evaluation pipeline: corpus, conditions, metrics, judges, reporting."""

from .baselines import CONDITIONS_BY_NAME, Condition, build_conditions, least_privilege_policies
from .corpus import Scenario, build_corpus, corpus_stats, load_corpus, read_jsonl, write_jsonl
from .judge import ClaudeJudge, Judge, RubricJudge
from .metrics import (
    CallJudgement,
    ConditionReport,
    ConfusionMatrix,
    Interval,
    ScenarioOutcome,
    bootstrap_interval,
    paired_difference,
    summarise,
)
from .report import to_json, to_markdown, write_reports
from .runner import EvalResult, RunConfig, run_evaluation, run_evaluation_sync, score

__all__ = [
    "CONDITIONS_BY_NAME",
    "CallJudgement",
    "ClaudeJudge",
    "Condition",
    "ConditionReport",
    "ConfusionMatrix",
    "EvalResult",
    "Interval",
    "Judge",
    "RubricJudge",
    "RunConfig",
    "Scenario",
    "ScenarioOutcome",
    "bootstrap_interval",
    "build_conditions",
    "build_corpus",
    "corpus_stats",
    "least_privilege_policies",
    "load_corpus",
    "paired_difference",
    "read_jsonl",
    "run_evaluation",
    "run_evaluation_sync",
    "score",
    "summarise",
    "to_json",
    "to_markdown",
    "write_jsonl",
    "write_reports",
]
