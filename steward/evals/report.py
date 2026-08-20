"""Rendering evaluation results as Markdown and JSON."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .metrics import Interval
from .runner import EvalResult

HEADLINE_ORDER = ["no_guard", "blanket_grant", "steward_calltime", "steward_full"]


def _fmt(interval: Interval | None) -> str:
    return "n/a" if interval is None else interval.as_percent()


def _num(value: float) -> str:
    """Render a metric, showing an undefined ratio as a dash rather than nan.

    Precision is undefined for a condition that never blocks anything; "nan"
    in a results table reads as a bug in the harness rather than as the
    absence of a denominator.
    """
    import math

    return "-" if not math.isfinite(value) else f"{value:.3f}"


def _ordered(result: EvalResult) -> list[str]:
    known = [name for name in HEADLINE_ORDER if name in result.reports]
    extra = [name for name in result.reports if name not in HEADLINE_ORDER]
    return known + extra


def to_markdown(result: EvalResult) -> str:
    lines: list[str] = []
    add = lines.append

    add("# Steward evaluation report")
    add("")
    add(f"Generated {datetime.now(UTC).isoformat(timespec='seconds')}")
    add("")
    add(
        f"Corpus: **{result.corpus_size} scenarios**. "
        f"Agent: **{'live Claude' if result.config.get('live') else 'deterministic'}**. "
        f"Seed: `{result.config.get('seed')}`. "
        f"Injection susceptibility: `{result.config.get('susceptibility')}`."
    )
    add("")
    add(
        "Intervals are 95% bootstrap percentile intervals over scenarios "
        f"({result.config.get('bootstrap_resamples')} resamples)."
    )
    add("")

    # ---- headline table ------------------------------------------------
    add("## Headline results")
    add("")
    add(
        "| Condition | Attack success | Attack attempted | Task completion | Over-refusal |"
    )
    add("| --- | --- | --- | --- | --- |")
    for name in _ordered(result):
        report = result.reports[name]
        add(
            f"| `{name}` | {_fmt(report.attack_success_rate)} "
            f"| {_fmt(report.attack_attempt_rate)} "
            f"| {_fmt(report.task_completion_rate)} "
            f"| {_fmt(report.over_refusal_rate)} |"
        )
    add("")
    add(
        "*Attack success* is the fraction of adversarial scenarios in which a "
        "forbidden action completed; *attack attempted* is the fraction in "
        "which one was tried. The gap between them is what the guardrail "
        "intercepted. *Over-refusal* counts benign scenarios where legitimate "
        "work was refused -- the cost side of the trade."
    )
    add("")

    # ---- decision quality ----------------------------------------------
    add("## Decision quality")
    add("")
    add(
        "Per tool call, treating *should have been blocked* as the positive "
        "class."
    )
    add("")
    add("| Condition | Precision | Recall | F1 | TP | FP | FN | TN |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for name in _ordered(result):
        matrix = result.reports[name].confusion
        add(
            f"| `{name}` | {_num(matrix.precision)} | {_num(matrix.recall)} "
            f"| {_num(matrix.f1)} | {matrix.true_positive} | {matrix.false_positive} "
            f"| {matrix.false_negative} | {matrix.true_negative} |"
        )
    add("")
    add(
        "False negatives are attacks that got through. False positives are "
        "legitimate calls that were refused."
    )
    add("")

    # ---- per category ---------------------------------------------------
    add("## Attack success by category")
    add("")
    categories = sorted(
        {
            category
            for report in result.reports.values()
            for category, entry in report.by_category.items()
            if entry.get("is_attack")
        }
    )
    if categories:
        header = "| Category | n | " + " | ".join(f"`{n}`" for n in _ordered(result)) + " |"
        add(header)
        add("| --- | --- | " + " | ".join("---" for _ in _ordered(result)) + " |")
        for category in categories:
            counts = [
                result.reports[name].by_category.get(category, {})
                for name in _ordered(result)
            ]
            size = next((entry.get("n", 0) for entry in counts if entry), 0)
            cells = [
                f"{entry.get('attack_success_rate', float('nan')) * 100:.0f}%"
                if entry
                else "-"
                for entry in counts
            ]
            add(f"| {category} | {size} | " + " | ".join(cells) + " |")
        add("")

    add("## Task completion by benign category")
    add("")
    benign = sorted(
        {
            category
            for report in result.reports.values()
            for category, entry in report.by_category.items()
            if not entry.get("is_attack")
        }
    )
    if benign:
        add("| Category | n | " + " | ".join(f"`{n}`" for n in _ordered(result)) + " |")
        add("| --- | --- | " + " | ".join("---" for _ in _ordered(result)) + " |")
        for category in benign:
            counts = [
                result.reports[name].by_category.get(category, {})
                for name in _ordered(result)
            ]
            size = next((entry.get("n", 0) for entry in counts if entry), 0)
            cells = [
                f"{entry.get('task_completion_rate', float('nan')) * 100:.0f}%"
                if entry
                else "-"
                for entry in counts
            ]
            add(f"| {category} | {size} | " + " | ".join(cells) + " |")
        add("")

    # ---- why calls were refused ----------------------------------------
    add("## Refusal reasons")
    add("")
    add(
        "Which mechanism produced each block. A defence that never fires is "
        "not earning its complexity."
    )
    add("")
    for name in _ordered(result):
        codes = result.reports[name].by_reason_code
        if not codes:
            continue
        add(f"**`{name}`**")
        add("")
        for code, count in sorted(codes.items(), key=lambda item: -item[1]):
            add(f"- `{code}`: {count}")
        add("")

    # ---- judge ----------------------------------------------------------
    if any(report.judge_score for report in result.reports.values()):
        add("## Judged quality")
        add("")
        add("| Condition | Score |")
        add("| --- | --- |")
        for name in _ordered(result):
            report = result.reports[name]
            if report.judge_score:
                add(f"| `{name}` | {report.judge_score} |")
        add("")

    return "\n".join(lines)


def to_json(result: EvalResult) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "corpus_size": result.corpus_size,
        "config": result.config,
        "conditions": {
            name: report.to_dict() for name, report in result.reports.items()
        },
        "scenarios": {
            name: [
                {
                    "scenario_id": outcome.scenario_id,
                    "category": outcome.category,
                    "is_attack": outcome.is_attack,
                    "attack_attempted": outcome.attack_attempted,
                    "attack_succeeded": outcome.attack_succeeded,
                    "task_completed": outcome.task_completed,
                    "over_refused": outcome.over_refused,
                    "steps": outcome.steps,
                    "judge_score": outcome.judge_score,
                }
                for outcome in outcomes
            ]
            for name, outcomes in result.outcomes.items()
        },
    }


def write_reports(result: EvalResult, directory: str | Path) -> dict[str, Path]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    markdown_path = target / "report.md"
    json_path = target / "results.json"
    transcript_path = target / "transcripts.json"

    markdown_path.write_text(to_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(to_json(result), indent=2), encoding="utf-8")
    transcript_path.write_text(
        json.dumps(
            {
                condition: {
                    scenario_id: transcript.to_dict()
                    for scenario_id, transcript in transcripts.items()
                }
                for condition, transcripts in result.transcripts.items()
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return {"markdown": markdown_path, "json": json_path, "transcripts": transcript_path}
