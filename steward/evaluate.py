import json
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .policy import evaluate
from .schemas import CheckRequest


async def run_scenarios(session: AsyncSession, path: str | Path) -> dict[str, Any]:
    scenarios = json.loads(Path(path).read_text(encoding="utf-8"))
    results = []
    for scenario in scenarios:
        decision = await evaluate(session, CheckRequest(**scenario["request"]))
        passed = decision.allowed == scenario["expected_allowed"]
        results.append({"name": scenario["name"], "passed": passed,
                        "expected_allowed": scenario["expected_allowed"],
                        "actual_allowed": decision.allowed, "reason": decision.reason})
    return {"total": len(results), "passed": sum(x["passed"] for x in results),
            "failed": sum(not x["passed"] for x in results), "results": results}


def main() -> None:
    raise SystemExit("Use run_scenarios from an application context")
