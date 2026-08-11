"""Parse pyrit_run.py's results JSON into a per-attack ASR (TOOL_API.md §4)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class PyritResult:
    objective: str
    outcome: str          # SUCCESS / FAILURE / UNDETERMINED / ERROR
    turns_used: int | None
    outcome_reason: str | None


@dataclass
class PyritReport:
    attack: str
    pyrit_version: str | None
    seed: int | None
    results: list[PyritResult] = field(default_factory=list)

    @property
    def successes(self) -> int:
        return sum(1 for r in self.results if r.outcome == "SUCCESS")

    @property
    def scored(self) -> int:
        # objectives that produced a verdict (exclude ERROR runs from the denominator)
        return sum(1 for r in self.results if r.outcome != "ERROR")

    @property
    def asr(self) -> float:
        return (self.successes / self.scored) if self.scored else 0.0


def parse_report(path: str) -> PyritReport:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    results = [
        PyritResult(
            objective=r.get("objective", ""),
            outcome=str(r.get("outcome", "UNDETERMINED")).upper(),
            turns_used=r.get("turns_used"),
            outcome_reason=r.get("outcome_reason"),
        )
        for r in data.get("results", [])
    ]
    return PyritReport(
        attack=data.get("attack", "crescendo"),
        pyrit_version=data.get("pyrit_version"),
        seed=data.get("seed"),
        results=results,
    )
