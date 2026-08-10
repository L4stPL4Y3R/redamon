"""Parse giskard_run.py's results JSON into issues (TOOL_API.md §4)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class GiskardIssue:
    detector: str
    description: str
    severity: str        # major / medium / minor
    num_examples: int


@dataclass
class GiskardReport:
    giskard_version: str | None
    detectors: list[str]
    issues: list[GiskardIssue] = field(default_factory=list)


def parse_report(path: str) -> GiskardReport:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    issues = [
        GiskardIssue(
            detector=i.get("detector", "") or "",
            description=i.get("description", "") or "",
            severity=str(i.get("severity", "minor")).lower(),
            num_examples=int(i.get("num_examples", 0) or 0),
        )
        for i in data.get("issues", [])
    ]
    return GiskardReport(
        giskard_version=data.get("giskard_version"),
        detectors=data.get("detectors", []) or [],
        issues=issues,
    )
