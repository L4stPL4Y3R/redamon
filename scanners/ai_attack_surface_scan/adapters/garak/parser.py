"""Parse garak's report.jsonl into per-probe-family results (TOOL_API.md §3-4).

We key on the stable `eval` rows (probe, detector, passed, fails,
total_evaluated). ASR(probe, detector) = fails / total_evaluated; per-family ASR
= the worst (max) detector. The version-sensitive attempt rows are not needed
for ASR (only for transcript drill-down).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .owasp_map import family_of


@dataclass
class DetectorResult:
    probe: str
    detector: str
    asr: float
    hits: int          # fails = attack succeeded
    trials: int        # total_evaluated


@dataclass
class FamilyResult:
    family: str
    asr: float                       # max over the family's (probe, detector)
    trials: int                      # trials of the representative detector
    hits: int
    top_probe: str
    top_detector: str
    detectors: list[DetectorResult] = field(default_factory=list)


@dataclass
class GarakReport:
    families: list[FamilyResult]
    garak_version: str | None = None
    seed: int | None = None


def _find_key(obj, key):
    """Best-effort recursive search for a scalar key (version/seed live in the
    init/start_run entry whose exact nesting varies by garak version)."""
    if isinstance(obj, dict):
        if key in obj and not isinstance(obj[key], (dict, list)):
            return obj[key]
        for v in obj.values():
            found = _find_key(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_key(v, key)
            if found is not None:
                return found
    return None


def parse_report(path: str) -> GarakReport:
    eval_rows: list[tuple[str, str, int, int]] = []
    version = None
    seed = None

    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = obj.get("entry_type")
            if et == "eval":
                probe = obj.get("probe", "") or ""
                detector = obj.get("detector", "") or ""
                fails = int(obj.get("fails", 0) or 0)
                total = int(obj.get("total_evaluated", 0) or 0)
                eval_rows.append((probe, detector, fails, total))
            elif et in ("start_run setup", "init", "start_run", "config", "setup"):
                # garak 0.15.1: 'init' carries top-level garak_version; the seed
                # lives under the FLAT dotted key 'run.seed' in 'start_run setup'.
                if version is None:
                    version = (obj.get("garak_version") or obj.get("_config.version")
                               or _find_key(obj, "garak_version"))
                if seed is None:
                    s = obj.get("run.seed")
                    if s is None and isinstance(obj.get("run"), dict):
                        s = obj["run"].get("seed")
                    seed = s

    # Group eval rows by probe family.
    by_family: dict[str, list[DetectorResult]] = {}
    for probe, detector, fails, total in eval_rows:
        asr = (fails / total) if total > 0 else 0.0
        by_family.setdefault(family_of(probe), []).append(
            DetectorResult(probe=probe, detector=detector, asr=asr, hits=fails, trials=total)
        )

    families: list[FamilyResult] = []
    for fam, rows in by_family.items():
        top = max(rows, key=lambda r: r.asr)
        families.append(FamilyResult(
            family=fam, asr=top.asr, trials=top.trials, hits=top.hits,
            top_probe=top.probe, top_detector=top.detector, detectors=rows,
        ))

    families.sort(key=lambda f: f.asr, reverse=True)
    return GarakReport(families=families, garak_version=version, seed=seed)
