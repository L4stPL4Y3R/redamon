"""giskard adapter: invoke giskard_run.py (in venv-giskard) -> parse -> Findings.

giskard is a scan (issue present/absent), not trials — so each flagged issue
becomes one Finding (ai_asr=1.0, ai_trials=num_examples). Reuses the shared auth +
custom targets. The judge/embedding LLM is forced local (the egress fix lives in
the runner).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from normalizer import Finding
from proc import run_streamed

from .detectors import DEFAULT_DETECTORS, detector_meta
from .parser import parse_report

logger = logging.getLogger("ai-attack-surface")

GISKARD_PYTHON = os.environ.get("GISKARD_PYTHON", "python")
RUNNER = os.path.join(os.path.dirname(__file__), "giskard_run.py")
DEFAULT_TIMEOUT = int(os.environ.get("AI_ATTACK_GISKARD_TIMEOUT", "36000"))

_SEVERITY = {"major": "high", "medium": "medium", "minor": "low"}


def run(target, bounds, output_dir: str, run_id: str,
        judge_base_url: str | None = None, detectors: list[str] | None = None,
        target_model: str | None = None, target_purpose: str | None = None,
        api_key: str | None = None,
        auth_header: str | None = None, auth_scheme: str | None = None) -> list[Finding]:
    """Run giskard's LLM scan against one target. Failure-soft.

    Needs the local Ollama as its scan judge — without judge_base_url it returns
    [] with a warning (no degraded mode)."""
    if not judge_base_url:
        logger.warning("giskard needs a local scan judge (judge_base_url); skipping")
        return []

    detectors = detectors or DEFAULT_DETECTORS
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ids = getattr(target, "ai_model_ids", None)
    first_id = ids[0] if isinstance(ids, list) and ids else (ids if isinstance(ids, str) else None)
    model = target_model or first_id or getattr(target, "ai_model_family_guess", None) or "default"

    cfg = {
        "baseurl": getattr(target, "baseurl", ""),
        "path": getattr(target, "path", "/"),
        "interface_type": getattr(target, "ai_interface_type", None),
        "model": model,
        "auth_header": auth_header or "",
        "auth_scheme": auth_scheme or "",
        "api_key": api_key or "",
        "judge_base_url": judge_base_url,
        "judge_model": bounds.judge_model or "qwen2.5:7b",
        "detectors": detectors,
        # giskard generates its adversarial test set FROM the model description,
        # so a real app purpose markedly improves detection. Falls back generic.
        "description": (target_purpose or "").strip() or "A general-purpose LLM chat assistant.",
        "out": str(out / "giskard_report.json"),
    }
    cfg_path = out / "giskard_config.json"
    cfg_path.write_text(json.dumps(cfg, indent=2))

    rc, tail = _invoke(cfg_path, timeout=int(getattr(bounds, "timeout", 0) or DEFAULT_TIMEOUT))
    if not os.path.exists(cfg["out"]):
        logger.warning(f"giskard produced no report (rc={rc}); tail:\n{tail}")
        return []

    report = parse_report(cfg["out"])
    logger.info(f"giskard: {len(report.issues)} issue(s) across {report.detectors}")

    # Aggregate per detector: many issues from one detector share the same
    # payload_class+target, so they would dedup to one graph node anyway. Pick the
    # WORST severity (deterministic, vs. last-write-wins) and count the issues.
    from collections import defaultdict
    sev_rank = {"major": 3, "medium": 2, "minor": 1}
    by_detector: dict[str, list] = defaultdict(list)
    for issue in report.issues:
        by_detector[issue.detector].append(issue)

    findings: list[Finding] = []
    for detector, issues in by_detector.items():
        owasp, chip = detector_meta(detector)
        worst = max(issues, key=lambda i: sev_rank.get(i.severity, 0))
        # giskard's num_examples is often 0; fall back to the issue count so the
        # finding carries a meaningful "how many variants succeeded".
        trials = sum(i.num_examples for i in issues) or len(issues)
        findings.append(Finding(
            source="giskard",
            chip=chip,
            name=f"giskard {detector}: {worst.severity}",
            baseurl=getattr(target, "baseurl", "") or "",
            path=getattr(target, "path", "/") or "/",
            severity=_SEVERITY.get(worst.severity, "low"),
            description=worst.description or f"giskard {detector} flagged an issue",
            ai_owasp_llm_id=owasp,
            ai_asr=1.0,                       # giskard: issue present (binary), not trials
            ai_trials=trials,
            ai_oracle_kind="judge_llm",
            ai_payload_class=f"giskard-{detector}",
            ai_transcript_ref=cfg["out"],
            ai_probe_pack_version=f"giskard/{report.giskard_version or '2.19.1'}",
            evidence=f"{detector}: {len(issues)} issue(s) (worst: {worst.severity})",
        ))

    logger.info(f"giskard: {len(findings)} finding(s)")
    return findings


def _invoke(cfg_path, timeout=DEFAULT_TIMEOUT):
    cmd = [GISKARD_PYTHON, RUNNER, str(cfg_path)]
    logger.info(f"Running giskard: {' '.join(cmd)}")
    # Belt-and-suspenders egress guard: ensure no OpenAI key leaks into the run.
    env = {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY",)}
    return run_streamed(cmd, env=env, timeout=timeout, tag="giskard")
