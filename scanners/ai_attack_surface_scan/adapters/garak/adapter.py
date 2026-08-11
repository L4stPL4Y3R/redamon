"""garak adapter orchestration: build REST config -> run garak -> parse -> Findings.

Public entry point used by main.py Phase 3 when tool == "garak".
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from normalizer import Finding

from .owasp_map import map_family
from .parser import parse_report
from .rest_config import build_rest_config
from .runner import run_garak_scan

logger = logging.getLogger("ai-attack-surface")

DEFAULT_PROBES = ["promptinject", "dan", "encoding", "leakreplay"]
DEFAULT_SEED = int(os.environ.get("AI_ATTACK_GARAK_SEED", "0"))
# Hard cap so a single garak run can't hang the job forever.
DEFAULT_TIMEOUT = int(os.environ.get("AI_ATTACK_GARAK_TIMEOUT", "36000"))


def _severity(asr: float) -> str:
    if asr >= 0.5:
        return "high"
    if asr >= 0.3:
        return "medium"
    if asr > 0:
        return "low"
    return "info"


def run(target, bounds, output_dir: str, run_id: str,
        judge_base_url: str | None = None, probes: list[str] | None = None,
        target_model: str | None = None, api_key: str | None = None,
        auth_header: str | None = None, auth_scheme: str | None = None) -> list[Finding]:
    """Run garak against one target and return findings above the ASR threshold.

    Failure-soft: if garak can't run or produces no report, returns [] (the job
    still completes), logging the reason.
    """
    probes = probes or DEFAULT_PROBES
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    config = build_rest_config(
        target, model=target_model,
        auth_header=auth_header, auth_scheme=auth_scheme,
    )
    config_path = out / "garak_rest.json"
    config_path.write_text(json.dumps(config, indent=2))
    logger.info(f"garak REST config -> {config_path}")

    report_prefix = out / "garak_run"
    report_path, rc, tail = run_garak_scan(
        config_path=str(config_path),
        probes=probes,
        generations=max(1, int(bounds.trials)),
        # Honor an explicit seed of 0 (don't let `0 or DEFAULT` override it).
        seed=int(bounds.seed) if getattr(bounds, "seed", None) is not None else DEFAULT_SEED,
        report_prefix=str(report_prefix),
        judge_base_url=judge_base_url,
        api_key=api_key,
        timeout=int(getattr(bounds, "timeout", 0) or DEFAULT_TIMEOUT),
        parallel_attempts=max(1, int(getattr(bounds, "parallelism", 2) or 2)),
    )

    if not report_path:
        logger.warning(f"garak produced no report (rc={rc}); tail:\n{tail}")
        return []

    report = parse_report(report_path)
    threshold = float(bounds.asr_threshold)
    version = report.garak_version or "0.15.1"

    findings: list[Finding] = []
    for fam in report.families:
        logger.info(f"garak family {fam.family}: ASR={fam.asr:.2f} "
                    f"({fam.hits}/{fam.trials}) via {fam.top_probe}/{fam.top_detector}")
        if fam.asr < threshold:
            continue
        owasp, chip, oracle = map_family(fam.family)
        findings.append(Finding(
            source="garak",
            chip=chip,
            name=f"garak {fam.family}: ASR {fam.asr:.0%}",
            baseurl=getattr(target, "baseurl", "") or "",
            path=getattr(target, "path", "/") or "/",
            severity=_severity(fam.asr),
            description=(f"garak probe family '{fam.family}' succeeded on "
                         f"{fam.hits}/{fam.trials} outputs "
                         f"(detector {fam.top_detector})"),
            ai_owasp_llm_id=owasp,
            ai_asr=round(fam.asr, 4),
            ai_trials=fam.trials,
            ai_oracle_kind=oracle,
            ai_payload_class=f"garak-{fam.family}",
            ai_transcript_ref=report_path,
            ai_probe_pack_version=f"garak/{version}",
            evidence=f"{fam.top_probe}/{fam.top_detector} hits={fam.hits}/{fam.trials}",
        ))

    logger.info(f"garak: {len(findings)} finding(s) above ASR>={threshold}")
    return findings
