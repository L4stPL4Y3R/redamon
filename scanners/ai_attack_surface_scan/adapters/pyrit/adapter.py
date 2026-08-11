"""PyRIT adapter: invoke pyrit_run.py (in venv-pyrit) -> parse -> Findings.

The runner runs in the isolated pyrit venv; this adapter runs in the base
interpreter (it builds the normalized Finding, which the spine writes to Neo4j).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from normalizer import Finding
from proc import run_streamed

from .objectives import DEFAULT_ATTACKS, attack_meta
from .parser import parse_report

logger = logging.getLogger("ai-attack-surface")

# pyrit lives in its own venv (datasets pin conflicts with garak).
PYRIT_PYTHON = os.environ.get("PYRIT_PYTHON", "python")
RUNNER = os.path.join(os.path.dirname(__file__), "pyrit_run.py")
DEFAULT_TIMEOUT = int(os.environ.get("AI_ATTACK_PYRIT_TIMEOUT", "36000"))
DEFAULT_SEED = int(os.environ.get("AI_ATTACK_PYRIT_SEED", "0"))


def _severity(asr: float) -> str:
    if asr >= 0.5:
        return "high"
    if asr >= 0.3:
        return "medium"
    if asr > 0:
        return "low"
    return "info"


def run(target, bounds, output_dir: str, run_id: str,
        judge_base_url: str | None = None, attacks: list[str] | None = None,
        objective: str | None = None,
        target_model: str | None = None, target_purpose: str | None = None,
        api_key: str | None = None,
        auth_header: str | None = None, auth_scheme: str | None = None) -> list[Finding]:
    """Run the selected PyRIT attacks against one target. Failure-soft.

    PyRIT needs the local Ollama as its attacker+judge — without judge_base_url
    it cannot run, so it returns [] with a warning (no degraded mode).
    """
    if not judge_base_url:
        logger.warning("PyRIT needs a local judge/attacker (judge_base_url); skipping")
        return []

    attacks = attacks or DEFAULT_ATTACKS
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ids = getattr(target, "ai_model_ids", None)
    # recon stores a list; guard against a bare string (ids[0] would slice a char).
    first_id = ids[0] if isinstance(ids, list) and ids else (ids if isinstance(ids, str) else None)
    model = target_model or first_id \
        or getattr(target, "ai_model_family_guess", None) or "default"

    findings: list[Finding] = []
    threshold = float(bounds.asr_threshold)

    # A custom objective (from the UI) overrides every attack's built-in goals,
    # so the operator can target a specific harmful outcome for this app.
    custom = (objective or "").strip()
    for attack in attacks:
        meta = attack_meta(attack)
        objectives = [custom] if custom else meta["objectives"]
        if not objectives:
            continue
        cfg = {
            "baseurl": getattr(target, "baseurl", ""),
            "path": getattr(target, "path", "/"),
            "method": getattr(target, "method", "POST"),
            "interface_type": getattr(target, "ai_interface_type", None),
            "model": model,
            "auth_header": auth_header or "",
            "auth_scheme": auth_scheme or "",
            "api_key": api_key or "",
            "judge_base_url": judge_base_url,
            "judge_model": bounds.judge_model or "qwen2.5:7b",
            "attack": attack,
            "objectives": objectives,
            # App context for the adversarial chat (consumed by pyrit_run when set);
            # lets the attacker model frame its turns for this specific target.
            "target_purpose": (target_purpose or "").strip(),
            "max_turns": int(bounds.max_turns),
            "max_backtracks": 5,
            "seed": int(bounds.seed) if getattr(bounds, "seed", None) is not None else DEFAULT_SEED,
            "out": str(out / f"pyrit_{attack}.json"),
        }
        cfg_path = out / f"pyrit_{attack}_config.json"
        cfg_path.write_text(json.dumps(cfg, indent=2))

        rc, tail = _invoke(cfg_path, timeout=int(getattr(bounds, "timeout", 0) or DEFAULT_TIMEOUT))
        if not os.path.exists(cfg["out"]):
            logger.warning(f"PyRIT {attack} produced no results (rc={rc}); tail:\n{tail}")
            continue

        report = parse_report(cfg["out"])
        logger.info(f"pyrit {attack}: ASR={report.asr:.2f} ({report.successes}/{report.scored})")
        if report.asr < threshold:
            continue
        won = next((r for r in report.results if r.outcome == "SUCCESS"), None)
        findings.append(Finding(
            source="pyrit",
            chip=meta["chip"],
            name=f"PyRIT {attack}: ASR {report.asr:.0%}",
            baseurl=getattr(target, "baseurl", "") or "",
            path=getattr(target, "path", "/") or "/",
            severity=_severity(report.asr),
            description=(f"PyRIT {attack} achieved {report.successes}/{report.scored} "
                        f"objective(s) via bounded multi-turn (max_turns={bounds.max_turns})"),
            ai_owasp_llm_id=meta["owasp"],
            ai_asr=round(report.asr, 4),
            ai_trials=report.scored,
            ai_oracle_kind="judge_llm",
            ai_payload_class=f"pyrit-{attack.replace('_', '-')}",
            ai_transcript_ref=cfg["out"],
            ai_probe_pack_version=f"pyrit/{report.pyrit_version or '0.14.0'}",
            evidence=(f"objective '{won.objective}' in {won.turns_used} turn(s)" if won
                      else f"{report.successes}/{report.scored} objectives"),
        ))

    logger.info(f"pyrit: {len(findings)} finding(s) above ASR>={threshold}")
    return findings


def _invoke(cfg_path, timeout=DEFAULT_TIMEOUT):
    cmd = [PYRIT_PYTHON, RUNNER, str(cfg_path)]
    logger.info(f"Running PyRIT: {' '.join(cmd)}")
    return run_streamed(cmd, timeout=timeout, tag="pyrit")
