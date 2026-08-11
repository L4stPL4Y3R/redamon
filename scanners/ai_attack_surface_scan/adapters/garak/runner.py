"""Invoke garak as a subprocess (TOOL_API.md §1) and locate its report.jsonl."""
from __future__ import annotations

import glob
import logging
import os
import re
from pathlib import Path

from proc import run_streamed

logger = logging.getLogger("ai-attack-surface")

# garak's fatal message when a selected family has no active sub-probes, e.g.
#   "all probes in 'doctor,donotanswer' are marked inactive; select one ..."
_INACTIVE_FAMILIES = re.compile(r"all probes in '([^']+)' are marked inactive")

# garak lives in its own venv (its datasets pin conflicts with pyrit). Invoke it
# via that interpreter; fall back to "python" for local dev where it's on PATH.
GARAK_PYTHON = os.environ.get("GARAK_PYTHON", "python")


def run_garak_scan(
    config_path: str,
    probes: list[str],
    generations: int,
    seed: int,
    report_prefix: str,
    judge_base_url: str | None = None,
    api_key: str | None = None,
    timeout: int | None = None,
    parallel_attempts: int = 2,
):
    """Run garak with the REST generator. Returns (report_path|None, returncode,
    tail_of_output). Never raises on a non-zero garak exit — the caller decides.

    `parallel_attempts` is how many requests garak fires at the target at once;
    keep it low for a slow/CPU target so its queue doesn't back up past the
    request timeout (which 500s and can crash the run)."""
    # Egress guard: never inherit a hosted OPENAI_API_KEY (parity with giskard +
    # promptfoo). A stray key would let garak's judge-based detectors egress to
    # api.openai.com. We FORCE the local Ollama endpoint when a judge is set.
    env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    if api_key:
        env["REST_API_KEY"] = api_key
    if judge_base_url:
        base = judge_base_url.rstrip("/")
        env["OPENAI_API_BASE"] = base + "/v1"
        env["OPENAI_BASE_URL"] = base + "/v1"
        env["OPENAI_API_KEY"] = "ollama-local"

    # garak treats a probe family whose sub-probes are ALL marked inactive (e.g.
    # doctor, donotanswer) as a fatal error and refuses to run ANY probe -- one
    # such family in the selection aborts the whole scan in <1s. Detect that,
    # drop the offending families, and retry with the rest so a single bad
    # checkbox can't nuke an otherwise-valid run.
    probes = list(probes)
    rc, tail = 0, ""
    for _ in range(2):
        cmd = [
            GARAK_PYTHON, "-m", "garak",
            "--model_type", "rest",
            "--generator_option_file", str(config_path),
            "--probes", ",".join(probes),
            "--generations", str(generations),
            "--seed", str(seed),
            "--report_prefix", str(report_prefix),
            "--parallel_attempts", str(max(1, int(parallel_attempts))),
        ]
        logger.info(f"Running garak: {' '.join(cmd)}")
        # Stream garak's progress live (per-probe / tqdm) to the container log + UI.
        rc, tail = run_streamed(cmd, env=env, timeout=timeout, tag="garak")

        report_path = _locate_report(report_prefix)
        if report_path is not None:
            return report_path, rc, tail

        inactive = _INACTIVE_FAMILIES.search(tail or "")
        if not inactive:
            break
        dropped = {p.strip() for p in inactive.group(1).split(",") if p.strip()}
        kept = [p for p in probes if p not in dropped]
        logger.warning(
            f"garak: probe families {sorted(dropped)} are inactive by default and "
            f"abort the run; dropping them and retrying with {kept or '(none left)'}")
        if not kept or kept == probes:
            break
        probes = kept

    logger.warning(f"garak produced no report.jsonl for prefix {report_prefix} (rc={rc})")
    return None, rc, tail


def _locate_report(report_prefix: str) -> str | None:
    """garak writes <prefix>.report.jsonl; fall back to a glob in the dir."""
    candidate = f"{report_prefix}.report.jsonl"
    if os.path.exists(candidate):
        return candidate
    matches = sorted(glob.glob(f"{Path(report_prefix).parent}/*.report.jsonl"))
    return matches[-1] if matches else None
