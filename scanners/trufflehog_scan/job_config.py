"""Run configuration for one TruffleHog job.

The orchestrator writes a JSON job file into the run directory and passes its
path via ``TRUFFLEHOG_JOB``; the container reads it and nothing else. This is the
whole contract across the dirty/clean boundary (12.3): config in through the job
file, findings out through the output JSON, credentials in through env. The
container does not fetch project settings over HTTP and holds no Neo4j
credentials, so a parser exploit in a malicious target image finds nothing.

Env fallbacks exist so the container can be driven directly while iterating:

    PROJECT_ID=x TRUFFLEHOG_JOB=/tmp/job.json python trufflehog_scan/main.py
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class JobConfig:
    project_id: str
    user_id: str = ""
    source: str = ""
    run_id: str = ""
    #: Source-specific fields, shape defined by the source registry. Never a secret.
    config: dict = field(default_factory=dict)
    #: Shared per-project TruffleHog options (A.1).
    common: dict = field(default_factory=dict)
    #: Scratch dir for pathfile materialisation and the GCP service-account blob.
    run_dir: str = "/tmp/trufflehog-run"
    #: Where the findings JSON is written. Empty => derived from project+source.
    output_file: str = ""

    @property
    def verification_enabled(self) -> bool:
        """Whether TruffleHog will actually call the owning APIs.

        Drives the ``unverified`` vs ``unvalidated`` distinction on every finding,
        so it has to be read from the same place that builds ``--no-verification``.
        """
        return not bool(self.common.get("skipVerification"))


def _default_output_file(project_id: str, source: str) -> str:
    out_dir = Path(__file__).parent / "output"
    return str(out_dir / f"trufflehog_{project_id}_{source}.json")


def load_job(env: Optional[dict] = None) -> JobConfig:
    """Build the JobConfig from the job file, falling back to env vars."""
    env = os.environ if env is None else env
    raw: dict = {}
    job_path = (env.get("TRUFFLEHOG_JOB") or "").strip()
    if job_path:
        with open(job_path) as fh:
            raw = json.load(fh) or {}

    project_id = str(raw.get("project_id") or env.get("PROJECT_ID") or "")
    source = str(raw.get("source") or env.get("TRUFFLEHOG_SOURCE") or "").replace("-", "_")
    job = JobConfig(
        project_id=project_id,
        user_id=str(raw.get("user_id") or env.get("USER_ID") or ""),
        source=source,
        run_id=str(raw.get("run_id") or source),
        config=raw.get("config") or {},
        common=raw.get("common") or {},
        run_dir=str(raw.get("run_dir") or env.get("TRUFFLEHOG_RUN_DIR") or "/tmp/trufflehog-run"),
        output_file=str(raw.get("output_file") or ""),
    )
    if not job.output_file:
        job.output_file = _default_output_file(project_id, source or "unknown")
    return job
