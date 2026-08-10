"""Shared spine piece 2 — safety / bounds / RoE / hard-guardrail floor (§6.2, §10).

One enforcement layer identical for every tool. Step 2 ships the structure and
the cheap invariants (sane bounds, RoE confirmation, the hard-blocked-categories
floor); the host-exclusion / time-window helpers and per-payload guardrail
classification land with the tool adapters.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("ai-attack-surface")


class SafetyError(Exception):
    """Raised when a run violates a safety invariant and must not proceed."""


def enforce(config) -> list[str]:
    """Validate a run against the shared safety invariants.

    Returns a list of non-fatal warnings. Raises SafetyError on a disqualifying
    condition (the run must not send any payload).
    """
    warnings: list[str] = []
    b = config.bounds

    if b.trials < 1:
        raise SafetyError(f"trials must be >= 1 (got {b.trials})")
    if not (0.0 <= b.asr_threshold <= 1.0):
        raise SafetyError(f"asr_threshold must be in [0,1] (got {b.asr_threshold})")
    if b.max_turns < 1:
        raise SafetyError(f"max_turns must be >= 1 (got {b.max_turns})")

    # The hard guardrail floor must always be present (§10): these categories are
    # blocked before any payload leaves the container, regardless of settings.
    if not b.hard_blocked_categories:
        raise SafetyError("hard-guardrail floor is empty; refusing to run")

    # A launch is a confirmed action (§10). A dry run is allowed to skip it.
    if not config.roe_confirmed and not config.dry_run:
        raise SafetyError("RoE not confirmed; a launch must be a confirmed action")

    if config.dry_run:
        warnings.append("dry-run: no payloads will be sent")
    if not b.judge_model:
        warnings.append("no judge model set; judge-based detectors will degrade to no-judge")

    logger.info(
        f"Safety check passed: trials={b.trials} asr>={b.asr_threshold} "
        f"floor={b.hard_blocked_categories} roe_confirmed={config.roe_confirmed}"
    )
    for w in warnings:
        logger.warning(f"Safety warning: {w}")
    return warnings


def is_hard_blocked(category: str, config) -> bool:
    """True if `category` is in the hard-guardrail floor (CSAM/CBRN/etc).

    Stub hook for the per-payload classification the tool adapters will call
    before any payload is emitted.
    """
    return (category or "").strip().lower() in {
        c.lower() for c in config.bounds.hard_blocked_categories
    }
