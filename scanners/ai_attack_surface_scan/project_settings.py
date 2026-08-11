"""Default settings for the AI Attack Surface layer.

Surfaced through the standard multi-layer flow (Prisma -> recon defaults ->
/defaults -> frontend -> presets) in Step 3 (§5.4). The master profile defaults
OFF because it sends adversarial payloads; per-tool sub-toggles default ON once
the profile is enabled.
"""
from __future__ import annotations

DEFAULT_AI_ATTACK_SURFACE_SETTINGS: dict = {
    # Master profile gate — OFF by default (sends payloads, §5.4 / §9).
    "AI_ATTACK_SURFACE_ENABLED": False,

    # Per-tool sub-toggles (effective only when the profile is enabled).
    "AI_ATTACK_GARAK_ENABLED": True,
    "AI_ATTACK_PYRIT_ENABLED": True,
    "AI_ATTACK_GISKARD_ENABLED": True,
    "AI_ATTACK_PROMPTFOO_ENABLED": True,

    # Shared run bounds (§3 'Run bounds' block).
    "AI_ATTACK_TRIALS": 1,
    "AI_ATTACK_ASR_THRESHOLD": 0.3,
    "AI_ATTACK_MAX_TURNS": 4,
    "AI_ATTACK_JUDGE_MODEL": "qwen2.5:7b",

    # Hard guardrail floor (§10) — shown read-only in the UI as a floor.
    "AI_ATTACK_HARD_BLOCKED_CATEGORIES": ["csam", "cbrn", "bioweapon"],
}
