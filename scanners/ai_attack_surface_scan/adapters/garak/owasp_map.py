"""garak probe-family -> OWASP-LLM id + attack chip + oracle kind (TOOL_API.md §4).

Keyed on the probe *family* (the part before the first dot of garak's
probe_classname, e.g. "promptinject" from "promptinject.HijackHateHumans").
"""
from __future__ import annotations

# family -> (owasp_llm_id, chip, default_oracle_kind). Covers garak 0.15.1's full
# probe-family catalog so every selectable family is classified; map_family()
# still falls back to _DEFAULT for any family not listed (e.g. a future garak rev).
PROBE_FAMILY_MAP: dict[str, tuple[str, str, str]] = {
    # --- MVP set ---
    "promptinject": ("LLM01", "prompt-injection", "classifier"),
    "dan":          ("LLM01", "jailbreak", "classifier"),
    "encoding":     ("LLM01", "encoding-bypass", "classifier"),
    "leakreplay":   ("LLM02", "data-disclosure", "contains"),
    # --- Prompt / indirect injection ---
    "latentinjection": ("LLM01", "prompt-injection", "classifier"),
    "goodside":     ("LLM01", "prompt-injection", "classifier"),
    "agent_breaker": ("LLM01", "prompt-injection", "classifier"),
    "xss":          ("LLM01", "prompt-injection", "classifier"),  # legacy alias of web_injection
    # --- Jailbreaks ---
    "doctor":       ("LLM01", "jailbreak", "classifier"),
    "grandma":      ("LLM01", "jailbreak", "classifier"),
    "dra":          ("LLM01", "jailbreak", "classifier"),
    "fitd":         ("LLM01", "jailbreak", "classifier"),
    "phrasing":     ("LLM01", "jailbreak", "classifier"),
    "suffix":       ("LLM01", "jailbreak", "classifier"),
    "tap":          ("LLM01", "jailbreak", "judge_llm"),
    "goat":         ("LLM01", "jailbreak", "judge_llm"),
    "glitch":       ("LLM01", "jailbreak", "classifier"),
    "sata":         ("LLM01", "jailbreak", "classifier"),
    "audio":        ("LLM01", "jailbreak", "classifier"),
    "visual_jailbreak": ("LLM01", "jailbreak", "classifier"),
    # --- System prompt leakage ---
    "sysprompt_extraction": ("LLM07", "system-prompt-leak", "contains"),
    # --- Sensitive data disclosure ---
    "apikey":       ("LLM02", "data-disclosure", "contains"),
    "propile":      ("LLM02", "data-disclosure", "contains"),
    "divergence":   ("LLM02", "data-disclosure", "classifier"),
    # --- Encoding / smuggling ---
    "smuggling":    ("LLM01", "encoding-bypass", "classifier"),
    # --- Toxicity / harmful content ---
    "realtoxicityprompts": ("safety", "toxicity", "classifier"),
    "lmrc":         ("safety", "toxicity", "classifier"),
    "continuation": ("safety", "toxicity", "classifier"),
    "donotanswer":  ("safety", "toxicity", "classifier"),
    "atkgen":       ("safety", "toxicity", "classifier"),
    "topic":        ("safety", "toxicity", "classifier"),
    # --- Harmful generation ---
    "malwaregen":   ("safety", "harmful-generation", "judge_llm"),
    "exploitation": ("LLM05", "harmful-generation", "judge_llm"),
    "av_spam_scanning": ("safety", "harmful-generation", "contains"),
    "fileformats":  ("safety", "harmful-generation", "classifier"),
    # --- Insecure output handling ---
    "ansiescape":   ("LLM05", "insecure-output", "classifier"),
    "web_injection": ("LLM05", "insecure-output", "classifier"),
    "badchars":     ("LLM05", "insecure-output", "classifier"),
    # --- Supply chain ---
    "packagehallucination": ("LLM03", "supply-chain", "classifier"),
    # --- Misinformation / hallucination ---
    "misleading":   ("LLM09", "hallucination", "classifier"),
    "snowball":     ("LLM09", "hallucination", "classifier"),
}

_DEFAULT = ("LLM01", "prompt-injection", "classifier")


def family_of(probe_classname: str) -> str:
    return (probe_classname or "").split(".")[0]


def map_family(family: str) -> tuple[str, str, str]:
    """Return (owasp_llm_id, chip, oracle_kind) for a probe family."""
    return PROBE_FAMILY_MAP.get(family, _DEFAULT)
