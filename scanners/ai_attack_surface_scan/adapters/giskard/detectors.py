"""giskard LLM detector tags -> OWASP-LLM id + chip (TOOL_API.md §3-4).

giskard's scan `only=[...]` filters by detector TAGS (not the registry names),
intersecting the registered tag set. The real LLM-detector tags (giskard 2.19.1):
  llm_prompt_injection       -> {prompt_injection, jailbreak, ...}
  llm_information_disclosure -> {information_disclosure, ...}
  llm_faithfulness           -> {faithfulness}
  llm_implausible_output     -> {hallucination, implausible_output, ...}
  llm_basic_sycophancy       -> {hallucination, sycophancy, misinformation}
  llm_output_formatting      -> {output_formatting}

So the config carries TAGS as the selection. The issue we get back reports a
detector_name; we map it to a chip by substring (robust to the exact format).
"""
from __future__ import annotations

# Semantic tags passed to giskard.scan(only=...). The security-relevant pair is
# the MVP default (LLM-judge based, no embedding model needed).
DEFAULT_DETECTORS = ["prompt_injection", "information_disclosure"]

# tag (giskard.scan only=...) -> (owasp, chip) for UI / catalog display.
# All verified against giskard 2.19.1's DetectorRegistry._tags.
TAG_MAP: dict[str, tuple[str, str]] = {
    "prompt_injection": ("LLM01", "prompt-injection"),
    "information_disclosure": ("LLM02", "data-disclosure"),
    "hallucination": ("LLM09", "hallucination"),
    "sycophancy": ("LLM09", "hallucination"),
    "harmfulness": ("safety", "toxicity"),
    "stereotypes": ("safety", "bias"),
    "output_formatting": ("LLM05", "insecure-output"),
}


def detector_meta(detector_name: str) -> tuple[str, str]:
    """Map an issue's detector_name -> (owasp_llm_id, chip) by substring."""
    d = (detector_name or "").lower()
    if "disclosure" in d:
        return ("LLM02", "data-disclosure")
    if "harmful" in d:
        return ("safety", "toxicity")
    if "stereotype" in d or "discrimination" in d or "bias" in d:
        return ("safety", "bias")
    if "formatting" in d or "output_format" in d:
        return ("LLM05", "insecure-output")
    if "injection" in d or "jailbreak" in d:
        return ("LLM01", "prompt-injection")
    if any(x in d for x in ("hallucination", "faithfulness", "implausible", "sycophancy", "misinformation")):
        return ("LLM09", "hallucination")
    return ("LLM01", "prompt-injection")
