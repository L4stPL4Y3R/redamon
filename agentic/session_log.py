"""
Structured per-session event stream + flag detection.

Two logging channels serve different consumers:

  - agent.<session_id>.log        human-readable prose (decisions, analysis)
  - agent.<session_id>.events.jsonl  one JSON object per event, machine-readable

``log_event(kind, **fields)`` writes to the second channel via the dedicated
``session_events`` logger, which logging_config routes per session. This stream
is what cross-session evaluation, benchmark scoring and future auto-tuning read:
it is small, stable and greppable, unlike the prose log.

``detect_flags(text)`` finds CTF flag shapes in tool output so the orchestrator
can emit an unambiguous ``flag_captured`` event the moment a flag appears,
instead of leaving it buried inside a multi-KB tool dump.

Both functions are best-effort and never raise into the caller.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, List

_events_logger = logging.getLogger("session_events")

# CTF flag shapes: flag{...}, FLAG{...}, and the common named-prefix variants
# challenges use (ctf{}, htb{}, thm{}, and NahamCon's own). Case insensitive;
# bounded body so a runaway match can't swallow a whole page. The lookbehind
# skips CSS/code lookalikes where the keyword is part of a selector or identifier
# (".flag{color:red}", "#flag{...}", "my-flag{...}", "keyflag{...}") — those are
# not flags. "key" is intentionally NOT a prefix: it collides with code far too
# often for too little coverage.
_FLAG_RE = re.compile(r"(?i)(?<![\w.#-])(?:flag|ctf|htb|thm|nahamcon)\{[^}\r\n]{1,256}\}")


def detect_flags(text: Any) -> List[str]:
    """Return unique flag-shaped strings found in ``text`` (order preserved)."""
    if not text:
        return []
    try:
        return list(dict.fromkeys(_FLAG_RE.findall(str(text))))
    except Exception:
        return []


def _scrub(value: Any) -> Any:
    """Redact secrets from string values before serialisation so the emitted
    JSON is always valid (redacting the serialised line could eat a quote/brace)."""
    if isinstance(value, str):
        try:
            from logging_config import redact_text
            return redact_text(value)
        except Exception:
            return value
    return value


def log_event(kind: str, **fields: Any) -> None:
    """Emit one structured event to the per-session JSONL stream. Never raises."""
    try:
        payload = {"kind": kind}
        for key, value in fields.items():
            payload[key] = _scrub(value)
        _events_logger.info(json.dumps(payload, default=str, ensure_ascii=False))
    except Exception:
        pass
