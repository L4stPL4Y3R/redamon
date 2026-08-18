"""Import shim for the TruffleHog source registry.

The registry itself lives with the scanner (``scanners/trufflehog_scan/``) and is
the single authority for argv construction, cross-field validation, the
per-source credential gate and the egress-host list. The orchestrator needs the
last three at start time — it must refuse a bad config, a missing mandatory key
and an internal target BEFORE spawning anything — so it imports the same module
rather than reimplementing the rules and drifting.

Compose mounts the scanner source at ``/app/trufflehog_scan``, so the plain
top-level import is the container path; the ``scanners.`` package path is how it
resolves from a repo checkout (tests, tooling). Both reach the same file.
"""

from __future__ import annotations

try:  # orchestrator container: ./scanners/trufflehog_scan mounted at /app/trufflehog_scan
    from trufflehog_scan import findings, sources
except ImportError:  # repo checkout
    from scanners.trufflehog_scan import findings, sources  # type: ignore

__all__ = ["findings", "sources"]
