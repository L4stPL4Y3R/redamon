"""Shared supply-chain runners and parsers.

This top-level package is mounted read-only into every image that runs a
supply-chain step (the recon spawn blocks, the standalone supply_chain_scan
container, and the dirty supply_chain_analyzer) the SAME way `graph_db` is
mounted. The L3 agent tool lives in a different image (kali-sandbox) and does
NOT import this package; it parses inline (see the plan, review C8).

Nothing here holds secrets or writes to the graph. These are pure runners
(subprocess shell-outs, shell=False) plus defensive parsers. Every function
that reaches a subprocess or a filename first passes untrusted names through
`security.sanitize_name` (S6/S7).

Tool contracts verified 2026-08-06 against:
  - OSV-Scanner v2.4.0  (google.github.io/osv-scanner, offline-mode docs)
  - GuardDog v3.0.1      (github.com/DataDog/guarddog)
  - retire.js v5.4.3     (github.com/RetireJS/retire.js)
"""

from .purl import build_purl, normalize_name, ECOSYSTEM_PURL_TYPE
from .security import sanitize_name, SanitizeError

__all__ = [
    "build_purl",
    "normalize_name",
    "ECOSYSTEM_PURL_TYPE",
    "sanitize_name",
    "SanitizeError",
]
