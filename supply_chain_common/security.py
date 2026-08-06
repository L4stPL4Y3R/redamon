"""Name sanitization and the DIRTY->CLEAN JSON boundary contract.

`sanitize_name` is the single gate every attacker-controlled package name /
version / purl must pass BEFORE it reaches a subprocess argument or a filename
(threats S6 command injection, S7 path traversal). It is deliberately strict:
allow only the characters that legitimately appear in package coordinates and
reject everything else rather than trying to escape.

`validate_artifact` (the DIRTY->CLEAN schema boundary) is added in Phase 0.5;
this module already exists so the Phase-0 runners can import `sanitize_name`.
"""

import re

__all__ = [
    "sanitize_name", "sanitize_version", "SanitizeError", "MAX_NAME_LEN",
    "validate_artifact", "ArtifactError", "ARTIFACT_SCHEMA_VERSION",
    "MAX_PACKAGES", "MAX_FINDINGS", "MAX_STRING_LEN",
]


class SanitizeError(ValueError):
    """Raised when an untrusted name fails the charset allowlist."""


class ArtifactError(ValueError):
    """Raised when the DIRTY->CLEAN artifact fails schema validation."""


# Longest legitimate npm/PyPI/Maven coordinate we will ever accept. Anything
# longer is either an attack or garbage; reject rather than truncate.
MAX_NAME_LEN = 256

# Package NAME charset. Covers every ecosystem coordinate we harvest:
#   npm            @scope/name           -> '@', '/', letters, digits, '-', '_', '.'
#   PyPI           name.with-dots_under
#   Go / Maven     group:artifact, host/path/name -> ':', '/'
#   crates/gems    hyphen/underscore
# Explicitly EXCLUDES shell metacharacters, whitespace, and anything that could
# start a path escape. '..' is rejected separately below.
_NAME_RE = re.compile(r"^[A-Za-z0-9._@/:+-]+$")

# Version strings: semver + PEP 440 + Maven qualifiers. No metacharacters.
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+~:-]+$")


def sanitize_name(value):
    """Return `value` unchanged if it is a safe package coordinate, else raise.

    Never mutates the value (a silently-rewritten name would scan the wrong
    package); it is a validator, not a transformer. Callers that need a
    filesystem-safe token should hash/slugify the RESULT, never interpolate the
    raw name into a path (S7).
    """
    if not isinstance(value, str):
        raise SanitizeError(f"name must be a string, got {type(value).__name__}")
    if not value or len(value) > MAX_NAME_LEN:
        raise SanitizeError(f"name length out of range (1..{MAX_NAME_LEN})")
    if ".." in value:
        raise SanitizeError("name contains '..' (path traversal)")
    if value.startswith("/") or value.startswith("-"):
        # A leading '/' escapes to absolute paths; a leading '-' would be parsed
        # as a CLI flag by the tool we shell out to.
        raise SanitizeError("name may not start with '/' or '-'")
    if not _NAME_RE.match(value):
        raise SanitizeError("name contains disallowed characters")
    return value


def sanitize_version(value):
    """Validate a version string (may be None -> returned as None)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SanitizeError(f"version must be a string, got {type(value).__name__}")
    if not value or len(value) > MAX_NAME_LEN:
        raise SanitizeError("version length out of range")
    if not _VERSION_RE.match(value):
        raise SanitizeError("version contains disallowed characters")
    return value


# ---------------------------------------------------------------------------
# DIRTY -> CLEAN artifact boundary
# ---------------------------------------------------------------------------
# The dirty analyzer writes ONE JSON artifact to a shared scratch mount. The
# clean writer (which holds Neo4j creds) MUST pass it through validate_artifact
# before touching a single field. This is the choke point that stops a
# compromised analyzer from smuggling an oversized payload, an unknown field, a
# 10 MB string, or a shell/XSS/prompt-injection name into the trusted zone (S5
# boundary). It rejects structural attacks and drops individual malformed
# entries; escaping for specific sinks (HTML/LLM/filename) still happens at each
# sink, this only guarantees shape + caps + charset.

ARTIFACT_SCHEMA_VERSION = 1
MAX_PACKAGES = 5000
MAX_FINDINGS = 5000
MAX_STRING_LEN = 4096
MAX_ERRORS = 500

_ALLOWED_TOP = {"schema_version", "mode", "packages", "malicious",
                "vulnerable", "suspicious", "errors"}
_ALLOWED_MODES = {"lockfile", "sbom", "dir", "purls", "js-dir"}
_PKG_FIELDS = {"purl", "name", "version", "ecosystem", "source", "source_path"}
_FINDING_FIELDS = {"purl", "name", "version", "ecosystem", "advisory_id",
                   "rule", "severity", "confidence", "title", "detail",
                   "message", "summary", "aliases", "soft_error"}
_ALLOWED_SEVERITY = {"high", "medium", "low", "critical", "unknown", None}


def _cap_str(value):
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value[:MAX_STRING_LEN]


def _clean_package(entry):
    if not isinstance(entry, dict):
        return None
    if not set(entry).issubset(_PKG_FIELDS):
        raise ArtifactError("package has unknown fields: {}".format(
            set(entry) - _PKG_FIELDS))
    name = entry.get("name")
    if name is not None:
        try:
            sanitize_name(name)  # hostile name -> whole artifact rejected
        except SanitizeError as exc:
            raise ArtifactError("hostile package name: {}".format(exc))
    out = {k: _cap_str(entry.get(k)) for k in _PKG_FIELDS if k in entry}
    return out


def _clean_finding(entry):
    if not isinstance(entry, dict):
        return None
    if not set(entry).issubset(_FINDING_FIELDS):
        raise ArtifactError("finding has unknown fields: {}".format(
            set(entry) - _FINDING_FIELDS))
    name = entry.get("name")
    if name is not None:
        try:
            sanitize_name(name)
        except SanitizeError as exc:
            raise ArtifactError("hostile finding name: {}".format(exc))
    sev = entry.get("severity")
    if sev not in _ALLOWED_SEVERITY:
        raise ArtifactError("finding has invalid severity: {!r}".format(sev))
    out = {}
    for k in _FINDING_FIELDS:
        if k not in entry:
            continue
        v = entry[k]
        if k == "aliases" and isinstance(v, list):
            out[k] = [_cap_str(a) for a in v[:100]]
        elif k == "soft_error":
            out[k] = bool(v)
        else:
            out[k] = _cap_str(v)
    return out


def validate_artifact(artifact):
    """Validate + normalize the analyzer's output. Returns a clean dict or raises
    ArtifactError. Never trusts array sizes, string lengths, field names, or the
    charset of any attacker-derived name."""
    if not isinstance(artifact, dict):
        raise ArtifactError("artifact must be a JSON object")
    unknown = set(artifact) - _ALLOWED_TOP
    if unknown:
        raise ArtifactError("unknown top-level fields: {}".format(unknown))

    if artifact.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        raise ArtifactError("unsupported schema_version: {!r}".format(
            artifact.get("schema_version")))

    mode = artifact.get("mode")
    if mode is not None and mode not in _ALLOWED_MODES:
        raise ArtifactError("invalid mode: {!r}".format(mode))

    def _array(key, limit):
        val = artifact.get(key) or []
        if not isinstance(val, list):
            raise ArtifactError("{} must be a list".format(key))
        if len(val) > limit:
            raise ArtifactError("{} exceeds cap ({} > {})".format(
                key, len(val), limit))
        return val

    packages = [p for p in (_clean_package(e) for e in _array("packages", MAX_PACKAGES)) if p]
    malicious = [f for f in (_clean_finding(e) for e in _array("malicious", MAX_FINDINGS)) if f]
    vulnerable = [f for f in (_clean_finding(e) for e in _array("vulnerable", MAX_FINDINGS)) if f]
    suspicious = [f for f in (_clean_finding(e) for e in _array("suspicious", MAX_FINDINGS)) if f]

    errors = _array("errors", MAX_ERRORS)
    errors = [_cap_str(e) for e in errors]

    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "mode": mode,
        "packages": packages,
        "malicious": malicious,
        "vulnerable": vulnerable,
        "suspicious": suspicious,
        "errors": errors,
    }
