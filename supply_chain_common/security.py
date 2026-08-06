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

__all__ = ["sanitize_name", "sanitize_version", "SanitizeError", "MAX_NAME_LEN"]


class SanitizeError(ValueError):
    """Raised when an untrusted name fails the charset allowlist."""


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
