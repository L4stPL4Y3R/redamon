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
    "sanitize_name", "sanitize_version", "sanitize_purl", "sanitize_ecosystem",
    "sanitize_advisory", "sanitize_hostname", "SanitizeError", "MAX_NAME_LEN",
    "MAX_HOSTNAME_LEN",
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
# NOTE: anchors are ^...\Z, NOT ^...$ - in Python `$` also matches just before a
# single trailing newline, which would let "evil\n" slip through the gate (F2).
_NAME_RE = re.compile(r"^[A-Za-z0-9._@/:+-]+\Z")

# Version strings: semver + PEP 440 + Maven qualifiers. No metacharacters.
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+~:-]+\Z")

# purl charset: like a name plus '%' (percent-encoding, e.g. pkg:npm/%40scope/x).
_PURL_RE = re.compile(r"^[A-Za-z0-9._@/:+%-]+\Z")

# ecosystem: OSV brands like npm, PyPI, crates.io, Go, Maven. No path/shell chars.
_ECOSYSTEM_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")

# advisory id / rule name: MAL-2022-1122, CVE-..., GHSA-..., npm-install-script.
_ADVISORY_RE = re.compile(r"^[A-Za-z0-9._:-]+\Z")


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


def _check_field(value, regex, label, max_len=MAX_NAME_LEN):
    """Validate an optional structured string field against a regex. None is
    allowed (returns None); anything present must match, be within length, and
    contain no '..'. Raises SanitizeError."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SanitizeError(f"{label} must be a string, got {type(value).__name__}")
    if not value or len(value) > max_len or ".." in value:
        raise SanitizeError(f"{label} length/'..' out of range")
    if not regex.match(value):
        raise SanitizeError(f"{label} contains disallowed characters")
    return value


def sanitize_purl(value):
    # Purls carry namespace + name + version, so allow more length than a name.
    return _check_field(value, _PURL_RE, "purl", max_len=512)


def sanitize_ecosystem(value):
    return _check_field(value, _ECOSYSTEM_RE, "ecosystem")


def sanitize_advisory(value):
    return _check_field(value, _ADVISORY_RE, "advisory_id")


# Longest legal DNS name. Anything longer is not a hostname.
MAX_HOSTNAME_LEN = 253

# One DNS label: LDH (letters/digits/hyphen), no leading or trailing hyphen.
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\Z")


def sanitize_hostname(value, *, allow_wildcard=True):
    """Validate an IOC hostname from the incident feed; raise on anything else.

    The feed's `domains` array is dirty by construction: 13 of 216 entries are
    prose sentences, some are raw IPs (route those to the IP validator instead),
    and at least one is slash-joined garbage. This is the charset gate that drops
    all three classes, and it is deliberately stricter than `sanitize_name` -
    a hostname has no '@', '/', ':' or '_'.

    Unlike the other sanitizers this one LOWERCASES its result. DNS is
    case-insensitive and the value is used for set membership, never as a
    subprocess argument or a filename, so a case-folded compare is the correct
    behaviour rather than a silent rewrite of an identity.

    `allow_wildcard` permits ONE leading '*.' label. The caller still applies the
    public-suffix rule (a bare '*.workers.dev' is dropped as too broad).
    """
    if not isinstance(value, str):
        raise SanitizeError(
            "hostname must be a string, got {}".format(type(value).__name__))
    host = value.strip().lower()
    if not host or len(host) > MAX_HOSTNAME_LEN:
        raise SanitizeError(
            "hostname length out of range (1..{})".format(MAX_HOSTNAME_LEN))
    if ".." in host:
        raise SanitizeError("hostname contains '..'")
    # A trailing root dot is legal DNS but never appears in an IOC; normalize it
    # away rather than rejecting the entry.
    if host.endswith("."):
        host = host[:-1]

    wildcard = False
    if host.startswith("*."):
        if not allow_wildcard:
            raise SanitizeError("wildcard hostname not allowed here")
        wildcard = True
        host_body = host[2:]
    else:
        host_body = host
    if not host_body:
        raise SanitizeError("hostname is only a wildcard")
    # A second '*' anywhere means this is not a hostname we can match on.
    if "*" in host_body:
        raise SanitizeError("hostname has a non-leading wildcard")

    labels = host_body.split(".")
    if len(labels) < 2:
        # Single-label entries ("localhost", or a prose word) are never usable
        # IOCs and would match far too broadly.
        raise SanitizeError("hostname must have at least two labels")
    for label in labels:
        if not label or len(label) > 63 or not _HOSTNAME_LABEL_RE.match(label):
            raise SanitizeError("hostname has an invalid label: {!r}".format(label))
    # A purely numeric last label means this is an IP, not a hostname; the caller
    # must route it to the IP validator so the private-range drop applies.
    if labels[-1].isdigit():
        raise SanitizeError("hostname looks like an IP address")

    return ("*." + host_body) if wildcard else host_body


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
# cvss_vector is free text (a "CVSS:3.1/AV:N/..." string), so it is capped like
# title/detail rather than charset-gated - it never reaches a subprocess or a
# filename, only a display field.
_FINDING_FIELDS = {"purl", "name", "version", "ecosystem", "advisory_id",
                   "rule", "severity", "confidence", "title", "detail",
                   "message", "summary", "aliases", "soft_error",
                   "cvss_vector"}
_ALLOWED_SEVERITY = {"high", "medium", "low", "critical", "unknown", None}


def _cap_str(value):
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value[:MAX_STRING_LEN]


# Structured (identity/subprocess-bound) fields validated by their own charset,
# NOT just capped. Free-text fields (title/detail/message/summary) stay _cap_str
# and are neutralized at their sink (escapeHtml / wrap_untrusted). (F1)
def _validate_structured(entry, label):
    """Charset-validate purl/version/ecosystem/advisory_id; raises ArtifactError
    on a hostile value so a compromised analyzer cannot smuggle path/shell
    metacharacters past the DIRTY->CLEAN boundary."""
    try:
        if "name" in entry and entry["name"] is not None:
            sanitize_name(entry["name"])
        sanitize_purl(entry.get("purl"))
        sanitize_version(entry.get("version"))
        sanitize_ecosystem(entry.get("ecosystem"))
        sanitize_advisory(entry.get("advisory_id"))
        if entry.get("rule") is not None:
            sanitize_advisory(entry.get("rule"))
        if entry.get("source") is not None:
            sanitize_ecosystem(entry.get("source"))
    except SanitizeError as exc:
        raise ArtifactError("hostile {} field: {}".format(label, exc))


def _clean_package(entry):
    if not isinstance(entry, dict):
        return None
    if not set(entry).issubset(_PKG_FIELDS):
        raise ArtifactError("package has unknown fields: {}".format(
            set(entry) - _PKG_FIELDS))
    _validate_structured(entry, "package")
    out = {k: _cap_str(entry.get(k)) for k in _PKG_FIELDS if k in entry}
    return out


def _clean_finding(entry):
    if not isinstance(entry, dict):
        return None
    if not set(entry).issubset(_FINDING_FIELDS):
        raise ArtifactError("finding has unknown fields: {}".format(
            set(entry) - _FINDING_FIELDS))
    _validate_structured(entry, "finding")
    sev = entry.get("severity")
    if sev not in _ALLOWED_SEVERITY:
        raise ArtifactError("finding has invalid severity: {!r}".format(sev))
    out = {}
    for k in _FINDING_FIELDS:
        if k not in entry:
            continue
        v = entry[k]
        if k == "aliases":
            # F6: coerce a non-list aliases to a list so downstream never sees a
            # string where it expects a list.
            v = v if isinstance(v, list) else ([] if v is None else [v])
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

    truncations = []

    def _array(key, limit):
        val = artifact.get(key) or []
        if not isinstance(val, list):
            raise ArtifactError("{} must be a list".format(key))
        if len(val) > limit:
            # F4: TRUNCATE to the cap instead of rejecting the whole artifact.
            # Rejecting would silently drop a MAL- verdict that may sit anywhere
            # in a large list; truncation still bounds the blast radius (the
            # security intent) and records the loss as an error, never silent.
            truncations.append("{} truncated {}->{}".format(key, len(val), limit))
            val = val[:limit]
        return val

    packages = [p for p in (_clean_package(e) for e in _array("packages", MAX_PACKAGES)) if p]
    malicious = [f for f in (_clean_finding(e) for e in _array("malicious", MAX_FINDINGS)) if f]
    vulnerable = [f for f in (_clean_finding(e) for e in _array("vulnerable", MAX_FINDINGS)) if f]
    suspicious = [f for f in (_clean_finding(e) for e in _array("suspicious", MAX_FINDINGS)) if f]

    errors = _array("errors", MAX_ERRORS) + truncations
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
