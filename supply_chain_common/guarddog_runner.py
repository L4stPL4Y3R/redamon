"""GuardDog runner + parser (behavioural analysis).

Verified against GuardDog v3.0.1 (2026-08-06):
  - Scan one package:   guarddog <eco> scan <name> [--version X] --output-format json
  - Scan a tarball/dir: guarddog <eco> scan <path> --output-format json
  - Verify a lockfile:  guarddog <eco> verify <path> --output-format json
  - Ecosystems: npm, pypi, go, crates, rubygems, github_action, extension.

Output shapes:
  scan   -> a single object {package, path, issues, errors, results}
  verify -> a LIST of {dependency, version, result:{issues, errors, results, path}}
  results[rule] is a STRING (or null) for metadata rules and a LIST of finding
  objects for source-code rules; both shapes are handled.

GuardDog downloads attacker-authored tarballs, so this runner is only ever
invoked INSIDE the dirty sandbox (Phase 0.5), never inline in a secret-holding
container. A GuardDog finding is ALWAYS `suspicious` confidence, never
`malicious` (only an OSV MAL- hit is malicious).
"""

import json

from ._run import run_argv
from .security import sanitize_name, sanitize_version

__all__ = ["scan_package", "verify_lockfile", "parse_guarddog",
           "severity_for_rule", "GUARDDOG_ECOSYSTEMS"]

GUARDDOG_ECOSYSTEMS = {"npm", "pypi", "go", "crates", "rubygems",
                       "github_action", "extension"}

# Rule -> severity. GuardDog emits no severity of its own; this is our
# convention (plan section 2.2). Matched by substring so ecosystem-prefixed
# variants (npm-*, pypi-*) map without enumerating every one.
_HIGH_MARKERS = (
    "install-script", "exec-base64", "exfiltrate-sensitive-data",
    "serialize-environment", "silent-process-execution", "dll-hijacking",
    "steganography", "code-execution", "download-executable",
)
_MEDIUM_MARKERS = (
    "typosquatting", "unclaimed_maintainer_email_domain",
    "potentially_compromised_email_domain", "metadata_mismatch",
    "shady-links", "obfuscation",
)


def severity_for_rule(rule):
    r = (rule or "").lower()
    if any(m in r for m in _HIGH_MARKERS):
        return "high"
    if any(m in r for m in _MEDIUM_MARKERS):
        return "medium"
    return "low"


def scan_package(ecosystem, name, version=None, *, timeout=120,
                 binary="guarddog"):
    """Statically analyse one named package. Returns {raw, findings, error}."""
    if ecosystem not in GUARDDOG_ECOSYSTEMS:
        return {"raw": None, "findings": [],
                "error": "unsupported ecosystem: {}".format(ecosystem)}
    sanitize_name(name)
    sanitize_version(version)

    argv = [binary, ecosystem, "scan", name]
    if version:
        argv += ["--version", version]
    argv += ["--output-format", "json"]

    res = run_argv(argv, timeout=timeout)
    return _finalize(res, name)


def verify_lockfile(ecosystem, path, *, timeout=600, binary="guarddog"):
    """Scan every dependency in a lockfile. Returns {raw, findings, error}."""
    if ecosystem not in GUARDDOG_ECOSYSTEMS:
        return {"raw": None, "findings": [],
                "error": "unsupported ecosystem: {}".format(ecosystem)}
    argv = [binary, ecosystem, "verify", str(path), "--output-format", "json"]
    res = run_argv(argv, timeout=timeout)
    return _finalize(res, None)


def _finalize(res, package_hint):
    raw = None
    error = res["error"]
    if res["stdout"]:
        try:
            raw = json.loads(res["stdout"])
        except (ValueError, TypeError):
            if error is None:
                error = "guarddog produced non-JSON output"
    return {"raw": raw, "findings": parse_guarddog(raw), "error": error}


def parse_guarddog(raw):
    """Normalize scan-object OR verify-list output into a flat finding list.

    Each finding: {package, version, rule, severity, confidence, message,
    soft_error}. A download failure (`errors` non-empty, issues 0) yields a
    soft_error finding, never silently a clean result.
    """
    findings = []
    if raw is None:
        return findings

    if isinstance(raw, list):
        # verify output
        for item in raw:
            if not isinstance(item, dict):
                continue
            dep = item.get("dependency")
            ver = item.get("version")
            result = item.get("result") or {}
            findings.extend(_parse_one_result(result, dep, ver))
    elif isinstance(raw, dict):
        # scan output
        pkg = raw.get("package")
        findings.extend(_parse_one_result(raw, pkg, raw.get("version")))
    return findings


def _parse_one_result(result, package, version):
    out = []
    if not isinstance(result, dict):
        return out

    errors = result.get("errors") or {}
    # F8: GuardDog normally emits errors as a dict, but tolerate a list/other
    # shape rather than raising AttributeError on .items() (which would drop the
    # whole run). Normalize non-dict errors into a single soft error.
    if errors and not isinstance(errors, dict):
        errors = {"error": str(errors)[:2000]}
    if errors:
        # A rule failed to run (e.g. download-package failure). Surface as a
        # soft error so the caller does not treat this package as clean.
        for rule, msg in errors.items():
            out.append({
                "package": package,
                "version": version,
                "rule": rule,
                "severity": "low",
                "confidence": "suspicious",
                "message": str(msg)[:2000],
                "soft_error": True,
            })

    results = result.get("results") or {}
    if not isinstance(results, dict):
        return out

    for rule, value in results.items():
        if not value:
            # Falsy = rule did not fire: None (metadata not triggered), "" (empty
            # message), or [] (no source-code hits). Skip all of them.
            continue
        severity = severity_for_rule(rule)
        if isinstance(value, str):
            # metadata rule fired -> human message string
            out.append(_finding(package, version, rule, severity, value))
        elif isinstance(value, list):
            # source-code rule fired -> list of finding objects
            if not value:
                continue
            for entry in value:
                if isinstance(entry, dict):
                    msg = entry.get("message") or entry.get("code") or ""
                else:
                    msg = str(entry)
                out.append(_finding(package, version, rule, severity, msg))
        else:
            out.append(_finding(package, version, rule, severity, str(value)))
    return out


def _finding(package, version, rule, severity, message):
    return {
        "package": package,
        "version": version,
        "rule": rule,
        "severity": severity,
        "confidence": "suspicious",
        "message": str(message)[:2000],
        "soft_error": False,
    }
