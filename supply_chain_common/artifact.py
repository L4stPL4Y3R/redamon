"""Shared artifact assembly: turn tool output into the DIRTY->CLEAN artifact.

Both the dirty analyzer entrypoint and the L1 CLEAN scan runner build the same
artifact shape from OSV / GuardDog results, so the mapping lives here once.
The result is always run through security.validate_artifact before use.
"""

from .security import ARTIFACT_SCHEMA_VERSION

__all__ = ["empty_artifact", "add_osv_findings", "add_guarddog_findings",
           "osv_mode_for_path"]

_VALID_MODES = {"lockfile", "sbom", "dir", "purls", "js-dir"}


def empty_artifact(mode=None):
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "mode": mode if mode in _VALID_MODES else None,
        "packages": [], "malicious": [], "vulnerable": [], "suspicious": [],
        "errors": [],
    }


def add_osv_findings(artifact, parsed, *, source="osv"):
    """Merge parse_osv_json output into the artifact (packages + verdicts)."""
    for pkg in parsed.get("packages") or []:
        artifact["packages"].append({
            "purl": pkg.get("purl"), "name": pkg.get("name"),
            "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem"),
            "source": source, "source_path": pkg.get("source_path"),
        })
    for mal in parsed.get("malicious") or []:
        artifact["malicious"].append({
            "purl": mal.get("purl"), "name": mal.get("name"),
            "version": mal.get("version"), "ecosystem": mal.get("ecosystem"),
            "advisory_id": mal.get("advisory_id"), "severity": "high",
            "confidence": "malicious",
            "title": mal.get("summary") or mal.get("advisory_id"),
            "aliases": mal.get("aliases") or [],
        })
    for vul in parsed.get("vulnerable") or []:
        artifact["vulnerable"].append({
            "purl": vul.get("purl"), "name": vul.get("name"),
            "version": vul.get("version"), "ecosystem": vul.get("ecosystem"),
            "advisory_id": vul.get("advisory_id"), "severity": "unknown",
            "confidence": "suspicious",
            "title": vul.get("summary") or vul.get("advisory_id"),
        })
    return artifact


def add_guarddog_findings(artifact, findings, *, ecosystem=None, name=None):
    """Merge parse_guarddog output (a list) into the artifact's suspicious set."""
    for f in findings or []:
        artifact["suspicious"].append({
            "name": f.get("package") or name,
            "version": f.get("version"), "ecosystem": ecosystem,
            "rule": f.get("rule"), "severity": f.get("severity"),
            "confidence": "suspicious", "message": f.get("message"),
            "soft_error": f.get("soft_error", False),
        })
    return artifact


def osv_mode_for_path(path, is_dir=False):
    """Pick the osv-scanner mode from a filesystem path.

    SBOMs are detected by basename (osv also detects by content); everything
    else is treated as a lockfile (osv picks the extractor from the basename).
    """
    if is_dir:
        return "dir"
    base = (path or "").lower().rsplit("/", 1)[-1]
    if base in ("bom.json", "sbom.json") or base.endswith(
            (".cdx.json", ".spdx.json", ".cdx.xml", "cyclonedx.json")):
        return "sbom"
    return "lockfile"
