"""Shared artifact assembly: turn tool output into the DIRTY->CLEAN artifact.

Both the dirty analyzer entrypoint and the L1 CLEAN scan runner build the same
artifact shape from OSV / GuardDog results, so the mapping lives here once.
The result is always run through security.validate_artifact before use.
"""

from .security import ARTIFACT_SCHEMA_VERSION

__all__ = ["empty_artifact", "add_osv_findings", "add_guarddog_findings",
           "osv_mode_for_path", "to_cyclonedx"]

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
            "advisory_id": vul.get("advisory_id"),
            # Real advisory severity when OSV gave one (see
            # osv_runner.severity_for_vuln); "unknown" only when it did not.
            "severity": vul.get("severity") or "unknown",
            "confidence": "suspicious",
            "title": vul.get("summary") or vul.get("advisory_id"),
            # osv_runner.cvss_vector_for_vuln already extracted this; dropping it
            # here is why Vulnerability.cvss_metrics was always null even though
            # the graph writer asks for it.
            "cvss_vector": vul.get("cvss_vector"),
        })
    return artifact


def add_guarddog_findings(artifact, findings, *, ecosystem=None, name=None,
                          version=None, purl=None):
    """Merge parse_guarddog output (a list) into the artifact's suspicious set.

    `purl` matters: without it the graph writer falls back to building
    ``pkg:<eco>/<name>`` with no version, which MERGEs a SECOND, versionless
    Package node instead of attaching the finding to the versioned package the
    verdict actually came from. Callers that know the purl must pass it.
    """
    for f in findings or []:
        entry = {
            "name": f.get("package") or name,
            "version": f.get("version") or version, "ecosystem": ecosystem,
            "rule": f.get("rule"), "severity": f.get("severity"),
            "confidence": "suspicious", "message": f.get("message"),
            "soft_error": f.get("soft_error", False),
        }
        if purl:
            entry["purl"] = purl
        artifact["suspicious"].append(entry)
    return artifact


def to_cyclonedx(packages):
    """Synthesize a minimal CycloneDX 1.5 SBOM from packages (each with a purl),
    for an OSV verdict pass (osv-scanner detects components by purl)."""
    components = []
    for pkg in packages or []:
        purl = pkg.get("purl")
        if not purl:
            continue
        comp = {"type": "library", "name": pkg.get("name"), "purl": purl}
        if pkg.get("version"):
            comp["version"] = pkg["version"]
        components.append(comp)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "version": 1, "components": components}


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
