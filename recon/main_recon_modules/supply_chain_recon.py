"""L2 Supply-Chain recon module (plan Phase 3.3).

Runs in GROUP 5.5 AFTER JS-recon (it consumes JS-recon output). Against the LIVE
target with no manifest, it harvests the served npm package set (source-map
mining + imports + technologies - all from data JS-recon already downloaded, so
NO new fetch and NO SSRF surface, S4), verdicts it OFFLINE with osv-scanner, and
stores a validated artifact under combined_result['supply_chain_recon'] for the
graph write (Package/MalPackageFinding MERGE, anchored to the target BaseURLs).

Only osv-scanner (static, offline) runs here. retire.js over target-served JS
and GuardDog deep analysis (the hostile-byte steps) dispatch to the DIRTY
analyzer and are v2; this module never fetches or executes anything.
"""

import copy
import os
import tempfile

# supply_chain_common is mounted into the recon container like graph_db.
from supply_chain_common import osv_runner as _osv_runner
from supply_chain_common.artifact import (
    empty_artifact, add_osv_findings, to_cyclonedx,
)
from supply_chain_common.security import validate_artifact, ArtifactError

_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/osv-db")


def _extract_source_maps(combined_result):
    js = combined_result.get("js_recon") or {}
    return js.get("source_maps") or []


def _extract_technologies(combined_result):
    """Best-effort {name, version} list from httpx/wappalyzer output."""
    techs = []
    http = combined_result.get("http_probe") or {}
    # http_probe results vary; scan common shapes for tech lists.
    for key in ("results", "live_urls", "probes"):
        for entry in (http.get(key) or []):
            if not isinstance(entry, dict):
                continue
            for t in (entry.get("technologies") or entry.get("tech") or []):
                if isinstance(t, dict):
                    techs.append({"name": t.get("name"), "version": t.get("version")})
                elif isinstance(t, str):
                    techs.append({"name": t, "version": None})
    return techs


def _extract_base_urls(combined_result):
    """Base URLs that the harvested packages should be anchored to (DEPENDS_ON)."""
    urls = set()
    http = combined_result.get("http_probe") or {}
    for key in ("results", "live_urls", "probes"):
        for entry in (http.get(key) or []):
            if isinstance(entry, dict):
                u = entry.get("url") or entry.get("base_url")
                if u:
                    urls.add(u)
            elif isinstance(entry, str):
                urls.add(entry)
    return sorted(urls)


def verdict_packages(packages, *, db_path=None, osv=None):
    """Verdict a harvested package list against the offline OSV DB.

    Synthesizes a CycloneDX SBOM and scans it (osv detects components by purl).
    Returns a boundary-valid artifact. `osv` is injectable for tests.
    """
    osv = osv or _osv_runner
    db_path = db_path or _OSV_DB
    artifact = empty_artifact("js-dir")
    for pkg in packages:
        artifact["packages"].append({
            "purl": pkg.get("purl"), "name": pkg.get("name"),
            "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem"),
            "source": pkg.get("source"),
        })

    if packages:
        sbom = to_cyclonedx(packages)
        tmpdir = tempfile.mkdtemp(prefix="sc-recon-")
        bom_path = os.path.join(tmpdir, "bom.cdx.json")
        try:
            import json
            with open(bom_path, "w") as fh:
                json.dump(sbom, fh)
            result = osv.run_osv_scan(bom_path, mode="sbom", db_path=db_path)
            if result.get("error"):
                artifact["errors"].append("osv: {}".format(result["error"]))
            # Only fold in the verdicts (malicious/vulnerable); packages already added.
            parsed = result.get("parsed") or {}
            add_osv_findings(artifact, {"packages": [], "malicious": parsed.get("malicious", []),
                                        "vulnerable": parsed.get("vulnerable", [])})
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    try:
        return validate_artifact(artifact)
    except ArtifactError as exc:
        safe = empty_artifact()
        safe["errors"].append("artifact validation failed: {}".format(exc))
        return validate_artifact(safe)


def run_supply_chain_recon(combined_result, settings=None):
    """Harvest + verdict; store combined_result['supply_chain_recon']. Returns
    the mutated combined_result (pipeline convention)."""
    settings = settings or {}
    from recon.helpers.supply_chain.harvest import harvest_packages

    source_maps = _extract_source_maps(combined_result)
    technologies = _extract_technologies(combined_result)
    base_urls = _extract_base_urls(combined_result)

    packages = harvest_packages(source_maps=source_maps, technologies=technologies)
    ecos = settings.get("SUPPLY_CHAIN_RECON_ECOSYSTEMS")
    if ecos:
        allow = {e.strip() for e in ecos.split(",") if e.strip()} if isinstance(ecos, str) else set(ecos)
        packages = [p for p in packages if p.get("ecosystem") in allow]

    artifact = verdict_packages(packages, db_path=_OSV_DB)

    combined_result["supply_chain_recon"] = {
        "artifact": artifact,
        "base_urls": base_urls,
        "summary": {
            "packages": len(artifact["packages"]),
            "malicious": len(artifact["malicious"]),
            "vulnerable": len(artifact["vulnerable"]),
        },
    }
    print("[+][SupplyChainRecon] packages={} malicious={} vulnerable={}".format(
        len(artifact["packages"]), len(artifact["malicious"]), len(artifact["vulnerable"])))
    return combined_result


def run_supply_chain_recon_isolated(combined_result, settings=None):
    """Deep-copy variant for thread-safe use inside the pipeline executor."""
    local = copy.deepcopy(combined_result)
    return run_supply_chain_recon(local, settings=settings)
