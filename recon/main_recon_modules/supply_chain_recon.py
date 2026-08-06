"""L2 Supply-Chain recon module (plan Phase 3.3).

Runs in GROUP 5.5 AFTER JS-recon (it consumes JS-recon output). Against the LIVE
target with no manifest, it harvests the served npm package set (source-map
mining + imports + technologies - all from data JS-recon already downloaded, so
NO new fetch and NO SSRF surface, S4), verdicts it OFFLINE with osv-scanner, and
stores a validated artifact under combined_result['supply_chain_recon'] for the
graph write (Package/MalPackageFinding MERGE, anchored to the target BaseURLs).

osv-scanner (static, offline) always runs here. GuardDog deep analysis runs too
when SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED is on: it is dispatched INTO the
hardened DIRTY analyzer image over the broker socket this container already
holds, and only ever over packages the OSV pass already flagged. retire.js over
target-served JS is still v2.

This module itself never downloads or unpacks a tarball - it holds the Neo4j
creds, the analyzer does not.
"""

import copy
import os
import tempfile
import time

# supply_chain_common is mounted into the recon container like graph_db.
from supply_chain_common import osv_runner as _osv_runner
from supply_chain_common import guarddog_runner as _guarddog_runner
from supply_chain_common.artifact import (
    empty_artifact, add_osv_findings, add_guarddog_findings, to_cyclonedx,
)
from supply_chain_common.security import validate_artifact, ArtifactError

_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/osv-db")

# Deep analysis (GuardDog) knobs. This step DOWNLOADS attacker-authored tarballs
# from the public registry, so it is opt-in, capped, and restricted to packages
# a passive OSV verdict already flagged - never a sweep of the whole set.
_DEEP_MAX_PACKAGES = int(os.environ.get("SUPPLY_CHAIN_DEEP_MAX_PACKAGES", "10"))
_DEEP_TIMEOUT = int(os.environ.get("SUPPLY_CHAIN_DEEP_TIMEOUT", "180"))
# Whole-pass ceiling. Without it the worst case is MAX_PACKAGES * TIMEOUT
# (10 x 180s = 30 min) of a recon scan blocked on a registry that is slow or
# hanging, with no way for the pipeline to make progress.
_DEEP_TOTAL_BUDGET = int(os.environ.get("SUPPLY_CHAIN_DEEP_TOTAL_BUDGET", "900"))
_ANALYZER_IMAGE = os.environ.get("SUPPLY_CHAIN_ANALYZER_IMAGE",
                                 _guarddog_runner.ANALYZER_IMAGE)

# OSV ecosystem brand -> GuardDog ecosystem slug. Ecosystems GuardDog cannot
# analyse (Maven, Packagist, NuGet) are absent on purpose and get skipped.
_OSV_TO_GUARDDOG_ECO = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "crates.io": "crates",
    "RubyGems": "rubygems",
}


def _extract_source_maps(combined_result):
    js = combined_result.get("js_recon") or {}
    return js.get("source_maps") or []


def _extract_technologies(combined_result):
    """{name, version} list from httpx/wappalyzer output.

    L2-2: the real http_probe shape is `by_url` (dict url->entry) with a
    `technologies` list of "Name:Version" STRINGS (plus a top-level
    `technologies_found` dict keyed by the same strings) - NOT a `results` list
    of {name,version} dicts. Read the right keys and split "Name:Version".
    """
    techs = []
    seen = set()
    http = combined_result.get("http_probe") or {}

    def _add_str(s):
        if not isinstance(s, str) or not s or s in seen:
            return
        seen.add(s)
        name, _, ver = s.partition(":")
        name = name.strip()
        if name:
            techs.append({"name": name, "version": (ver.strip() or None)})

    for entry in (http.get("by_url") or {}).values():
        if not isinstance(entry, dict):
            continue
        for t in (entry.get("technologies") or entry.get("tech") or []):
            if isinstance(t, str):
                _add_str(t)
            elif isinstance(t, dict) and t.get("name"):
                key = "{}:{}".format(t.get("name"), t.get("version") or "")
                if key not in seen:
                    seen.add(key)
                    techs.append({"name": t.get("name"), "version": t.get("version")})
    for t in (http.get("technologies_found") or {}):
        _add_str(t)
    return techs


def _extract_base_urls(combined_result):
    """Base URLs (scheme://netloc) to anchor harvested packages to (DEPENDS_ON).

    L2-1: reads the real `by_url` key. Normalizes each probed URL down to
    scheme://netloc so it matches the BaseURL node's `url` property (probed URLs
    may carry a path; BaseURL nodes do not).
    """
    from urllib.parse import urlparse
    urls = set()
    http = combined_result.get("http_probe") or {}
    for key, entry in (http.get("by_url") or {}).items():
        raw = None
        if isinstance(entry, dict):
            raw = entry.get("url") or entry.get("base_url")
        if not raw and isinstance(key, str):
            raw = key
        if not raw:
            continue
        try:
            p = urlparse(raw)
            urls.add("{}://{}".format(p.scheme, p.netloc) if p.scheme and p.netloc else raw)
        except Exception:
            urls.add(raw)
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


def flagged_specs(artifact, limit=_DEEP_MAX_PACKAGES):
    """Unique packages an OSV verdict already flagged, as GuardDog coordinates.

    Malicious first so the cap never starves the highest-signal packages.
    Returns [{ecosystem (guarddog slug), name, version, purl, osv_ecosystem}].
    """
    seen = set()
    out = []
    dropped = 0
    skipped_eco = set()
    for bucket in ("malicious", "vulnerable"):
        for f in artifact.get(bucket) or []:
            name = f.get("name")
            osv_eco = f.get("ecosystem")
            gd_eco = _OSV_TO_GUARDDOG_ECO.get(osv_eco)
            if not name:
                continue
            if not gd_eco:
                skipped_eco.add(osv_eco)
                continue
            key = (gd_eco, name, f.get("version"))
            if key in seen:
                continue
            seen.add(key)
            if len(out) >= limit:
                # Do NOT return early: keep counting so the cap is reported
                # instead of silently truncating the flagged set.
                dropped += 1
                continue
            out.append({"ecosystem": gd_eco, "name": name,
                        "version": f.get("version"), "purl": f.get("purl"),
                        "osv_ecosystem": osv_eco})
    if dropped:
        print("[!][SupplyChainRecon] deep analysis cap: {} flagged package(s) "
              "beyond SUPPLY_CHAIN_DEEP_MAX_PACKAGES={} were NOT analysed"
              .format(dropped, limit))
    if skipped_eco:
        print("[*][SupplyChainRecon] deep analysis skipped ecosystem(s) GuardDog "
              "cannot analyse: {}".format(sorted(e for e in skipped_eco if e)))
    return out


def _add_soft_error(artifact, spec, message):
    """Record an UNANALYSED package as a soft-error suspicious finding.

    The graph writer only ever reads packages/malicious/suspicious - never
    artifact["errors"] - so a failure recorded solely in `errors` is invisible
    to the operator and the package reads as behaviourally clean. Every path
    where GuardDog did not actually produce a verdict must land here.
    """
    artifact["suspicious"].append({
        "name": spec["name"], "version": spec["version"],
        "ecosystem": spec["osv_ecosystem"], "purl": spec["purl"],
        "rule": "guarddog-not-run", "severity": "low",
        "confidence": "suspicious", "message": str(message)[:2000],
        "soft_error": True,
    })
    return artifact


def deep_analyze(artifact, *, image=None, timeout=_DEEP_TIMEOUT,
                 limit=_DEEP_MAX_PACKAGES, budget=_DEEP_TOTAL_BUDGET,
                 guarddog=None):
    """Behavioural (GuardDog) pass over the OSV-flagged packages.

    Runs guarddog INSIDE the hardened dirty analyzer image, spawned through the
    broker socket the recon container already holds (DOCKER_HOST). This process
    never unpacks a tarball itself: it holds the Neo4j creds, the analyzer does
    not.

    A GuardDog hit is ALWAYS `suspicious`, never a terminal malicious verdict -
    only an OSV MAL- hit is malicious. A download failure surfaces as a
    soft_error finding so a package is never silently reported clean.

    Mutates and returns `artifact` (revalidated by the caller).
    """
    gd_mod = guarddog or _guarddog_runner
    specs = flagged_specs(artifact, limit=limit)
    stats = {"scanned": 0, "suspicious": 0, "soft_errors": 0,
             "failed": 0, "skipped_budget": 0}
    if not specs:
        return artifact, stats

    prefix = gd_mod.hardened_docker_argv(image or _ANALYZER_IMAGE)
    started = time.monotonic()

    for spec in specs:
        label = "{}@{}".format(spec["name"], spec["version"] or "latest")

        elapsed = time.monotonic() - started
        if budget and elapsed >= budget:
            # Out of time. Every remaining package must be recorded as an
            # UNANALYSED soft error, never left looking behaviourally clean.
            stats["skipped_budget"] += 1
            stats["failed"] += 1
            _add_soft_error(artifact, spec,
                            "deep analysis budget of {}s exhausted before this "
                            "package was analysed".format(budget))
            continue

        print("[*][SupplyChainRecon] deep analysis: {}".format(label))
        try:
            res = gd_mod.scan_package(spec["ecosystem"], spec["name"],
                                      spec["version"],
                                      timeout=min(timeout, max(1, int(budget - elapsed))) if budget else timeout,
                                      argv_prefix=prefix)
        except Exception as exc:
            # A hostile coordinate (SanitizeError) or a spawn failure must not
            # discard the OSV verdicts already collected. Isolate per package,
            # and record it so the package is not silently reported clean.
            artifact["errors"].append("guarddog {}: {}".format(label, exc))
            stats["failed"] += 1
            _add_soft_error(artifact, spec, "guarddog dispatch raised: {}".format(exc))
            continue

        findings = res.get("findings") or []
        if res.get("error"):
            artifact["errors"].append("guarddog {}: {}".format(label, res["error"]))
            stats["failed"] += 1
            if not findings:
                # THE false-clean guard. A dispatch failure (docker socket
                # missing, image not pulled, timeout, non-JSON output) yields
                # zero findings. artifact["errors"] is NOT written to the graph,
                # so without this the package would show no behavioural findings
                # and read as "deep analysis ran, nothing found" - the exact
                # failure mode --no-sandbox was added to kill, one layer up.
                _add_soft_error(artifact, spec,
                                "guarddog did not run: {}".format(res["error"]))
        else:
            stats["scanned"] += 1

        add_guarddog_findings(
            artifact, findings,
            ecosystem=spec["osv_ecosystem"], name=spec["name"],
            version=spec["version"], purl=spec["purl"])
        stats["suspicious"] += sum(1 for f in findings if not f.get("soft_error"))
        stats["soft_errors"] += sum(1 for f in findings if f.get("soft_error"))

    return artifact, stats


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

    # Deep behavioural analysis (GuardDog), opt-in. Runs only over packages the
    # offline OSV pass already flagged, inside the hardened dirty analyzer.
    deep_stats = None
    if settings.get("SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED"):
        try:
            artifact, deep_stats = deep_analyze(artifact)
            # Re-validate: GuardDog output is attacker-influenced (rule messages
            # quote package source), so it must clear the boundary gate too.
            artifact = validate_artifact(artifact)
        except ArtifactError as exc:
            # D1: dropping the WHOLE suspicious list here made every package the
            # deep pass touched read behaviourally clean again - including the
            # soft-error markers that exist precisely to prevent that. Drop only
            # the entries that cannot clear the gate, then re-mark every flagged
            # package that lost its finding as UNANALYSED.
            print("[!][SupplyChainRecon] deep analysis artifact invalid: {}".format(exc))
            bad = artifact["suspicious"]
            kept = []
            for f in bad:
                probe = dict(artifact, suspicious=[f])
                try:
                    validate_artifact(probe)
                    kept.append(f)
                except ArtifactError:
                    pass
            artifact["suspicious"] = kept
            artifact["errors"].append(
                "deep analysis: dropped {} unvalidatable finding(s): {}".format(
                    len(bad) - len(kept), exc))
            covered = {(f.get("name"), f.get("version")) for f in kept}
            for spec in flagged_specs(artifact):
                if (spec["name"], spec["version"]) not in covered:
                    _add_soft_error(artifact, spec,
                                    "deep analysis result failed validation and "
                                    "was dropped; package NOT analysed")
            artifact = validate_artifact(artifact)
        except Exception as exc:
            print("[!][SupplyChainRecon] deep analysis failed: {}".format(exc))
            artifact["errors"].append("deep analysis failed: {}".format(exc))

    combined_result["supply_chain_recon"] = {
        "artifact": artifact,
        "base_urls": base_urls,
        "summary": {
            "packages": len(artifact["packages"]),
            "malicious": len(artifact["malicious"]),
            "vulnerable": len(artifact["vulnerable"]),
            "suspicious": len(artifact["suspicious"]),
            "deep_analysis": deep_stats,
        },
    }
    print("[+][SupplyChainRecon] packages={} malicious={} vulnerable={} suspicious={}".format(
        len(artifact["packages"]), len(artifact["malicious"]),
        len(artifact["vulnerable"]), len(artifact["suspicious"])))
    if deep_stats:
        print("[+][SupplyChainRecon] deep analysis: scanned={} suspicious={} "
              "soft_errors={} failed={} skipped_budget={}".format(
                  deep_stats["scanned"], deep_stats["suspicious"],
                  deep_stats["soft_errors"], deep_stats["failed"],
                  deep_stats["skipped_budget"]))
    return combined_result


def run_supply_chain_recon_isolated(combined_result, settings=None):
    """Deep-copy variant for thread-safe use inside the pipeline executor."""
    local = copy.deepcopy(combined_result)
    return run_supply_chain_recon(local, settings=settings)
