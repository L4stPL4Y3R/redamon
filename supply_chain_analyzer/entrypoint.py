#!/usr/bin/env python3
"""DIRTY analyzer entrypoint.

Reads a job spec from the shared scratch mount, runs the requested tools over
untrusted input (tarballs / target-served JS / manifests / SBOMs), and writes
ONE schema-validated JSON artifact back to scratch. This process holds no
secrets and (for the OSV path) makes zero network calls.

Job spec (JSON):
  {
    "mode": "lockfile" | "sbom" | "dir" | "js-dir" | "purls",
    "target": "/work/<path>",          # path inside the scratch mount
    "ecosystems": ["npm", ...],         # for filtering / guarddog
    "deep_analysis": false,             # opt-in GuardDog (registry egress)
    "guarddog_packages": [ {"ecosystem": "npm", "name": "...", "version": "..."} ]
  }

Output artifact conforms to supply_chain_common.security.validate_artifact.
The analyzer self-validates before writing, so a bug here cannot emit an
artifact the clean side would reject.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

# supply_chain_common is bind-mounted at /app (like graph_db). PYTHONPATH=/app.
from supply_chain_common import osv_runner, retire_runner, guarddog_runner
from supply_chain_common.security import (
    validate_artifact, ArtifactError, sanitize_name, sanitize_version, SanitizeError,
)
from supply_chain_common.artifact import (
    empty_artifact, add_osv_findings, add_guarddog_findings, to_cyclonedx,
)

_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")


def run_job(job):
    mode = job.get("mode")
    target = job.get("target")
    artifact = empty_artifact(mode)

    if mode == "js-dir":
        # Black-box harvest: retire.js over downloaded JS, then OSV over the
        # resulting SBOM.
        #
        # retire.js is the ONLY L2 source that yields a NAME **and a VERSION**
        # straight out of the served bytes. Source-map mining gives names with
        # no version (unverdictable), and the technology path only covers the
        # 15-entry alias table, so without this step most of a real target's
        # dependency set can never be verdicted at all.
        retire_res = retire_runner.scan_js_dir(target)
        if retire_res["error"]:
            artifact["errors"].append("retire: {}".format(retire_res["error"]))
        harvested = []
        for comp in retire_res["components"]:
            # retire.js parses ATTACKER-SERVED JavaScript, so a component name
            # is untrusted input. Drop a hostile one here: validate_artifact at
            # the end of this function raises on the whole artifact, so a single
            # bad name would otherwise discard every legitimate package AND
            # every verdict collected in this job (same failure mode the
            # GuardDog leg already guards against below).
            name = comp.get("name")
            try:
                sanitize_name(name)
                sanitize_version(comp.get("version"))
            except (SanitizeError, TypeError):
                artifact["errors"].append(
                    "retire: dropped hostile component name {!r}".format(name)[:500])
                continue
            try:
                purl = retire_runner.to_purls([comp])
            except Exception:
                purl = []
            pkg = {
                "name": name,
                "version": comp.get("version"),
                "ecosystem": "npm",
                "purl": purl[0] if purl else None,
                "source": "retirejs",
            }
            artifact["packages"].append(pkg)
            if pkg["purl"]:
                harvested.append(pkg)

        # Verdict the harvested set offline. osv-scanner detects components by
        # purl, so a synthesized CycloneDX SBOM is the input format (same shape
        # the L2 recon module already builds).
        if harvested:
            tmpdir = tempfile.mkdtemp(prefix="sc-jsdir-")
            bom_path = os.path.join(tmpdir, "bom.cdx.json")
            try:
                with open(bom_path, "w") as fh:
                    json.dump(to_cyclonedx(harvested), fh)
                osv_res = osv_runner.run_osv_scan(bom_path, mode="sbom",
                                                 db_path=_OSV_DB)
                if osv_res.get("error"):
                    artifact["errors"].append("osv: {}".format(osv_res["error"]))
                # Only fold in the verdicts; the packages are already recorded
                # above with source=retirejs (add_osv_findings would relabel
                # them source=osv and duplicate the set).
                parsed = osv_res.get("parsed") or {}
                add_osv_findings(artifact, {
                    "packages": [],
                    "malicious": parsed.get("malicious", []),
                    "vulnerable": parsed.get("vulnerable", []),
                })
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
    elif mode in {"lockfile", "sbom", "dir"}:
        osv_res = osv_runner.run_osv_scan(target, mode=mode, db_path=_OSV_DB)
        if osv_res["error"]:
            artifact["errors"].append("osv: {}".format(osv_res["error"]))
        add_osv_findings(artifact, osv_res["parsed"])
    else:
        artifact["errors"].append("unsupported mode: {}".format(mode))

    # Opt-in GuardDog on an explicit, capped package list (never the whole set).
    if job.get("deep_analysis") and job.get("guarddog_packages"):
        for spec in job["guarddog_packages"][:100]:
            eco = spec.get("ecosystem")
            name = spec.get("name")
            if not eco or not name:
                continue
            # F3: one hostile coordinate (scan_package raises SanitizeError on a
            # bad name/version) must NOT abort the whole job and discard the OSV
            # verdicts already collected. Isolate each package.
            try:
                gd = guarddog_runner.scan_package(eco, name, spec.get("version"))
            except Exception as exc:
                artifact["errors"].append("guarddog {}: {}".format(name, exc))
                continue
            if gd["error"]:
                artifact["errors"].append("guarddog {}: {}".format(name, gd["error"]))
            add_guarddog_findings(artifact, gd["findings"], ecosystem=eco, name=name)

    # Self-validate: never emit something the clean side would reject.
    return validate_artifact(artifact)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Supply-chain dirty analyzer")
    parser.add_argument("--job", required=True, help="path to job spec JSON")
    parser.add_argument("--out", required=True, help="path to write artifact JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.job) as fh:
            job = json.load(fh)
    except (OSError, ValueError) as exc:
        _write_error(args.out, "cannot read job spec: {}".format(exc))
        return 2

    try:
        artifact = run_job(job)
    except ArtifactError as exc:
        _write_error(args.out, "artifact self-validation failed: {}".format(exc))
        return 3
    except Exception as exc:  # keep the box from crash-looping on tool weirdness
        _write_error(args.out, "analyzer error: {}".format(exc))
        return 4

    with open(args.out, "w") as fh:
        json.dump(artifact, fh)
    return 0


def _write_error(out_path, message):
    try:
        art = empty_artifact()
        art["errors"].append(message)
        with open(out_path, "w") as fh:
            json.dump(art, fh)
    except OSError:
        sys.stderr.write(message + "\n")


if __name__ == "__main__":
    sys.exit(main())
