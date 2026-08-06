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
import sys

# supply_chain_common is bind-mounted at /app (like graph_db). PYTHONPATH=/app.
from supply_chain_common import osv_runner, retire_runner, guarddog_runner
from supply_chain_common.security import (
    validate_artifact, ARTIFACT_SCHEMA_VERSION, ArtifactError,
)

_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")


def _osv_findings_to_artifact(parsed, artifact):
    for pkg in parsed.get("packages", []):
        artifact["packages"].append({
            "purl": pkg.get("purl"),
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "ecosystem": pkg.get("ecosystem"),
            "source": "osv",
            "source_path": pkg.get("source_path"),
        })
    for mal in parsed.get("malicious", []):
        artifact["malicious"].append({
            "purl": mal.get("purl"),
            "name": mal.get("name"),
            "version": mal.get("version"),
            "ecosystem": mal.get("ecosystem"),
            "advisory_id": mal.get("advisory_id"),
            "severity": "high",
            "confidence": "malicious",
            "title": mal.get("summary") or mal.get("advisory_id"),
            "aliases": mal.get("aliases") or [],
        })
    for vul in parsed.get("vulnerable", []):
        artifact["vulnerable"].append({
            "purl": vul.get("purl"),
            "name": vul.get("name"),
            "version": vul.get("version"),
            "ecosystem": vul.get("ecosystem"),
            "advisory_id": vul.get("advisory_id"),
            "severity": "unknown",
            "confidence": "suspicious",
            "title": vul.get("summary") or vul.get("advisory_id"),
        })


def run_job(job):
    mode = job.get("mode")
    target = job.get("target")
    artifact = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "mode": mode if mode in {"lockfile", "sbom", "dir", "purls", "js-dir"} else None,
        "packages": [], "malicious": [], "vulnerable": [], "suspicious": [],
        "errors": [],
    }

    if mode == "js-dir":
        # Black-box harvest: retire.js over downloaded JS, then OSV over the
        # resulting SBOM/purls.
        retire_res = retire_runner.scan_js_dir(target)
        if retire_res["error"]:
            artifact["errors"].append("retire: {}".format(retire_res["error"]))
        for comp in retire_res["components"]:
            try:
                purl = retire_runner.to_purls([comp])
            except Exception:
                purl = []
            artifact["packages"].append({
                "name": comp.get("name"),
                "version": comp.get("version"),
                "ecosystem": "npm",
                "purl": purl[0] if purl else None,
                "source": "retirejs",
            })
        # OSV verdict on the harvested set would run here against a synthesized
        # SBOM; wired in Phase 3 when the harvest chain produces the SBOM file.
    elif mode in {"lockfile", "sbom", "dir"}:
        osv_res = osv_runner.run_osv_scan(target, mode=mode, db_path=_OSV_DB)
        if osv_res["error"]:
            artifact["errors"].append("osv: {}".format(osv_res["error"]))
        _osv_findings_to_artifact(osv_res["parsed"], artifact)
    else:
        artifact["errors"].append("unsupported mode: {}".format(mode))

    # Opt-in GuardDog on an explicit, capped package list (never the whole set).
    if job.get("deep_analysis") and job.get("guarddog_packages"):
        for spec in job["guarddog_packages"][:100]:
            eco = spec.get("ecosystem")
            name = spec.get("name")
            if not eco or not name:
                continue
            gd = guarddog_runner.scan_package(eco, name, spec.get("version"))
            if gd["error"]:
                artifact["errors"].append("guarddog {}: {}".format(name, gd["error"]))
            for f in gd["findings"]:
                artifact["suspicious"].append({
                    "name": f.get("package") or name,
                    "version": f.get("version"),
                    "ecosystem": eco,
                    "rule": f.get("rule"),
                    "severity": f.get("severity"),
                    "confidence": "suspicious",
                    "message": f.get("message"),
                    "soft_error": f.get("soft_error", False),
                })

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
        with open(out_path, "w") as fh:
            json.dump({
                "schema_version": ARTIFACT_SCHEMA_VERSION, "mode": None,
                "packages": [], "malicious": [], "vulnerable": [],
                "suspicious": [], "errors": [message],
            }, fh)
    except OSError:
        sys.stderr.write(message + "\n")


if __name__ == "__main__":
    sys.exit(main())
