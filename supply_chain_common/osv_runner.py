"""OSV-Scanner runner + parser (the verdict engine).

Verified against OSV-Scanner v2.4.0 (2026-08-06):
  - Scan a lockfile:   osv-scanner scan source -L <path> --format json
  - Scan a directory:  osv-scanner scan source -r <dir> --format json
  - Scan an SBOM:       osv-scanner scan source <bom.cdx.json> --format json
                        (v2 auto-detects CycloneDX/SPDX by content; there is no
                         separate --sbom flag in v2, unlike v1)
  - OFFLINE (mandatory for passivity): pass --offline and point the scanner at
    the pre-downloaded local DB via the environment variable
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<db_path>. The DB is fetched ONCE by the
    Phase-0 updater with --download-offline-databases; scans never download.
    VERIFIED 2026-08-06 against v2.4.0: --offline loads the local DB (logs
    "Loaded npm local db from <path>/osv-scanner/npm/all.zip") and matches MAL-
    ids. --offline-vulnerabilities did NOT load the local DB in this build and
    returned empty results; do not use it for the offline path. The plan's §2
    said --offline-vulnerabilities; this corrects it.
  - LOCKFILE NAME MATTERS: osv-scanner picks the extractor from the file's
    BASENAME (package-lock.json, requirements.txt, ...). A path like /work/pl.json
    fails with "could not determine extractor". Callers MUST name the scanned
    file with a recognized lockfile name (or pass lockfile_type to force it).
  - Exit codes: 0 = no findings, 1 = findings present, 127/128/... = tool error.
    We never gate on exit code alone; anything outside {0,1} is a runner error
    but we still attempt to parse stdout.

A vulnerability whose `id` starts with 'MAL-' is a terminal MALICIOUS verdict.
CVE-/GHSA- ids are known-vulnerable (not malicious) and are routed to the
`vulnerable` bucket, never written as a malicious finding by this feature.
"""

import json
import os

from ._run import run_argv
from .purl import build_purl
from .security import sanitize_name

__all__ = ["run_osv_scan", "parse_osv_json", "OSV_OK_EXIT_CODES"]

OSV_OK_EXIT_CODES = {0, 1}

_MODE_FLAG = {
    "lockfile": "-L",
    "dir": "-r",
    # sbom: passed as a positional path (v2 auto-detects the SBOM format)
    "sbom": None,
}


def run_osv_scan(target, *, mode="lockfile", db_path=None, offline=True,
                 timeout=120, binary="osv-scanner"):
    """Run osv-scanner over `target` and return {raw, parsed, exit_code, error}.

    `mode` in {lockfile, dir, sbom}. `target` is a filesystem path already
    inside a trusted scratch dir (the caller owns path safety). `db_path` is the
    local OSV DB cache directory; required when offline=True.
    """
    if mode not in _MODE_FLAG:
        return {"raw": None, "parsed": _empty_parsed(),
                "exit_code": None, "error": "unknown mode: {}".format(mode)}

    if offline:
        # F5: running --offline with no local DB (missing dir OR an empty volume
        # that was created but never populated by `redamon.sh supply-chain-sync`)
        # returns an EMPTY result with exit 0 - a silent false-clean where a
        # genuinely malicious package passes. Fail hard with an actionable error
        # instead of reporting a misleading clean verdict.
        db = str(db_path) if db_path else ""
        if not db or not os.path.isdir(db) or not os.listdir(db):
            return {"raw": None, "parsed": _empty_parsed(), "exit_code": None,
                    "error": ("offline OSV DB missing or empty at {!r}; run "
                              "'./redamon.sh supply-chain-sync <ecosystems>' "
                              "first".format(db_path))}

    argv = [binary, "scan", "source"]
    flag = _MODE_FLAG[mode]
    if flag:
        argv += [flag, str(target)]
    else:
        argv += [str(target)]

    env = dict(os.environ)
    if offline:
        # --offline (NOT --offline-vulnerabilities) is what loads the local DB
        # and matches MAL- ids in v2.4.0. Verified 2026-08-06; see module docstring.
        argv.append("--offline")
        if db_path:
            env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(db_path)
    argv += ["--format", "json"]

    res = run_argv(argv, timeout=timeout, env=env)

    error = res["error"]
    if error is None and res["exit_code"] not in OSV_OK_EXIT_CODES:
        # Non-{0,1} exit is a tool/usage error. Keep stderr context but still try
        # to parse whatever stdout we got.
        error = "osv-scanner exit {}: {}".format(
            res["exit_code"], (res["stderr"] or "").strip()[:500])

    raw = None
    if res["stdout"]:
        try:
            raw = json.loads(res["stdout"])
        except (ValueError, TypeError):
            if error is None:
                error = "osv-scanner produced non-JSON output"

    return {
        "raw": raw,
        "parsed": parse_osv_json(raw),
        "exit_code": res["exit_code"],
        "error": error,
    }


def _empty_parsed():
    return {"packages": [], "malicious": [], "vulnerable": []}


def parse_osv_json(raw):
    """Split an osv-scanner JSON document into packages / malicious / vulnerable.

    Fully defensive: `raw` may be None, `results` may be [] or null, a package
    may have no `vulnerabilities`. Never raises.
    """
    out = _empty_parsed()
    if not isinstance(raw, dict):
        return out

    for result in raw.get("results") or []:
        if not isinstance(result, dict):
            continue
        source_path = ((result.get("source") or {}).get("path")) if isinstance(
            result.get("source"), dict) else None
        for pkg_entry in result.get("packages") or []:
            if not isinstance(pkg_entry, dict):
                continue
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name")
            version = pkg.get("version")
            ecosystem = pkg.get("ecosystem")
            if not name or not ecosystem:
                continue
            try:
                sanitize_name(name)
                purl = build_purl(ecosystem, name, version)
            except Exception:
                # A package name that fails our charset gate is not something we
                # will emit; skip it rather than risk it downstream.
                continue

            out["packages"].append({
                "purl": purl,
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "source_path": source_path,
            })

            for vuln in pkg_entry.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = vuln.get("id") or ""
                finding = {
                    "purl": purl,
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "advisory_id": vid,
                    "aliases": vuln.get("aliases") or [],
                    "summary": vuln.get("summary") or "",
                }
                if vid.startswith("MAL-"):
                    out["malicious"].append(finding)
                else:
                    # CVE-, GHSA-, and anything else = known-vulnerable, not
                    # malicious. Kept for the raw path; not a MalPackageFinding.
                    out["vulnerable"].append(finding)

    return out
