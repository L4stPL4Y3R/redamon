"""retire.js runner + parser (black-box JS library harvest).

Verified against retire.js v5.4.3 (2026-08-06):
  - Scan a folder of downloaded JS:
      retire --path <dir> --outputformat json --outputpath <out.json>
  - Also supports --outputformat cyclonedxJSON for a ready-made SBOM.
  - Exit codes: 13 when vulnerabilities are found (override with --exitwith),
    0 when none. Exit 13 is NOT an error; parse the JSON.

This is the black-box capability L2 needs: it identifies component+version from
file content/hash/filename/uri with ZERO manifest. A component with no
`vulnerabilities` is still a harvested package (keep it; OSV decides malicious).
"""

import json
import os

from ._run import run_argv
from .purl import build_purl
from .security import sanitize_name

__all__ = ["scan_js_dir", "parse_retire_json", "to_purls", "RETIRE_OK_EXIT_CODES"]

# retire.js exits 13 on findings, 0 on none. Both are success for us.
RETIRE_OK_EXIT_CODES = {0, 13}


def scan_js_dir(js_dir, *, out_path=None, timeout=300, binary="retire"):
    """Run retire.js over a directory of downloaded .js files.

    Returns {raw, components, vulns, error}. `components` is the harvested
    package set (name+version+detection); `vulns` is the known-vulnerable detail.
    """
    if not out_path:
        out_path = os.path.join(js_dir, "_retire_out.json")

    argv = [binary, "--path", str(js_dir),
            "--outputformat", "json",
            "--outputpath", str(out_path),
            # Force exit 0 so a findings run is not confused with a tool error;
            # we parse the JSON regardless.
            "--exitwith", "0"]

    res = run_argv(argv, timeout=timeout)

    error = res["error"]
    if error is None and res["exit_code"] not in RETIRE_OK_EXIT_CODES:
        error = "retire exit {}: {}".format(
            res["exit_code"], (res["stderr"] or "").strip()[:500])

    raw = None
    # retire writes JSON to --outputpath, not stdout.
    try:
        with open(out_path, "r") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        if error is None:
            error = "retire output file missing or not JSON"

    parsed = parse_retire_json(raw)
    return {"raw": raw, "components": parsed["components"],
            "vulns": parsed["vulns"], "error": error}


def parse_retire_json(raw):
    """Parse retire.js `--outputformat json` into components + vulns.

    Schema: {data: [{file, results: [{component, version, detection,
    vulnerabilities: [...]}]}]}. Fully defensive; never raises.
    """
    components = []
    vulns = []
    seen = set()
    if not isinstance(raw, dict):
        return {"components": components, "vulns": vulns}

    for file_entry in raw.get("data") or []:
        if not isinstance(file_entry, dict):
            continue
        file_path = file_entry.get("file")
        for comp in file_entry.get("results") or []:
            if not isinstance(comp, dict):
                continue
            name = comp.get("component")
            version = comp.get("version")
            if not name:
                continue
            try:
                sanitize_name(name)
            except Exception:
                continue
            key = (name, version)
            if key not in seen:
                seen.add(key)
                components.append({
                    "name": name,
                    "version": version,
                    "detection": comp.get("detection"),
                    "file": file_path,
                })
            for vuln in comp.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                idents = vuln.get("identifiers") or {}
                cves = idents.get("CVE") or []
                vulns.append({
                    "name": name,
                    "version": version,
                    "severity": vuln.get("severity"),
                    "cves": cves,
                    "summary": idents.get("summary") or idents.get("issue") or "",
                    "info": vuln.get("info") or [],
                })
    return {"components": components, "vulns": vulns}


def to_purls(components):
    """Map harvested retire.js components (all npm) to purl strings.

    retire.js identifies JS libraries by their npm name, so the ecosystem is
    always npm here. Components without a version still produce a name-only purl.
    """
    purls = []
    for comp in components or []:
        name = comp.get("name")
        version = comp.get("version")
        if not name:
            continue
        try:
            purls.append(build_purl("npm", name, version))
        except Exception:
            continue
    return purls
