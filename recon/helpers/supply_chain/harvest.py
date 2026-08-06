"""L2 black-box package harvest (plan Phase 3.2).

Infers the npm package set a LIVE target actually serves, with ZERO manifest,
from data JS-recon ALREADY downloaded:

  1. Source-map mining: node_modules/(@scope/)?<pkg> paths in a source map's
     `sources[]` (exact names). No new fetch -> no SSRF surface (S4).
  2. Widened imports: unscoped/scoped names from JS import/require statements.
  3. Technology -> purl: httpx/wappalyzer tech+version already in the graph.

Everything here is PURE parsing of in-memory strings; it makes NO network calls
(forbidding raw requests.get satisfies S4 by construction). Every harvested name
passes supply_chain_common.security.sanitize_name before use (S6/S7). The result
is a deduped purl set + a synthesized CycloneDX SBOM that the OSV verdict step
scans offline.
"""

import re

from supply_chain_common.purl import build_purl
from supply_chain_common.security import sanitize_name, SanitizeError
# SBOM synthesis is generic; it lives in the shared module so the OSV verdict
# path can use it without importing the recon.helpers package. Re-exported here
# so harvest keeps a single, cohesive public API.
from supply_chain_common.artifact import to_cyclonedx

__all__ = [
    "mine_sourcemap_packages", "mine_import_packages",
    "technologies_to_packages", "harvest_packages", "to_cyclonedx",
]

# node_modules/<pkg> where <pkg> is a scoped (@scope/name) or unscoped (name)
# package. Stops at the next '/'. Handles nested node_modules (findall).
_NODE_MODULES_RE = re.compile(r"node_modules/((?:@[^/@\s]+/)?[^/@\s][^/\s]*)")

# JS import/require of a bare module specifier (scoped or unscoped). Excludes
# relative ('./x') and absolute ('/x') paths and URLs.
_IMPORT_RE = re.compile(
    r"""(?:import\s+[^'"]*?from\s*|require\(\s*|import\(\s*|from\s+)"""
    r"""['"]((?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+)['"]""")

# A few common tech display-names -> their npm package name.
_TECH_NPM_ALIASES = {
    "react": "react", "vue.js": "vue", "vue": "vue", "angular": "@angular/core",
    "angularjs": "angular", "jquery": "jquery", "lodash": "lodash",
    "next.js": "next", "nuxt.js": "nuxt", "moment.js": "moment",
    "backbone.js": "backbone", "d3": "d3", "bootstrap": "bootstrap",
    "axios": "axios", "express": "express",
}


def _safe(name):
    try:
        sanitize_name(name)
        return True
    except SanitizeError:
        return False


def mine_sourcemap_packages(source_maps):
    """Extract npm packages from source-map `source_files`/`sources` lists.

    `source_maps` is the JS-recon source_maps result list; each item may carry
    `source_files` (our stored key) and/or `sources`. Returns [{name, version,
    ecosystem, source}]. Versions are unknown from paths (None).
    """
    out = {}
    for sm in source_maps or []:
        if not isinstance(sm, dict):
            continue
        files = sm.get("source_files") or sm.get("sources") or []
        for path in files:
            if not isinstance(path, str):
                continue
            for m in _NODE_MODULES_RE.findall(path):
                name = m.strip()
                if not name or not _safe(name):
                    continue
                out.setdefault(name, {"name": name, "version": None,
                                      "ecosystem": "npm", "source": "sourcemap"})
    return list(out.values())


def mine_import_packages(js_contents):
    """Extract bare-specifier packages from raw JS content strings."""
    out = {}
    for content in js_contents or []:
        if not isinstance(content, str):
            continue
        for name in _IMPORT_RE.findall(content):
            name = name.strip()
            # Skip obvious relative/builtin noise already excluded by the regex.
            if not name or not _safe(name):
                continue
            out.setdefault(name, {"name": name, "version": None,
                                  "ecosystem": "npm", "source": "import"})
    return list(out.values())


def technologies_to_packages(technologies):
    """Map httpx/wappalyzer technologies to npm packages (best-effort).

    `technologies` is a list of {name, version} (or plain strings). Only names
    with a known npm mapping are emitted, to avoid inventing non-npm purls.
    """
    out = {}
    for tech in technologies or []:
        if isinstance(tech, dict):
            raw = tech.get("name") or ""
            version = tech.get("version")
        else:
            raw = str(tech)
            version = None
        key = raw.strip().lower()
        npm = _TECH_NPM_ALIASES.get(key)
        if not npm or not _safe(npm):
            continue
        ver = version if version and _safe_version(version) else None
        out.setdefault((npm, ver), {"name": npm, "version": ver,
                                    "ecosystem": "npm", "source": "wappalyzer"})
    return list(out.values())


def _safe_version(v):
    from supply_chain_common.security import sanitize_version, SanitizeError
    try:
        sanitize_version(v)
        return True
    except SanitizeError:
        return False


def harvest_packages(*, source_maps=None, js_contents=None, technologies=None):
    """Run every harvest source and dedup into a single purl-keyed set.

    Best evidence wins on a name clash: a source-map/import name with a version
    from wappalyzer is preferred. Returns [{purl, name, version, ecosystem,
    source}].
    """
    collected = []
    collected += mine_sourcemap_packages(source_maps)
    collected += mine_import_packages(js_contents)
    collected += technologies_to_packages(technologies)

    by_name = {}
    for pkg in collected:
        name = pkg["name"]
        prev = by_name.get(name)
        # Keep the entry that has a concrete version; otherwise first-seen.
        if prev is None or (pkg.get("version") and not prev.get("version")):
            by_name[name] = pkg

    result = []
    for pkg in by_name.values():
        try:
            purl = build_purl(pkg["ecosystem"], pkg["name"], pkg.get("version"))
        except SanitizeError:
            continue
        result.append({**pkg, "purl": purl})
    return result


# to_cyclonedx is imported from supply_chain_common.artifact above.
