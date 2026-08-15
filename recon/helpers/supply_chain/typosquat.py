"""D: typosquat detection over harvested package names.

Two checks, deliberately separated because they have different false-positive
profiles:

1. DIRECT HIT - the name is in the incident catalog's typosquat pairs or its
   bad-package set. Always on, no toggle: it only ever reports names the catalog
   already names, so it cannot produce a false positive. Worth stating plainly
   though: ~98% of those names come from GHSA and are already in the offline OSV
   database, so this is a safety net for a stale or never-synced ecosystem, not
   new detection.

2. EDIT DISTANCE - the name is 1-2 edits from a popular package without being
   it. This is the part that finds squats OSV has not seen, and the part that can
   be wrong, so it is behind a toggle and ships LOW severity.

Pure string work: no network, no filesystem beyond the baked-in reference list.
That is what keeps `harvest.py`'s network-free contract (S4) intact.

NOT redundant with GuardDog's typosquatting rule: both layers feed GuardDog only
what OSV already flagged, so that rule can never fire on an unflagged package.
"""

import os

__all__ = ["detect_typosquats", "load_popular_names", "levenshtein_within",
           "MIN_NAME_LEN", "MAX_EDIT_DISTANCE"]

# Below this length, 1-2 edits reaches too many legitimate packages ("qs", "ms",
# "ws", "fs" are all real and all within 1 edit of each other).
MIN_NAME_LEN = 5
MAX_EDIT_DISTANCE = 2

_DATA_NAME = "npm_popular.txt"
_POPULAR_CACHE = None


def _data_path():
    # recon/helpers/supply_chain/typosquat.py -> recon/data/npm_popular.txt
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(here)), "data", _DATA_NAME)


def load_popular_names(path=None, *, force_reload=False):
    """The reference set, loaded once. Never raises: a missing file disables the
    edit-distance check rather than failing the scan."""
    global _POPULAR_CACHE
    if _POPULAR_CACHE is not None and not force_reload and path is None:
        return _POPULAR_CACHE
    names = set()
    try:
        with open(path or _data_path()) as fh:
            for line in fh:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                names.add(line)
    except OSError:
        names = set()
    if path is None:
        _POPULAR_CACHE = names
    return names


def levenshtein_within(a, b, max_distance=MAX_EDIT_DISTANCE):
    """Edit distance, but only enough of it to answer '<= max_distance?'.

    Returns the distance, or max_distance + 1 for anything further. The length
    pre-check makes the common case (most pairs are nowhere near) O(1).
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_distance:
        return max_distance + 1

    previous = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        best = current[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            val = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(val)
            if val < best:
                best = val
        # Whole row already past the ceiling: no completion can come back under.
        if best > max_distance:
            return max_distance + 1
        previous = current
    return previous[lb]


def _finding(name, ecosystem, purl, original, incident_id, distance, kind):
    """A `suspicious` artifact entry. NEVER `malicious`: only an OSV MAL- id
    makes a package malware, and a name similarity is not that."""
    advisory = "typosquat-of-{}".format(original)
    if kind == "catalog":
        detail = ("The incident catalog lists this exact name as a typosquat of "
                  "{!r}.".format(original))
        severity = "medium"
    else:
        detail = ("Name is {} edit(s) from the popular package {!r} without being "
                  "it. This is a heuristic, not a confirmed verdict.".format(
                      distance, original))
        severity = "low"
    finding = {
        "name": name,
        "ecosystem": ecosystem,
        "advisory_id": advisory,
        "rule": "typosquat",
        "severity": severity,
        "confidence": "suspicious",
        "title": advisory,
        "detail": detail,
    }
    if purl:
        finding["purl"] = purl
    if incident_id:
        # Carried so B's enrichment can attach the write-up to it later.
        finding["message"] = "incident {}".format(incident_id)
    return finding


def detect_typosquats(packages, *, intel=None, fuzzy_enabled=False,
                      popular=None):
    """Return (findings, stats) for the harvested package list.

    `fuzzy_enabled` gates ONLY the edit-distance check. The catalog lookup always
    runs, because it reports nothing the catalog does not already assert.
    """
    stats = {"checked": 0, "catalog_hits": 0, "fuzzy_hits": 0,
             "fuzzy_enabled": bool(fuzzy_enabled), "catalog_available": False}
    findings = []
    if not packages:
        return findings, stats

    typosquats, bad_packages = {}, {}
    if intel is not None and getattr(intel, "available", False):
        typosquats = intel.typosquats or {}
        bad_packages = intel.packages or {}
        stats["catalog_available"] = True

    popular_names = popular if popular is not None else (
        load_popular_names() if fuzzy_enabled else set())

    seen = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = (pkg.get("name") or "").strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        stats["checked"] += 1
        ecosystem = pkg.get("ecosystem") or "npm"
        purl = pkg.get("purl")

        # 1. Catalog: an exact, labelled typosquat.
        label = typosquats.get(name)
        if label:
            findings.append(_finding(
                name, ecosystem, purl, label.get("original") or "a popular package",
                label.get("incident_id"), 0, "catalog"))
            stats["catalog_hits"] += 1
            continue

        # A name the catalog lists as bad at all is reported through the same
        # route, since the harvested package IS the named package.
        rec = bad_packages.get("{}/{}".format(str(ecosystem).lower(), name))
        if rec:
            findings.append(_finding(
                name, ecosystem, purl, name, rec.get("incident_id"), 0, "catalog"))
            stats["catalog_hits"] += 1
            continue

        # 2. Edit distance against the popular set.
        if not fuzzy_enabled or len(name) < MIN_NAME_LEN:
            continue
        if name in popular_names:
            continue  # it IS the popular package
        best_name, best_distance = None, MAX_EDIT_DISTANCE + 1
        for candidate in popular_names:
            if len(candidate) < MIN_NAME_LEN:
                continue
            distance = levenshtein_within(name, candidate)
            if distance < best_distance:
                best_name, best_distance = candidate, distance
                if distance == 1:
                    break
        if best_name is not None and best_distance <= MAX_EDIT_DISTANCE:
            findings.append(_finding(
                name, ecosystem, purl, best_name, None, best_distance, "fuzzy"))
            stats["fuzzy_hits"] += 1

    return findings, stats
