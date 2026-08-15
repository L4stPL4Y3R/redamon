"""Population of the supply-chain incident-intel volume (`redamon-sca-intel`).

Fetches the supplychainattack.org incident catalog and normalizes it into three
small lookup files plus a manifest. Mirrors `osv_db_sync.py`: the remote feed is
itself an untrusted supply-chain input, so it is host-pinned, envelope-validated,
byte-capped, every value charset-gated, and the result is mounted read-only
everywhere except here.

Run two ways:
  - the operator command `./redamon.sh sca-intel-sync`
  - the orchestrator's TTL-guarded refresh on the scan-spawn path

stdlib only, so it runs inside the tiny analyzer image with no new deps. In
particular this does NOT import services/knowledge_base/curation/safe_http.py:
that module is absent from the analyzer image and importing it fails at runtime,
not at build time. Its logic (scheme check, host allowlist re-checked on every
redirect hop, hop cap, byte cap) is mirrored below instead.

Output layout under --out:

    network_iocs.json   {"domains": {host: rec}, "wildcards": [[suffix, rec]],
                         "ips": {addr: rec}}
    packages.json       {"<ecosystem>/<name>": rec}
    typosquats.json     {"<fake>": {"original": ..., "incident_id": ...}}
    manifest.json       feed revision, fetch time, accept/drop counts
    .redamon_sca_intel_attempt   touched on EVERY attempt (retry floor)
"""

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .security import (MAX_STRING_LEN, SanitizeError, sanitize_advisory,
                       sanitize_ecosystem, sanitize_hostname, sanitize_name)

__all__ = ["sync_intel", "intel_is_fresh", "attempt_is_recent",
           "FEED_URL", "ALLOWED_HOSTS", "MAX_FEED_BYTES",
           "DEFAULT_TTL_SECONDS", "DEFAULT_RETRY_SECONDS",
           "MANIFEST_NAME", "ATTEMPT_MARKER"]

FEED_URL = "https://supplychainattack.org/incidents.json"
ALLOWED_HOSTS = ("supplychainattack.org",)

# The feed is ~5.3 MB. 32 MB leaves a wide margin for growth while still
# bounding a hostile or runaway response.
MAX_FEED_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 60

DEFAULT_TTL_SECONDS = 24 * 3600
# Retry floor after a FAILED or REJECTED fetch. Without this a feed that is down
# (or serving a bad envelope, which by contract leaves the previous files in
# place and so never advances the manifest) would be re-fetched on every single
# scan spawn for as long as it stays broken.
DEFAULT_RETRY_SECONDS = 3600

MANIFEST_NAME = "manifest.json"
ATTEMPT_MARKER = ".redamon_sca_intel_attempt"

# Entry caps. The feed is 3,595 incidents today; these bound a hostile feed.
MAX_INCIDENTS = 50000
MAX_PACKAGES_PER_INCIDENT = 50
MAX_REMEDIATION_STEPS = 20

# Public hosting apexes where a BARE wildcard covers every tenant of a shared
# platform. '*.workers.dev' is all of Cloudflare Workers: shipping it would flag
# every legitimate target that uses a Worker. A specific host under one of these
# ('ai-script.test0ing7.workers.dev') and a deeper wildcard ('*.cf99.workers.dev')
# both still name one attacker deployment and are kept.
PUBLIC_HOSTING_APEXES = frozenset({
    "workers.dev", "vercel.app", "netlify.app", "pages.dev", "web.app",
    "firebaseapp.com", "herokuapp.com", "github.io", "glitch.me",
    "repl.co", "replit.dev", "ngrok.io", "ngrok-free.app", "onrender.com",
    "fly.dev", "surge.sh", "azurewebsites.net", "cloudfront.net",
    "amplifyapp.com", "r2.dev", "trycloudflare.com",
})


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

class FeedError(RuntimeError):
    """The feed could not be fetched or did not look like the expected feed."""


def _assert_allowed(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FeedError("refusing non-http(s) URL (scheme={!r})".format(parsed.scheme))
    host = (parsed.hostname or "").lower()
    if not any(host == allowed.lower() for allowed in ALLOWED_HOSTS):
        raise FeedError("refusing request to off-allowlist host {!r}".format(host))


def fetch_feed(url=FEED_URL, *, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_FEED_BYTES,
               opener=None):
    """Host-allowlisted, size-capped GET returning the decoded JSON body.

    Redirects are followed MANUALLY so every hop's host is re-checked before a
    request is sent; an off-allowlist redirect target is refused. Never logs the
    URL with query parameters and never echoes the body on error.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _assert_allowed(current)
        req = urllib.request.Request(
            current,
            headers={"User-Agent": "RedAmon-sca-intel-sync",
                     "Accept": "application/json"},
        )
        try:
            # No redirect handler: a 3xx is returned rather than followed, so the
            # next hop goes back through _assert_allowed above.
            open_fn = opener if opener is not None else _open_no_redirect
            resp = open_fn(req, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") if exc.headers else None
                if not location:
                    raise FeedError("redirect with no Location header")
                current = location
                continue
            raise FeedError("feed returned HTTP {}".format(exc.code))
        except urllib.error.URLError as exc:
            raise FeedError("feed unreachable: {}".format(exc.reason))
        except OSError as exc:
            raise FeedError("feed unreachable: {}".format(exc))

        with resp:
            length = resp.headers.get("Content-Length") if resp.headers else None
            if length:
                try:
                    if int(length) > max_bytes:
                        raise FeedError("feed too large (Content-Length {})".format(length))
                except ValueError:
                    pass
            body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise FeedError("feed exceeded {} bytes".format(max_bytes))
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FeedError("feed is not valid JSON: {}".format(exc))

    raise FeedError("too many redirects")


def _open_no_redirect(req, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    return opener.open(req, timeout=timeout)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTPError so the caller re-validates the host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------------------
# Envelope + normalization
# ---------------------------------------------------------------------------

def validate_envelope(payload):
    """Reject anything that is not the expected feed shape, BEFORE ingesting.

    On rejection the caller leaves the previous derived files untouched; the one
    thing that must never happen is truncating good data to empty because the
    feed had a bad day.
    """
    if not isinstance(payload, dict):
        raise FeedError("feed must be a JSON object")
    incidents = payload.get("incidents")
    if not isinstance(incidents, list):
        raise FeedError("feed has no 'incidents' list")
    count = payload.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        raise FeedError("feed has no integer 'count'")
    if count <= 0:
        raise FeedError("feed reports count={}".format(count))
    if not incidents:
        raise FeedError("feed 'incidents' is empty")
    if len(incidents) > MAX_INCIDENTS:
        raise FeedError("feed has {} incidents (cap {})".format(
            len(incidents), MAX_INCIDENTS))
    return incidents


def _cap(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value[:MAX_STRING_LEN]


def _incident_record(inc):
    """The compact record shared by every lookup file."""
    return {
        "incident_id": inc["_id"],
        "url": _cap(inc.get("url")),
        "title": _cap(inc.get("title")),
        "status": _cap(inc.get("status")),
        "severity": _cap(inc.get("severity")),
        "summary": _cap(inc.get("summary")),
        "blast_radius": _cap(inc.get("blastRadius")),
        "remediation": inc.get("_remediation", []),
        "attack_vectors": inc.get("_attack_vectors", []),
        "last_updated": _cap(inc.get("lastUpdated")),
    }


def _norm_remediation(raw):
    """Remediation is free text or a list of steps; normalize to a capped list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out = []
    for step in raw[:MAX_REMEDIATION_STEPS]:
        if isinstance(step, dict):
            step = step.get("step") or step.get("text") or step.get("description")
        if step is None:
            continue
        text = _cap(step)
        if text:
            out.append(text)
    return out


def _norm_str_list(raw, cap=20):
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [_cap(x) for x in raw[:cap] if x]


def _ip_is_usable(addr):
    """Keep only globally routable addresses.

    A poisoned feed entry naming 127.0.0.1 or 10.0.0.0/8 would otherwise turn
    every internal target into a 'contacts malicious host' finding.

    `is_global` is the primary gate because it is the only one that covers the
    whole IANA special-purpose registry in one check. In particular CGNAT
    (100.64.0.0/10) is NOT in `is_private` on any Python we run, so a
    private-only check silently lets shared-carrier space through. The explicit
    checks below stay as belt-and-braces in case a future Python reclassifies
    one of them.
    """
    if not getattr(addr, "is_global", False):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified
                or getattr(addr, "is_site_local", False))


def _is_bare_public_apex_wildcard(host):
    """True for '*.workers.dev' (drop) but not '*.cf99.workers.dev' (keep)."""
    if not host.startswith("*."):
        return False
    body = host[2:]
    return body in PUBLIC_HOSTING_APEXES


def normalize(incidents):
    """Turn the raw incident list into the three lookup tables + drop counts.

    Every value passes a charset gate; a rejected value is DROPPED AND COUNTED,
    never silently vanished, so the sync report can be read as coverage.
    """
    domains, wildcards, ips, packages, typosquats = {}, [], {}, {}, {}
    stats = {
        "incidents": 0, "incidents_dropped": 0,
        "domains": 0, "domains_dropped": 0,
        "wildcards": 0, "wildcards_dropped_public_apex": 0,
        "ips": 0, "ips_dropped": 0,
        "packages": 0, "packages_dropped": 0,
        "typosquats": 0,
    }

    for inc in incidents:
        if not isinstance(inc, dict):
            stats["incidents_dropped"] += 1
            continue
        try:
            incident_id = sanitize_advisory(_cap(inc.get("id")) or None)
        except SanitizeError:
            incident_id = None
        if not incident_id:
            stats["incidents_dropped"] += 1
            continue

        inc = dict(inc)
        inc["_id"] = incident_id
        inc["_remediation"] = _norm_remediation(inc.get("remediation"))
        inc["_attack_vectors"] = _norm_str_list(inc.get("attackVectors"))
        rec = _incident_record(inc)
        stats["incidents"] += 1

        iocs = inc.get("iocs") or {}
        if not isinstance(iocs, dict):
            iocs = {}

        # ---- network IOCs -------------------------------------------------
        for raw in _norm_str_list(iocs.get("domains"), cap=200):
            # Raw IPs land in the domains array; route them to the IP validator
            # so the private-range drop applies to them too.
            try:
                addr = ipaddress.ip_address(raw.strip())
            except ValueError:
                addr = None
            if addr is not None:
                if _ip_is_usable(addr):
                    ips[str(addr)] = rec
                    stats["ips"] += 1
                else:
                    stats["ips_dropped"] += 1
                continue
            try:
                host = sanitize_hostname(raw)
            except SanitizeError:
                # Prose sentences and slash-joined garbage land here.
                stats["domains_dropped"] += 1
                continue
            if _is_bare_public_apex_wildcard(host):
                stats["wildcards_dropped_public_apex"] += 1
                continue
            if host.startswith("*."):
                wildcards.append([host[1:], rec])  # store as '.suffix'
                stats["wildcards"] += 1
            else:
                domains[host] = rec
                stats["domains"] += 1

        for raw in _norm_str_list(iocs.get("ips"), cap=200):
            try:
                addr = ipaddress.ip_address(raw.strip())
            except ValueError:
                stats["ips_dropped"] += 1
                continue
            if not _ip_is_usable(addr):
                stats["ips_dropped"] += 1
                continue
            ips[str(addr)] = rec
            stats["ips"] += 1

        # ---- package IOCs -------------------------------------------------
        for entry in (iocs.get("packages") or [])[:MAX_PACKAGES_PER_INCIDENT]:
            key = _package_key(entry)
            if key is None:
                stats["packages_dropped"] += 1
                continue
            packages[key] = rec
            stats["packages"] += 1

        # ---- typosquat labels ---------------------------------------------
        for fake, original in _typosquat_pairs(inc):
            typosquats[fake] = {"original": original, "incident_id": incident_id}
            stats["typosquats"] += 1

    return {
        "network_iocs": {"domains": domains, "wildcards": wildcards, "ips": ips},
        "packages": packages,
        "typosquats": typosquats,
        "stats": stats,
    }


def _package_key(entry):
    """'<ecosystem>/<name>' for a package IOC, or None if unusable.

    Matching is name-only by design: only 136 of 3,541 package IOCs are
    version-pinned, so a version match would drop most of the catalog. That is
    also why a hit here is weaker evidence than an OSV verdict and never sets a
    verdict of its own.
    """
    if isinstance(entry, str):
        name, ecosystem = entry, "npm"
    elif isinstance(entry, dict):
        name = entry.get("name") or entry.get("package")
        ecosystem = entry.get("ecosystem") or entry.get("registry") or "npm"
    else:
        return None
    if not name:
        return None
    try:
        name = sanitize_name(_cap(name))
        ecosystem = sanitize_ecosystem(_cap(ecosystem)) or "npm"
    except SanitizeError:
        return None
    return "{}/{}".format(ecosystem.lower(), name)


def _typosquat_pairs(inc):
    """Extract (fake, original) pairs the feed labels in affectedEntities notes.

    The catalog names the impersonated package in `affectedEntities[].note`
    (125 pairs). These are the ground truth for D's edit-distance threshold.
    """
    out = []
    entities = inc.get("affectedEntities")
    if not isinstance(entities, list):
        return out
    vectors = [v.lower() for v in inc.get("_attack_vectors", [])]
    if not any("typosquat" in v for v in vectors):
        return out
    for ent in entities[:MAX_PACKAGES_PER_INCIDENT]:
        if not isinstance(ent, dict):
            continue
        fake_raw = ent.get("name")
        note = ent.get("note") or ""
        if not fake_raw or not isinstance(note, str):
            continue
        original_raw = _original_from_note(note)
        if not original_raw:
            continue
        try:
            fake = sanitize_name(_cap(fake_raw))
            original = sanitize_name(_cap(original_raw))
        except SanitizeError:
            continue
        if fake == original:
            continue
        out.append((fake, original))
    return out


def _original_from_note(note):
    """Pull the impersonated package name out of a free-text note.

    The notes read like "typosquat of lodash" / "impersonates python-dateutil".
    Deliberately conservative: no match means no pair, because a wrong pair
    poisons D's ground-truth test set.
    """
    lowered = note.lower()
    for marker in ("typosquat of ", "typosquats ", "impersonates ",
                   "impersonating ", "mimics ", "squat of "):
        idx = lowered.find(marker)
        if idx == -1:
            continue
        tail = note[idx + len(marker):].strip()
        token = tail.split()[0] if tail.split() else ""
        return token.strip(".,;:'\"()[]")
    return None


# ---------------------------------------------------------------------------
# Freshness markers
# ---------------------------------------------------------------------------

def intel_is_fresh(out_path, ttl_seconds=DEFAULT_TTL_SECONDS):
    """True if a SUCCESSFUL sync landed within the TTL window.

    Keyed on manifest.json's mtime, which is written on success only, so there is
    no second source of truth to drift from.
    """
    try:
        age = time.time() - os.path.getmtime(os.path.join(out_path, MANIFEST_NAME))
    except OSError:
        return False
    return age < ttl_seconds


def attempt_is_recent(out_path, retry_seconds=DEFAULT_RETRY_SECONDS):
    """True if ANY attempt (success or failure) landed within the retry floor."""
    try:
        age = time.time() - os.path.getmtime(os.path.join(out_path, ATTEMPT_MARKER))
    except OSError:
        return False
    return age < retry_seconds


def _touch_attempt(out_path):
    try:
        os.makedirs(out_path, exist_ok=True)
        with open(os.path.join(out_path, ATTEMPT_MARKER), "w") as fh:
            fh.write(str(int(time.time())))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def sync_intel(out_path, *, url=FEED_URL, force=False,
               ttl_seconds=DEFAULT_TTL_SECONDS,
               retry_seconds=DEFAULT_RETRY_SECONDS,
               timeout=DEFAULT_TIMEOUT, fetcher=None):
    """Fetch, validate, normalize and write the intel files.

    Returns {"status": synced|skipped|failed, "detail": ..., "stats": {...}}.
    Never raises: a failure here must never block the scan that triggered it.
    """
    if not force:
        if intel_is_fresh(out_path, ttl_seconds):
            return {"status": "skipped", "detail": "within TTL", "stats": {}}
        if attempt_is_recent(out_path, retry_seconds):
            return {"status": "skipped", "detail": "within retry floor", "stats": {}}

    # Touched BEFORE the fetch: a hang that gets killed by the sidecar timeout
    # must still count as an attempt, or a wedged feed is retried every scan.
    _touch_attempt(out_path)

    try:
        payload = (fetcher or fetch_feed)(url, timeout=timeout)
        incidents = validate_envelope(payload)
    except FeedError as exc:
        # Previous derived files are left exactly as they were.
        return {"status": "failed", "detail": str(exc), "stats": {}}
    except Exception as exc:  # never raise into a scan spawn
        return {"status": "failed", "detail": "unexpected: {}".format(exc), "stats": {}}

    try:
        norm = normalize(incidents)
        revised = _cap(payload.get("revised")) or ""
        manifest = {
            "feed_url": url,
            "revised": revised,
            "fetched_at": int(time.time()),
            "count_reported": payload.get("count"),
            "count_ingested": norm["stats"]["incidents"],
            "stats": norm["stats"],
        }
        _write_all(out_path, norm, manifest)
    except OSError as exc:
        return {"status": "failed", "detail": "write failed: {}".format(exc),
                "stats": {}}
    except Exception as exc:
        return {"status": "failed", "detail": "normalize failed: {}".format(exc),
                "stats": {}}

    return {"status": "synced", "detail": "revised={}".format(revised),
            "stats": norm["stats"]}


def _write_all(out_path, norm, manifest):
    """Write every file atomically, manifest LAST.

    manifest.json is the freshness marker, so it must not exist newer than the
    data it describes; writing it last means a crash mid-write leaves a stale
    manifest and the next run retries rather than trusting half a dataset.
    """
    os.makedirs(out_path, exist_ok=True)
    _write_json(out_path, "network_iocs.json", norm["network_iocs"])
    _write_json(out_path, "packages.json", norm["packages"])
    _write_json(out_path, "typosquats.json", norm["typosquats"])
    _write_json(out_path, MANIFEST_NAME, manifest)
    _make_world_readable(out_path)


def _write_json(out_path, name, payload):
    final = os.path.join(out_path, name)
    tmp = final + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, final)


def _make_world_readable(out_path):
    """Add o+rX across the tree.

    Same reason as the OSV DB: this volume is consumed by NON-root, read-only
    scan containers. Written 0750 by root they would see an empty directory and
    silently produce no enrichment at all.
    """
    import stat as _stat
    for root, dirs, files in os.walk(out_path):
        for d in [root] + [os.path.join(root, x) for x in dirs]:
            try:
                os.chmod(d, os.stat(d).st_mode | _stat.S_IROTH | _stat.S_IXOTH
                         | _stat.S_IRGRP | _stat.S_IXGRP)
            except OSError:
                pass
        for f in files:
            fp = os.path.join(root, f)
            try:
                os.chmod(fp, os.stat(fp).st_mode | _stat.S_IROTH | _stat.S_IRGRP)
            except OSError:
                pass


def _main(argv=None):
    """CLI used by `redamon.sh sca-intel-sync` and the orchestrator sidecar."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sync the supply-chain incident intel volume.")
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", default=FEED_URL)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--retry-seconds", type=int, default=DEFAULT_RETRY_SECONDS)
    args = parser.parse_args(argv)

    result = sync_intel(args.out, url=args.url, force=args.force,
                        ttl_seconds=args.ttl_seconds,
                        retry_seconds=args.retry_seconds)
    # The drop report must be visible: counts, never silence.
    print(json.dumps(result, sort_keys=True))
    if result["status"] == "synced":
        # Sentinel the orchestrator greps for, so a TTL no-op is never logged as
        # a sync that happened.
        print("__DID_SYNC__")
    return 0 if result["status"] in ("synced", "skipped") else 1


if __name__ == "__main__":
    import sys

    sys.exit(_main())
