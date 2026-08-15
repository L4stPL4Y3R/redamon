"""Hardening pass over the supply-chain intel feature.

Section: root-agent. Covers the categories the feature actually has:
tenant isolation, idempotency, boundary/hostile inputs, contract stability for
rows written before the feature existed, and a bound on query count.

Deliberately NOT covered here, each with its reason:
  - migration rollback: the schema change is two nullable columns plus two
    boolean defaults, all additive. Prisma db push has no down-migration in this
    repo (push-based, never `migrate`), so there is no rollback path to test.
  - HTTP timeout behaviour of the real feed: `fetch_feed` is driven through an
    injected fetcher everywhere; the timeout is a urllib argument, and asserting
    urllib honours it tests the stdlib, not this code.
  - cache invalidation of the module-level Intel cache in a long-lived process:
    covered by `reset_cache` unit tests; the production behaviour (restart
    traffic-ingest to pick up a newer feed) is documented, not enforced in code.
"""

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_REPO, os.path.join(_REPO, "scanners")):
    if p not in sys.path:
        sys.path.insert(0, p)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from supply_chain_common import intel as intel_mod  # noqa: E402
from supply_chain_common import intel_sync  # noqa: E402
from graph_db.mixins.supply_chain_mixin import SupplyChainMixin  # noqa: E402


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "MERGE (dom)" in query:
            return FakeResult({"linked": 1})
        if "RETURN count" in query:
            return FakeResult({"linked": 1, "c": 1})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class Writer(SupplyChainMixin):
    def __init__(self, session):
        self.driver = FakeDriver(session)


def _incident(iid="SCA-0001", **kw):
    base = {
        "id": iid, "url": "https://supplychainattack.org/i/" + iid,
        "title": "Incident", "status": "confirmed", "severity": "high",
        "summary": "A summary.", "blastRadius": "3,000 downloads",
        "remediation": ["Remove it"], "attackVectors": ["malicious-package"],
        "lastUpdated": "2026-08-01", "iocs": {},
    }
    base.update(kw)
    return base


def _correlation(base_url="https://target.example.com", iid="SCA-0001"):
    return {"correlations": [{
        "base_url": base_url, "matched_host": "cdn.evil.example",
        "source_url": "https://cdn.evil.example/a.js",
        "evidence": "graph-host-match",
        "incident": {"incident_id": iid, "url": "https://x.test/" + iid,
                     "title": "t", "status": "confirmed", "summary": "s",
                     "blast_radius": "b", "remediation": ["r"],
                     "attack_vectors": ["v"], "last_updated": "2026-08-01",
                     "feed_revised": "2026-08-11"},
    }], "checked": 1, "available": True}


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation(unittest.TestCase):
    """One tenant's incident data must never become another tenant's.

    Every entity node this feature writes carries the {natural key, user_id,
    project_id} triple. Without it, two projects that both contact the same
    attacker host would MERGE into ONE ThreatPulse and each would see the
    other's correlation.
    """

    def _pulse_kwargs(self, uid, pid):
        session = FakeSession()
        Writer(session).update_graph_from_sca_intel(_correlation(), uid, pid)
        return next(kw for q, kw in session.queries if "ThreatPulse" in q)

    def test_same_incident_in_two_projects_uses_two_tenant_scoped_merges(self):
        a = self._pulse_kwargs("u1", "p1")
        b = self._pulse_kwargs("u1", "p2")
        # Same natural key...
        self.assertEqual(a["pulse_id"], b["pulse_id"])
        # ...but the MERGE is scoped, so they are different nodes.
        self.assertEqual((a["uid"], a["pid"]), ("u1", "p1"))
        self.assertEqual((b["uid"], b["pid"]), ("u1", "p2"))

    def test_every_pattern_in_the_correlation_write_is_tenant_scoped(self):
        session = FakeSession()
        Writer(session).update_graph_from_sca_intel(_correlation(), "u1", "p1")
        query = next(q for q, _ in session.queries if "ThreatPulse" in q)
        # Both node patterns (BaseURL and ThreatPulse) carry the triple.
        for pattern in ("MATCH (u:BaseURL {", "MERGE (tp:ThreatPulse {"):
            head = query.split(pattern)[1].split("})")[0]
            self.assertIn("user_id: $uid", head, pattern)
            self.assertIn("project_id: $pid", head, pattern)

    def test_the_base_url_anchor_cannot_be_crossed_between_tenants(self):
        """A BaseURL belonging to another project must not satisfy the MATCH."""
        session = FakeSession()
        Writer(session).update_graph_from_sca_intel(_correlation(), "u1", "p1")
        query = next(q for q, _ in session.queries if "ThreatPulse" in q)
        anchor = query.split("MATCH (u:BaseURL {")[1].split("})")[0]
        self.assertIn("url: $base_url", anchor)
        self.assertIn("user_id: $uid", anchor)
        self.assertIn("project_id: $pid", anchor)

    def test_finding_enrichment_writes_are_tenant_scoped(self):
        session = FakeSession()
        Writer(session).update_graph_from_supply_chain(
            {"packages": [], "vulnerable": [], "suspicious": [],
             "malicious": [{"purl": "pkg:npm/x@1", "name": "x",
                            "ecosystem": "npm", "advisory_id": "MAL-1",
                            "incident_id": "SCA-1"}]}, "u9", "p9")
        query, kwargs = next((q, k) for q, k in session.queries
                             if "MalPackageFinding" in q)
        self.assertEqual((kwargs["uid"], kwargs["pid"]), ("u9", "p9"))
        self.assertIn("user_id: $uid", query)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency(unittest.TestCase):

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="sca-idem-")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)
        intel_mod.reset_cache()
        self.addCleanup(intel_mod.reset_cache)

    def _sync(self, payload, **kw):
        return intel_sync.sync_intel(
            self.out, fetcher=lambda url, timeout=None: payload, **kw)

    def test_syncing_the_same_feed_twice_leaves_identical_files(self):
        feed = {"revised": "2026-08-11", "count": 1,
                "incidents": [_incident(iocs={"domains": ["evil.example.com"]})]}
        self._sync(feed, force=True)
        first = {n: open(os.path.join(self.out, n)).read()
                 for n in ("network_iocs.json", "packages.json", "typosquats.json")}
        self._sync(feed, force=True)
        second = {n: open(os.path.join(self.out, n)).read() for n in first}
        self.assertEqual(first, second)

    def test_normalize_is_deterministic(self):
        """Same input, same output - JSON is written sorted so a re-sync that
        changes nothing produces byte-identical files."""
        inc = [_incident(iocs={"domains": ["b.example.com", "a.example.com"]})]
        self.assertEqual(json.dumps(intel_sync.normalize(inc), sort_keys=True),
                         json.dumps(intel_sync.normalize(inc), sort_keys=True))

    def test_enriching_twice_is_a_no_op(self):
        """The pipeline can re-run enrichment (a retry, a re-import) without
        duplicating or mutating anything."""
        intel = intel_mod.Intel(
            packages={"npm/evil": {"incident_id": "SCA-1", "url": "",
                                   "summary": "s", "blast_radius": "b",
                                   "remediation": ["r"], "status": "confirmed"}},
            revised="2026-08-11", available=True)
        art = {"malicious": [{"name": "evil", "ecosystem": "npm"}],
               "vulnerable": [], "suspicious": [], "errors": []}
        once = copy.deepcopy(intel_mod.enrich_findings(copy.deepcopy(art), intel))
        twice = intel_mod.enrich_findings(copy.deepcopy(once), intel)
        self.assertEqual(once, twice)

    def test_unavailable_enrichment_does_not_stack_errors_per_finding(self):
        art = {"malicious": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
               "vulnerable": [], "suspicious": [], "errors": []}
        out = intel_mod.enrich_findings(art, intel_mod.Intel())
        self.assertEqual(len(out["errors"]), 1)


# ---------------------------------------------------------------------------
# Boundaries and hostile input
# ---------------------------------------------------------------------------

class TestBoundaryInputs(unittest.TestCase):

    def _norm(self, **iocs):
        return intel_sync.normalize([_incident(iocs=iocs)])

    def test_empty_feed_arrays_are_handled(self):
        norm = self._norm(domains=[], ips=[], packages=[])
        self.assertEqual(norm["network_iocs"]["domains"], {})
        self.assertEqual(norm["stats"]["incidents"], 1)

    def test_null_versus_missing_ioc_keys(self):
        self.assertEqual(intel_sync.normalize([_incident(iocs=None)])["stats"]["incidents"], 1)
        self.assertEqual(intel_sync.normalize([_incident()])["stats"]["incidents"], 1)

    def test_iocs_of_the_wrong_type_do_not_crash(self):
        for bad in ("a string", 42, ["a", "list"]):
            norm = intel_sync.normalize([_incident(iocs=bad)])
            self.assertEqual(norm["stats"]["incidents"], 1, repr(bad))

    def test_unicode_hostname_is_rejected_not_crashed(self):
        """IDN arrives punycoded in real feeds; raw unicode is not LDH."""
        norm = self._norm(domains=["еvil.example.com", "日本.example"])
        self.assertEqual(norm["network_iocs"]["domains"], {})
        self.assertEqual(norm["stats"]["domains_dropped"], 2)

    def test_punycode_hostname_is_accepted(self):
        norm = self._norm(domains=["xn--80ak6aa92e.example.com"])
        self.assertIn("xn--80ak6aa92e.example.com", norm["network_iocs"]["domains"])

    def test_hostname_at_the_length_limit(self):
        label = "a" * 63           # 63*3 + 3 dots = 192, + 61 = 253
        host = ".".join([label, label, label, "a" * 61])
        self.assertEqual(len(host), 253)
        norm = self._norm(domains=[host])
        self.assertIn(host, norm["network_iocs"]["domains"])

    def test_hostname_one_over_the_length_limit_is_dropped(self):
        label = "a" * 63
        host = ".".join([label, label, label, "a" * 62])   # 254
        self.assertEqual(len(host), 254)
        norm = self._norm(domains=[host])
        self.assertEqual(norm["network_iocs"]["domains"], {})

    def test_label_over_63_chars_is_dropped(self):
        norm = self._norm(domains=["{}.example.com".format("a" * 64)])
        self.assertEqual(norm["network_iocs"]["domains"], {})

    def test_huge_ioc_array_is_capped_per_incident(self):
        norm = self._norm(domains=["h{}.example.com".format(i) for i in range(5000)])
        self.assertLessEqual(len(norm["network_iocs"]["domains"]), 200)

    def test_ipv6_is_handled(self):
        norm = self._norm(ips=["2001:db8::1", "::1", "fe80::1"])
        # 2001:db8::/32 is documentation space and not globally routable.
        self.assertEqual(norm["network_iocs"]["ips"], {})
        self.assertEqual(norm["stats"]["ips_dropped"], 3)

    def test_a_routable_ipv6_is_kept(self):
        norm = self._norm(ips=["2606:4700:4700::1111"])
        self.assertIn("2606:4700:4700::1111", norm["network_iocs"]["ips"])

    def test_envelope_count_disagreeing_with_the_list_is_still_ingested(self):
        """The publisher's `count` is metadata; the list is the data."""
        feed = {"revised": "x", "count": 999, "incidents": [_incident()]}
        self.assertEqual(len(intel_sync.validate_envelope(feed)), 1)

    def test_feed_over_the_incident_cap_is_rejected_whole(self):
        feed = {"revised": "x", "count": 1,
                "incidents": [{}] * (intel_sync.MAX_INCIDENTS + 1)}
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope(feed)


# ---------------------------------------------------------------------------
# Contract stability
# ---------------------------------------------------------------------------

class TestContracts(unittest.TestCase):

    def test_rows_written_before_the_feature_still_load(self):
        """A finding stored by an older scan has no incident_* keys at all."""
        from graph_db.mixins.supply_chain_mixin import _incident_params

        old = {"purl": "pkg:npm/x@1", "name": "x", "ecosystem": "npm",
               "advisory_id": "MAL-1", "severity": "critical"}
        params = _incident_params(old)
        self.assertTrue(all(v is None for v in params.values()))

    def test_an_intel_file_from_an_older_sync_shape_still_loads(self):
        """Forward compatibility: unknown extra keys must not break the reader."""
        d = tempfile.mkdtemp(prefix="sca-shape-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "manifest.json"), "w") as fh:
            json.dump({"revised": "2026-08-11", "future_field": 1}, fh)
        with open(os.path.join(d, "network_iocs.json"), "w") as fh:
            json.dump({"domains": {"a.example": {"incident_id": "X",
                                                 "unknown_key": "y"}},
                       "wildcards": [], "ips": {}}, fh)
        for name in ("packages.json", "typosquats.json"):
            with open(os.path.join(d, name), "w") as fh:
                json.dump({}, fh)
        intel = intel_mod.load_intel(d, force_reload=True)
        self.addCleanup(intel_mod.reset_cache)
        self.assertTrue(intel.available)
        self.assertEqual(intel_mod.match_host("a.example", intel)["incident_id"], "X")

    def test_malformed_wildcard_entries_are_skipped_not_fatal(self):
        d = tempfile.mkdtemp(prefix="sca-wild-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "manifest.json"), "w") as fh:
            json.dump({"revised": "x"}, fh)
        with open(os.path.join(d, "network_iocs.json"), "w") as fh:
            json.dump({"domains": {}, "ips": {},
                       "wildcards": [["good.example"], "nope", 42,
                                     [".ok.example", {"incident_id": "K"}]]}, fh)
        for name in ("packages.json", "typosquats.json"):
            with open(os.path.join(d, name), "w") as fh:
                json.dump({}, fh)
        intel = intel_mod.load_intel(d, force_reload=True)
        self.addCleanup(intel_mod.reset_cache)
        self.assertEqual(len(intel.wildcards), 1)
        self.assertEqual(intel_mod.match_host("a.ok.example", intel)["incident_id"], "K")


# ---------------------------------------------------------------------------
# Query count
# ---------------------------------------------------------------------------

class TestQueryCount(unittest.TestCase):
    """The correlation writer runs one statement per matched incident.

    Not per (incident x package) and not per BaseURL: the package-anchoring path
    above it was already fixed once for exactly that (it re-wrote the whole
    artifact per BaseURL, ~500 round-trips where ~250 were needed).
    """

    def test_one_query_per_correlation(self):
        corr = {"available": True, "checked": 9, "correlations": [
            dict(_correlation(iid="SCA-{}".format(i))["correlations"][0])
            for i in range(9)]}
        session = FakeSession()
        Writer(session).update_graph_from_sca_intel(corr, "u1", "p1")
        pulse_queries = [q for q, _ in session.queries if "ThreatPulse" in q]
        self.assertEqual(len(pulse_queries), 9)

    def test_no_query_at_all_when_nothing_matched(self):
        session = FakeSession()
        Writer(session).update_graph_from_sca_intel(
            {"correlations": [], "available": True}, "u1", "p1")
        self.assertEqual(session.queries, [])

    def test_enrichment_adds_no_queries(self):
        """B is a dictionary join in the CLEAN zone, not a graph round trip."""
        intel = intel_mod.Intel(packages={"npm/x": {"incident_id": "S"}},
                                available=True, revised="r")
        art = {"malicious": [{"name": "x", "ecosystem": "npm"}],
               "vulnerable": [], "suspicious": [], "errors": []}
        intel_mod.enrich_findings(art, intel)   # no session anywhere
        self.assertEqual(art["malicious"][0]["incident_id"], "S")


if __name__ == "__main__":
    unittest.main()


class TestCoverageReporting(unittest.TestCase):
    """The sync report is read as coverage, so it must not flatter itself.

    The counters count occurrences; the tables are keyed by indicator, so
    several incidents naming the same host collapse into one entry. Reporting
    only the occurrence count overstated usable coverage 5x on the live feed
    (1,159 "domains" for 221 actual lookup entries).
    """

    def test_unique_counts_are_reported_alongside_occurrences(self):
        incidents = [
            _incident("SCA-1", iocs={"domains": ["same.example.com"]}),
            _incident("SCA-2", iocs={"domains": ["same.example.com"]}),
            _incident("SCA-3", iocs={"domains": ["other.example.com"]}),
        ]
        stats = intel_sync.normalize(incidents)["stats"]
        self.assertEqual(stats["domains"], 3)          # occurrences seen
        self.assertEqual(stats["domains_unique"], 2)   # entries actually usable

    def test_collisions_are_counted_so_they_are_not_silent(self):
        incidents = [
            _incident("SCA-1", iocs={"packages": [{"name": "evil-pkg"}]}),
            _incident("SCA-2", iocs={"packages": [{"name": "evil-pkg"}]}),
        ]
        stats = intel_sync.normalize(incidents)["stats"]
        self.assertEqual(stats["indicator_collisions"], 1)

    def test_no_collisions_reports_zero(self):
        incidents = [_incident("SCA-1", iocs={"domains": ["a.example.com"],
                                              "packages": [{"name": "p1"}]})]
        stats = intel_sync.normalize(incidents)["stats"]
        self.assertEqual(stats["indicator_collisions"], 0)

    def test_unique_counts_match_the_written_tables(self):
        norm = intel_sync.normalize([
            _incident("SCA-1", iocs={"domains": ["a.example.com", "b.example.com"],
                                     "ips": ["1.2.3.4"],
                                     "packages": [{"name": "p1"}]})])
        self.assertEqual(norm["stats"]["domains_unique"],
                         len(norm["network_iocs"]["domains"]))
        self.assertEqual(norm["stats"]["ips_unique"], len(norm["network_iocs"]["ips"]))
        self.assertEqual(norm["stats"]["packages_unique"], len(norm["packages"]))


class TestWildcardDnsServices(unittest.TestCase):
    """Wildcard-DNS services resolve any name under them to an embedded IP.

    A bare wildcard on one is "the entire internet by another route". The live
    feed genuinely uses SPECIFIC hosts under sslip.io, so only the bare wildcard
    is dropped.
    """

    def test_bare_wildcard_on_a_wildcard_dns_service_is_dropped(self):
        for svc in ("*.sslip.io", "*.nip.io", "*.webhook.site", "*.interact.sh"):
            norm = intel_sync.normalize([_incident(iocs={"domains": [svc]})])
            self.assertEqual(norm["network_iocs"]["wildcards"], [], svc)
            self.assertEqual(norm["stats"]["wildcards_dropped_public_apex"], 1, svc)

    def test_a_specific_host_under_one_is_kept(self):
        """This is a real shape in the live feed: an attacker IP encoded in a
        wildcard-DNS hostname."""
        norm = intel_sync.normalize(
            [_incident(iocs={"domains": ["16-171-38-148.sslip.io"]})])
        self.assertIn("16-171-38-148.sslip.io", norm["network_iocs"]["domains"])


class TestStaleCacheAfterResync(unittest.TestCase):
    """A long-lived reader must pick up a re-sync without a restart.

    The webapp and traffic-ingest run for days while the refresh sidecar
    rewrites the volume underneath them. Caching forever meant a freshly synced
    IOC never applied to newly captured traffic until someone restarted the
    container - the flag would keep saying "no match" for a host the catalog
    already named.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sca-reload-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        intel_mod.reset_cache()
        self.addCleanup(intel_mod.reset_cache)
        self._orig_window = intel_mod.RELOAD_CHECK_SECONDS
        self.addCleanup(setattr, intel_mod, "RELOAD_CHECK_SECONDS", self._orig_window)

    def _write(self, domains, revised="r1"):
        with open(os.path.join(self.dir, "network_iocs.json"), "w") as fh:
            json.dump({"domains": domains, "wildcards": [], "ips": {}}, fh)
        for name in ("packages.json", "typosquats.json"):
            with open(os.path.join(self.dir, name), "w") as fh:
                json.dump({}, fh)
        # manifest LAST, as the sync writes it: its mtime is the change signal.
        with open(os.path.join(self.dir, "manifest.json"), "w") as fh:
            json.dump({"revised": revised}, fh)

    def test_a_resync_is_picked_up_without_a_restart(self):
        intel_mod.RELOAD_CHECK_SECONDS = 0        # check on every call
        self._write({"old.example.com": {"incident_id": "OLD"}})
        first = intel_mod.load_intel(self.dir, force_reload=True)
        self.assertIsNone(intel_mod.match_host("new.example.com", first))

        # The sidecar re-syncs underneath the running process.
        os.utime(os.path.join(self.dir, "manifest.json"), (1, 1))
        self._write({"new.example.com": {"incident_id": "NEW"}}, revised="r2")

        second = intel_mod.load_intel(self.dir)
        self.assertEqual(second.revised, "r2")
        self.assertEqual(
            intel_mod.match_host("new.example.com", second)["incident_id"], "NEW")

    def test_within_the_window_the_file_is_not_re_stat_ed(self):
        """This sits on the ingest path: one stat per window, not per request."""
        intel_mod.RELOAD_CHECK_SECONDS = 3600
        self._write({"a.example.com": {"incident_id": "A"}})
        first = intel_mod.load_intel(self.dir, force_reload=True)
        self._write({"b.example.com": {"incident_id": "B"}}, revised="r2")
        second = intel_mod.load_intel(self.dir)
        self.assertIs(first, second, "must serve the cached copy inside the window")

    def test_an_unchanged_manifest_does_not_reparse(self):
        intel_mod.RELOAD_CHECK_SECONDS = 0
        self._write({"a.example.com": {"incident_id": "A"}})
        first = intel_mod.load_intel(self.dir, force_reload=True)
        second = intel_mod.load_intel(self.dir)
        self.assertIs(first, second, "same mtime must not trigger a reparse")

    def test_a_volume_that_disappears_degrades_rather_than_serving_stale(self):
        intel_mod.RELOAD_CHECK_SECONDS = 0
        self._write({"a.example.com": {"incident_id": "A"}})
        intel_mod.load_intel(self.dir, force_reload=True)
        os.remove(os.path.join(self.dir, "manifest.json"))
        after = intel_mod.load_intel(self.dir)
        self.assertFalse(after.available)
