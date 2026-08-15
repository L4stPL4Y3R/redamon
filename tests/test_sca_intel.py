"""Unit tests for the supply-chain intel read side (load, match, enrich).

Section: root-agent.

The contract under test is that this module NEVER raises: a missing volume, a
truncated file and a never-synced deploy must all degrade to available=False.
"""

import copy
import json
import os
import shutil
import tempfile
import unittest

from supply_chain_common import intel as intel_mod
from supply_chain_common.security import ArtifactError, validate_artifact


def _write_intel(path, *, domains=None, wildcards=None, ips=None,
                 packages=None, typosquats=None, revised="2026-08-11"):
    os.makedirs(path, exist_ok=True)
    payload = {
        "network_iocs.json": {
            "domains": domains or {},
            "wildcards": wildcards or [],
            "ips": ips or {},
        },
        "packages.json": packages or {},
        "typosquats.json": typosquats or {},
        "manifest.json": {"revised": revised, "fetched_at": 1},
    }
    for name, body in payload.items():
        with open(os.path.join(path, name), "w") as fh:
            json.dump(body, fh)


def _rec(iid="SCA-0001", **kw):
    base = {
        "incident_id": iid,
        "url": "https://supplychainattack.org/incident/{}".format(iid),
        "title": "Incident {}".format(iid),
        "status": "confirmed",
        "severity": "high",
        "summary": "Package published with a malicious postinstall.",
        "blast_radius": "3,000 downloads",
        "remediation": ["Remove it", "Rotate credentials"],
        "attack_vectors": ["malicious-package"],
        "last_updated": "2026-08-01",
    }
    base.update(kw)
    return base


class _IntelTestCase(unittest.TestCase):

    def setUp(self):
        intel_mod.reset_cache()
        self.addCleanup(intel_mod.reset_cache)
        self.path = tempfile.mkdtemp(prefix="sca-intel-read-")
        self.addCleanup(shutil.rmtree, self.path, ignore_errors=True)


class TestLoadIntel(_IntelTestCase):

    def test_missing_volume_is_unavailable_and_never_raises(self):
        intel = intel_mod.load_intel(os.path.join(self.path, "nope"),
                                     force_reload=True)
        self.assertFalse(intel.available)
        self.assertEqual(intel.domains, {})
        self.assertEqual(intel.packages, {})
        self.assertIn("no manifest", intel.error)

    def test_truncated_json_is_unavailable_and_never_raises(self):
        _write_intel(self.path, domains={"evil.example.com": _rec()})
        with open(os.path.join(self.path, "manifest.json"), "w") as fh:
            fh.write('{"revised": ')  # truncated mid-write
        intel = intel_mod.load_intel(self.path, force_reload=True)
        self.assertFalse(intel.available)

    def test_unreadable_data_file_degrades_to_empty_not_crash(self):
        _write_intel(self.path)
        with open(os.path.join(self.path, "packages.json"), "w") as fh:
            fh.write("{not json")
        intel = intel_mod.load_intel(self.path, force_reload=True)
        self.assertTrue(intel.available)
        self.assertEqual(intel.packages, {})

    def test_loads_tables_and_revision(self):
        _write_intel(self.path,
                     domains={"evil.example.com": _rec()},
                     wildcards=[[".cf99.workers.dev", _rec("SCA-0002")]],
                     ips={"1.2.3.4": _rec("SCA-0003")},
                     packages={"npm/evil-pkg": _rec("SCA-0004")},
                     typosquats={"lodahs": {"original": "lodash",
                                            "incident_id": "SCA-0005"}})
        intel = intel_mod.load_intel(self.path, force_reload=True)
        self.assertTrue(intel.available)
        self.assertEqual(intel.revised, "2026-08-11")
        self.assertEqual(len(intel.domains), 1)
        self.assertEqual(len(intel.wildcards), 1)
        self.assertEqual(intel.typosquats["lodahs"]["original"], "lodash")

    def test_entry_cap_enforced(self):
        big = {"host{}.example.com".format(i): _rec() for i in range(50)}
        _write_intel(self.path, domains=big)
        original = intel_mod.MAX_ENTRIES
        intel_mod.MAX_ENTRIES = 10
        try:
            intel = intel_mod.load_intel(self.path, force_reload=True)
        finally:
            intel_mod.MAX_ENTRIES = original
        self.assertEqual(len(intel.domains), 10)

    def test_cache_is_per_process(self):
        _write_intel(self.path, domains={"evil.example.com": _rec()})
        first = intel_mod.load_intel(self.path, force_reload=True)
        second = intel_mod.load_intel(self.path)
        self.assertIs(first, second)


class TestMatchHost(_IntelTestCase):

    def setUp(self):
        super().setUp()
        _write_intel(self.path,
                     domains={"evil.example.com": _rec("SCA-EXACT")},
                     wildcards=[[".cf99.workers.dev", _rec("SCA-WILD")]],
                     ips={"1.2.3.4": _rec("SCA-IP")},
                     packages={})
        self.intel = intel_mod.load_intel(self.path, force_reload=True)

    def test_exact_match(self):
        rec = intel_mod.match_host("evil.example.com", self.intel)
        self.assertEqual(rec["incident_id"], "SCA-EXACT")

    def test_match_is_case_insensitive(self):
        rec = intel_mod.match_host("EVIL.Example.CoM", self.intel)
        self.assertEqual(rec["incident_id"], "SCA-EXACT")

    def test_host_with_port_still_matches(self):
        rec = intel_mod.match_host("evil.example.com:8443", self.intel)
        self.assertEqual(rec["incident_id"], "SCA-EXACT")

    def test_wildcard_suffix_match(self):
        rec = intel_mod.match_host("a.cf99.workers.dev", self.intel)
        self.assertEqual(rec["incident_id"], "SCA-WILD")

    def test_wildcard_does_not_match_the_wrong_apex(self):
        self.assertIsNone(intel_mod.match_host("a.other.workers.dev", self.intel))

    def test_ip_match(self):
        rec = intel_mod.match_host(None, self.intel, ip="1.2.3.4")
        self.assertEqual(rec["incident_id"], "SCA-IP")

    def test_non_match_returns_none(self):
        self.assertIsNone(intel_mod.match_host("clean.example.com", self.intel))

    def test_unavailable_intel_returns_none(self):
        empty = intel_mod.Intel()
        self.assertIsNone(intel_mod.match_host("evil.example.com", empty))

    def test_ignore_list_suppresses_oast_hosts(self):
        _write_intel(self.path, domains={"x.oastify.com": _rec("SCA-OAST")})
        intel = intel_mod.load_intel(self.path, force_reload=True)
        # Default ignore list covers the 5 OAST providers in the feed, so an
        # operator's own Burp Collaborator callbacks are not flagged.
        self.assertIsNone(intel_mod.match_host("x.oastify.com", intel))
        # ... but with the suppression removed the record is really there.
        self.assertIsNotNone(
            intel_mod.match_host("x.oastify.com", intel, ignore_suffixes=[]))

    def test_ignore_list_accepts_a_comma_string(self):
        rec = intel_mod.match_host("evil.example.com", self.intel,
                                   ignore_suffixes="example.com,foo.test")
        self.assertIsNone(rec)


class TestEnrichFindings(_IntelTestCase):

    def setUp(self):
        super().setUp()
        _write_intel(self.path, packages={
            "npm/evil-pkg": _rec("SCA-PKG", remediation=[
                "step-{}".format(i) for i in range(50)]),
        })
        self.intel = intel_mod.load_intel(self.path, force_reload=True)

    def _artifact(self):
        return {
            "schema_version": 1,
            "mode": "lockfile",
            "packages": [{"name": "evil-pkg", "ecosystem": "npm"}],
            "malicious": [{"name": "evil-pkg", "ecosystem": "npm",
                           "advisory_id": "MAL-2022-1122", "severity": "critical"}],
            "vulnerable": [],
            "suspicious": [{"name": "clean-pkg", "ecosystem": "npm",
                            "rule": "npm-install-script", "severity": "low"}],
            "errors": [],
        }

    def test_attaches_all_seven_properties(self):
        art = intel_mod.enrich_findings(self._artifact(), self.intel)
        found = art["malicious"][0]
        for prop in intel_mod.INCIDENT_FIELDS:
            self.assertIn(prop, found, prop)
        self.assertEqual(found["incident_id"], "SCA-PKG")
        self.assertEqual(found["incident_feed_revised"], "2026-08-11")

    def test_remediation_is_capped(self):
        art = intel_mod.enrich_findings(self._artifact(), self.intel)
        self.assertEqual(len(art["malicious"][0]["incident_remediation"]), 20)

    def test_unmatched_finding_is_untouched(self):
        art = intel_mod.enrich_findings(self._artifact(), self.intel)
        self.assertNotIn("incident_id", art["suspicious"][0])

    def test_never_alters_verdict_or_severity(self):
        """A name-only intel match is weaker evidence than an OSV verdict."""
        before = self._artifact()
        art = intel_mod.enrich_findings(copy.deepcopy(before), self.intel)
        self.assertEqual(art["malicious"][0]["severity"],
                         before["malicious"][0]["severity"])
        self.assertEqual(art["malicious"][0]["advisory_id"],
                         before["malicious"][0]["advisory_id"])
        # No finding is added or moved between buckets.
        for bucket in ("malicious", "vulnerable", "suspicious"):
            self.assertEqual(len(art[bucket]), len(before[bucket]), bucket)

    def test_never_writes_title(self):
        """`title` is the graph viewer's node name, guarded at 120 chars."""
        art = intel_mod.enrich_findings(self._artifact(), self.intel)
        self.assertNotIn("title", art["malicious"][0])

    def test_unavailable_intel_alters_no_finding_but_records_an_error(self):
        """C7: a missing data source must never read as a clean result."""
        before = self._artifact()
        art = intel_mod.enrich_findings(copy.deepcopy(before), intel_mod.Intel())
        self.assertEqual(art["malicious"], before["malicious"])
        self.assertEqual(art["suspicious"], before["suspicious"])
        self.assertEqual(len(art["errors"]), 1)
        self.assertIn("sca-intel", art["errors"][0])

    def test_enrich_then_validate_raises(self):
        """The ordering lock for C1.

        Enrichment happens AFTER the last validate_artifact. The incident_*
        fields are deliberately absent from the artifact allowlist, so
        re-validating an enriched artifact must fail loudly. If this test ever
        goes green by adding the fields to the allowlist, the DIRTY->CLEAN
        boundary has been widened to accept them from the analyzer too.
        """
        art = intel_mod.enrich_findings(self._artifact(), self.intel)
        with self.assertRaises(ArtifactError):
            validate_artifact(art)

    def test_validate_then_enrich_is_the_supported_order(self):
        clean = validate_artifact(self._artifact())
        art = intel_mod.enrich_findings(clean, self.intel)
        self.assertEqual(art["malicious"][0]["incident_id"], "SCA-PKG")

    def test_non_dict_artifact_is_returned_unchanged(self):
        self.assertEqual(intel_mod.enrich_findings(None, self.intel), None)


if __name__ == "__main__":
    unittest.main()
