"""End-to-end (in-process) chain tests for the fields the Supply-Chain SCA
table reads.

These follow one value from RAW TOOL OUTPUT, through the parser, through the
artifact assembly, through the DIRTY->CLEAN boundary, into the exact Cypher
parameters the graph writer sends. Each of the properties involved was silently
dropped somewhere along that chain before, and a unit test on any single link
would have passed while the value still never reached the graph.

Run: python -m unittest tests.test_supply_chain_sca_chain
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from supply_chain_common.artifact import (
    empty_artifact, add_osv_findings, add_guarddog_findings,
)
from supply_chain_common.guarddog_runner import parse_guarddog
from supply_chain_common.osv_runner import parse_osv_json
from supply_chain_common.security import validate_artifact
from graph_db.mixins.supply_chain_mixin import SupplyChainMixin


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
        if "DEPENDS_ON" in query and "RETURN count" in query:
            return FakeResult({"c": 1})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class Writer(SupplyChainMixin):
    def __init__(self, session):
        self.driver = FakeDriver(session)


def params_for(session, marker):
    """Cypher parameters of the first query containing `marker`."""
    for q, kw in session.queries:
        if marker in q:
            return kw
    return None


class TestGuarddogSoftErrorChain(unittest.TestCase):
    """GuardDog's own per-rule failures must reach the graph as UNCHECKED.

    parse_guarddog turns an `errors` entry into a finding whose `rule` is the
    real rule name (e.g. `download-package`), not the `guarddog-not-run` marker
    the L1/L2 wrappers use. Before soft_error was persisted, that finding was
    indistinguishable from a genuine low-severity behavioural hit, so a package
    GuardDog never managed to download reported as "analysed, mildly
    suspicious".
    """

    RAW = {
        "results": {},
        "errors": {"download-package": "failed to download tarball: 404"},
        "package": "evil-pkg",
        "version": "1.0.0",
    }

    def test_parse_guarddog_marks_rule_errors_as_soft(self):
        findings = parse_guarddog(self.RAW)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "download-package")
        self.assertTrue(findings[0]["soft_error"])

    def test_soft_error_survives_artifact_assembly_and_validation(self):
        art = empty_artifact("purls")
        add_guarddog_findings(art, parse_guarddog(self.RAW), ecosystem="npm",
                              name="evil-pkg", version="1.0.0",
                              purl="pkg:npm/evil-pkg@1.0.0")
        clean = validate_artifact(art)
        self.assertTrue(clean["suspicious"][0]["soft_error"])

    def test_soft_error_reaches_the_graph_writer(self):
        art = empty_artifact("purls")
        add_guarddog_findings(art, parse_guarddog(self.RAW), ecosystem="npm",
                              name="evil-pkg", version="1.0.0",
                              purl="pkg:npm/evil-pkg@1.0.0")
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            validate_artifact(art), "u1", "p1")
        kw = params_for(sess, "MERGE (mf:MalPackageFinding")
        self.assertIsNotNone(kw)
        self.assertIs(kw["soft_error"], True)
        # It attaches to the VERSIONED purl, so it lands on the package the
        # verdict was actually about rather than creating a second node.
        self.assertEqual(kw["purl"], "pkg:npm/evil-pkg@1.0.0")

    def test_a_real_guarddog_hit_is_not_marked_soft(self):
        raw = {"results": {"npm-install-script": "postinstall runs curl"},
               "errors": {}, "package": "evil-pkg", "version": "1.0.0"}
        art = empty_artifact("purls")
        add_guarddog_findings(art, parse_guarddog(raw), ecosystem="npm",
                              name="evil-pkg", version="1.0.0",
                              purl="pkg:npm/evil-pkg@1.0.0")
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            validate_artifact(art), "u1", "p1")
        kw = params_for(sess, "MERGE (mf:MalPackageFinding")
        self.assertIs(kw["soft_error"], False)


class TestOsvAdvisoryChain(unittest.TestCase):
    """CVSS vector + aliases + source_path, from osv-scanner JSON to Cypher."""

    RAW = {
        "results": [{
            "source": {"path": "/work/repo/web/package-lock.json"},
            "packages": [{
                "package": {"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
                "vulnerabilities": [
                    {"id": "GHSA-abcd-1234", "summary": "SSRF",
                     "aliases": ["CVE-2026-1111"],
                     "database_specific": {"severity": "HIGH"},
                     "severity": [{"type": "CVSS_V3",
                                   "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
                    {"id": "MAL-2026-2307", "summary": "malware",
                     "aliases": ["GHSA-mal-0001"]},
                ],
            }],
        }],
    }

    def _clean_artifact(self):
        art = empty_artifact("dir")
        add_osv_findings(art, parse_osv_json(self.RAW))
        return validate_artifact(art)

    def test_parser_extracts_severity_and_cvss(self):
        parsed = parse_osv_json(self.RAW)
        vuln = parsed["vulnerable"][0]
        self.assertEqual(vuln["severity"], "high")
        self.assertTrue(vuln["cvss_vector"].startswith("CVSS:3.1/"))
        self.assertEqual(parsed["malicious"][0]["advisory_id"], "MAL-2026-2307")

    def test_cvss_vector_reaches_the_vulnerability_merge(self):
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            self._clean_artifact(), "u1", "p1")
        kw = params_for(sess, "MERGE (v:Vulnerability")
        self.assertIsNotNone(kw)
        self.assertEqual(kw["advisory"], "GHSA-abcd-1234")
        self.assertTrue(kw["cvss"].startswith("CVSS:3.1/"))
        self.assertEqual(kw["severity"], "high")

    def test_aliases_reach_the_finding_merge(self):
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            self._clean_artifact(), "u1", "p1")
        kw = params_for(sess, "MERGE (mf:MalPackageFinding")
        self.assertEqual(kw["aliases"], ["GHSA-mal-0001"])

    def test_source_path_reaches_the_package_merge(self):
        # Which lockfile inside a cloned repo the package came from.
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            self._clean_artifact(), "u1", "p1")
        kw = params_for(sess, "MERGE (p:Package")
        self.assertEqual(kw["source_path"], "/work/repo/web/package-lock.json")

    def test_cve_never_becomes_a_malicious_finding(self):
        # The invariant the whole verdict model rests on.
        sess = FakeSession()
        stats = Writer(sess).update_graph_from_supply_chain(
            self._clean_artifact(), "u1", "p1")
        self.assertEqual(stats["malicious_merged"], 1)      # the MAL- id only
        self.assertEqual(stats["vulnerabilities_merged"], 1)  # the GHSA- id
        finding_advisories = [kw["advisory"] for q, kw in sess.queries
                              if "MERGE (mf:MalPackageFinding" in q]
        self.assertEqual(finding_advisories, ["MAL-2026-2307"])


class TestUngradedAdvisorySeverity(unittest.TestCase):
    def test_ungraded_advisory_lands_at_info_not_unknown(self):
        # The graph's Vulnerability severity enum has no "unknown"; an advisory
        # OSV did not grade must not inflate the alert stream.
        raw = {"results": [{"source": {"path": "x"}, "packages": [{
            "package": {"name": "x", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-nograde"}]}]}]}
        art = empty_artifact("lockfile")
        add_osv_findings(art, parse_osv_json(raw))
        sess = FakeSession()
        Writer(sess).update_graph_from_supply_chain(
            validate_artifact(art), "u1", "p1")
        kw = params_for(sess, "MERGE (v:Vulnerability")
        self.assertEqual(kw["severity"], "info")


if __name__ == "__main__":
    unittest.main()
