"""Graph-write tests for the incident context (B) on MalPackageFinding.

Uses the same fake-session harness as tests/test_supply_chain_mixin.py.

The rules under test:
  - all seven incident_* properties are written
  - `title` is NEVER written from incident text (it is the graph viewer's node
    name, guarded at 120 chars)
  - a never-enriched finding writes None, not "" (absent is the honest state)
  - the tenant triple is on every MERGE (C8)
  - the duplicated property list here and in supply_chain_common.intel do not
    drift (graph_db cannot import supply_chain_common: it is COPY-baked into the
    agent image, where that package is absent)

Run: python -m unittest tests.test_sca_intel_mixin
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

from graph_db.mixins.supply_chain_mixin import (  # noqa: E402
    SupplyChainMixin, _INCIDENT_PROPS, _incident_params,
)


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


def _enriched_finding(**over):
    f = {
        "purl": "pkg:npm/evil-pkg@1.0.0",
        "name": "evil-pkg",
        "ecosystem": "npm",
        "advisory_id": "MAL-2022-1122",
        "severity": "critical",
        "incident_id": "SCA-0001",
        "incident_url": "https://supplychainattack.org/incident/SCA-0001",
        "incident_summary": "Malicious postinstall exfiltrating env vars.",
        "incident_blast_radius": "3,000 downloads",
        "incident_remediation": ["Remove the package", "Rotate credentials"],
        "incident_status": "confirmed",
        "incident_feed_revised": "2026-08-11",
    }
    f.update(over)
    return f


def _artifact(malicious):
    return {"packages": [], "malicious": malicious, "vulnerable": [],
            "suspicious": []}


def _finding_query(session):
    for query, kwargs in session.queries:
        if "MalPackageFinding" in query and "MERGE (mf" in query:
            return query, kwargs
    raise AssertionError("no MalPackageFinding MERGE was issued")


class TestIncidentParams(unittest.TestCase):

    def test_all_seven_props_present(self):
        params = _incident_params(_enriched_finding())
        self.assertEqual(set(params), set(_INCIDENT_PROPS))
        self.assertEqual(len(_INCIDENT_PROPS), 7)

    def test_never_enriched_finding_yields_none_not_empty_string(self):
        params = _incident_params({"name": "x"})
        for prop in _INCIDENT_PROPS:
            self.assertIsNone(params[prop], prop)

    def test_empty_string_becomes_none(self):
        params = _incident_params(_enriched_finding(incident_summary=""))
        self.assertIsNone(params["incident_summary"])

    def test_remediation_capped_at_twenty(self):
        params = _incident_params(_enriched_finding(
            incident_remediation=["step-{}".format(i) for i in range(50)]))
        self.assertEqual(len(params["incident_remediation"]), 20)

    def test_remediation_scalar_is_coerced_to_a_list(self):
        params = _incident_params(_enriched_finding(
            incident_remediation="Remove the package"))
        self.assertEqual(params["incident_remediation"], ["Remove the package"])

    def test_non_string_scalar_is_stringified(self):
        params = _incident_params(_enriched_finding(incident_id=1234))
        self.assertEqual(params["incident_id"], "1234")

    def test_field_list_matches_the_intel_module(self):
        """graph_db cannot import supply_chain_common, so the list is duplicated.

        If this fails, the two copies have drifted and findings will be written
        with a property the enrichment step never sets (or vice versa).
        """
        sys.path.insert(0, os.path.join(_REPO, "scanners"))
        try:
            from supply_chain_common.intel import INCIDENT_FIELDS
        except ImportError:
            self.skipTest("supply_chain_common not importable in this image")
        self.assertEqual(set(INCIDENT_FIELDS), set(_INCIDENT_PROPS))


class TestIncidentGraphWrite(unittest.TestCase):

    def test_writes_all_seven_properties(self):
        session = FakeSession()
        Writer(session).update_graph_from_supply_chain(
            _artifact([_enriched_finding()]), "u1", "p1")
        query, kwargs = _finding_query(session)
        for prop in _INCIDENT_PROPS:
            self.assertIn("mf.{} = ${}".format(prop, prop), query, prop)
            self.assertIn(prop, kwargs, prop)
        self.assertEqual(kwargs["incident_id"], "SCA-0001")
        self.assertEqual(kwargs["incident_feed_revised"], "2026-08-11")

    def test_title_is_not_taken_from_incident_text(self):
        """`title` is the node's displayed name; incident titles would blow the
        120-char guard and the summary is a paragraph."""
        session = FakeSession()
        Writer(session).update_graph_from_supply_chain(
            _artifact([_enriched_finding()]), "u1", "p1")
        _, kwargs = _finding_query(session)
        self.assertEqual(kwargs["title"], "MAL-2022-1122")
        self.assertNotIn(kwargs["incident_summary"], str(kwargs["title"]))

    def test_unenriched_finding_writes_nulls(self):
        session = FakeSession()
        plain = {"purl": "pkg:npm/plain@1.0.0", "name": "plain",
                 "ecosystem": "npm", "advisory_id": "MAL-2022-9999",
                 "severity": "critical"}
        Writer(session).update_graph_from_supply_chain(
            _artifact([plain]), "u1", "p1")
        _, kwargs = _finding_query(session)
        for prop in _INCIDENT_PROPS:
            self.assertIsNone(kwargs[prop], prop)

    def test_verdict_is_unchanged_by_enrichment(self):
        session = FakeSession()
        Writer(session).update_graph_from_supply_chain(
            _artifact([_enriched_finding()]), "u1", "p1")
        _, kwargs = _finding_query(session)
        self.assertEqual(kwargs["verdict"], "malicious")
        self.assertEqual(kwargs["advisory"], "MAL-2022-1122")

    def test_tenant_triple_on_every_merge(self):
        """C8: a MERGE without the tenant keys merges one project into another."""
        session = FakeSession()
        Writer(session).update_graph_from_supply_chain(
            _artifact([_enriched_finding()]), "u1", "p1")
        query, kwargs = _finding_query(session)
        self.assertIn("user_id: $uid", query)
        self.assertIn("project_id: $pid", query)
        self.assertEqual(kwargs["uid"], "u1")
        self.assertEqual(kwargs["pid"], "p1")
        # ...on the Package MERGE in the same statement too.
        merge_pkg = query.split("MERGE (p:Package")[1].split(")")[0]
        self.assertIn("user_id: $uid", merge_pkg)
        self.assertIn("project_id: $pid", merge_pkg)


if __name__ == "__main__":
    unittest.main()


def _correlation(**over):
    hit = {
        "base_url": "https://target.example.com",
        "matched_host": "cdn.evil.example",
        "source_url": "https://cdn.evil.example/app.js",
        "evidence": "graph-host-match",
        "incident": {
            "incident_id": "SCA-0001",
            "url": "https://supplychainattack.org/i/SCA-0001",
            "title": "Compromised CDN script",
            "status": "confirmed",
            "summary": "A CDN-hosted script was replaced with a skimmer.",
            "blast_radius": "3,000 sites",
            "remediation": ["Remove the script", "Rotate keys"],
            "attack_vectors": ["compromised-cdn"],
            "last_updated": "2026-08-01",
            "feed_revised": "2026-08-11",
        },
    }
    hit.update(over)
    return {"correlations": [hit], "checked": 2, "available": True}


class TestScaIntelGraphWrite(unittest.TestCase):
    """A2: ThreatPulse + CONTACTS_MALICIOUS_HOST."""

    def _write(self, correlation):
        session = FakeSession()
        stats = Writer(session).update_graph_from_sca_intel(correlation, "u1", "p1")
        return session, stats

    def _pulse_query(self, session):
        for query, kwargs in session.queries:
            if "ThreatPulse" in query:
                return query, kwargs
        raise AssertionError("no ThreatPulse MERGE was issued")

    def test_merges_a_threatpulse_with_the_tenant_triple(self):
        session, stats = self._write(_correlation())
        query, kwargs = self._pulse_query(session)
        self.assertIn("user_id: $uid", query)
        self.assertIn("project_id: $pid", query)
        self.assertEqual(kwargs["pulse_id"], "sca-SCA-0001")

    def test_edge_is_contacts_malicious_host_not_appears_in_pulse(self):
        """APPEARS_IN_PULSE means 'my asset is named in the report', which is
        false here and would leak these into the OTX arms of the Red Zone."""
        session, _ = self._write(_correlation())
        query, _ = self._pulse_query(session)
        self.assertIn("CONTACTS_MALICIOUS_HOST", query)
        self.assertNotIn("APPEARS_IN_PULSE", query)

    def test_adversary_is_never_set(self):
        """The feed has no threat-actor field; both the Red Zone route and the
        report roll pulse.adversary into an adversary list."""
        session, _ = self._write(_correlation())
        query, kwargs = self._pulse_query(session)
        self.assertNotIn("tp.adversary", query)
        self.assertNotIn("adversary", kwargs)

    def test_base_url_is_matched_never_merged(self):
        """Inventing a BaseURL would put a target the scan never saw in the graph."""
        session, _ = self._write(_correlation())
        query, _ = self._pulse_query(session)
        self.assertIn("MATCH (u:BaseURL", query)
        self.assertNotIn("MERGE (u:BaseURL", query)

    def test_attacker_host_is_never_a_node(self):
        """It is a third party the target contacts, not part of the attack
        surface. It belongs on the relationship."""
        session, _ = self._write(_correlation())
        query, kwargs = self._pulse_query(session)
        self.assertEqual(kwargs["matched_host"], "cdn.evil.example")
        for label in ("Domain", "Subdomain", "ExternalDomain", "IP"):
            self.assertNotIn("MERGE ({}:{}".format(label[0].lower(), label), query)
        self.assertIn("c.matched_host = $matched_host", query)

    def test_incident_text_lands_on_sca_prefixed_properties(self):
        session, _ = self._write(_correlation())
        query, kwargs = self._pulse_query(session)
        import re

        for prop in ("sca_incident_url", "sca_status", "sca_summary",
                     "sca_blast_radius", "sca_remediation", "sca_feed_revised"):
            # Whitespace-insensitive: the Cypher aligns its '=' signs.
            self.assertRegex(query, r"tp\.{}\s*=".format(re.escape(prop)))
        self.assertEqual(kwargs["summary"],
                         "A CDN-hosted script was replaced with a skimmer.")

    def test_evidence_is_carried_on_the_relationship(self):
        """Traffic purges delete the Postgres rows but not these nodes, so the
        evidence kind is what keeps a stale finding interpretable."""
        session, _ = self._write(_correlation())
        _, kwargs = self._pulse_query(session)
        self.assertEqual(kwargs["evidence"], "graph-host-match")

    def test_empty_correlation_writes_nothing(self):
        session, stats = self._write({"correlations": [], "available": True})
        self.assertEqual(session.queries, [])
        self.assertEqual(stats["pulses_merged"], 0)

    def test_none_correlation_is_safe(self):
        session, stats = self._write(None)
        self.assertEqual(stats["pulses_merged"], 0)

    def test_hit_without_an_incident_id_is_skipped(self):
        corr = _correlation()
        corr["correlations"][0]["incident"] = {}
        session, stats = self._write(corr)
        self.assertEqual(stats["pulses_merged"], 0)

    def test_hit_without_a_base_url_is_skipped(self):
        session, stats = self._write(_correlation(base_url=None))
        self.assertEqual(stats["pulses_merged"], 0)
