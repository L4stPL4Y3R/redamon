"""Unit tests for the supply-chain graph writer (Phase 2/4 graph model).

Uses a fake Neo4j session (no live DB), mirroring test_js_recon_graph_ingestion.
Asserts: Package + MalPackageFinding MERGE, MAL-vs-suspicious verdict routing,
name-only purl fallback, dedup stability, and finding_id determinism.

Run: python -m unittest tests.test_supply_chain_mixin
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

from graph_db.mixins.supply_chain_mixin import SupplyChainMixin, _finding_id


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self, anchor_exists=True):
        self.queries = []
        self.anchor_exists = anchor_exists

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "DEPENDS_ON" in query and "RETURN count" in query:
            return FakeResult({"c": 1 if self.anchor_exists else 0})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class Writer(SupplyChainMixin):
    def __init__(self, session):
        self.driver = FakeDriver(session)


def artifact(**over):
    a = {"packages": [], "malicious": [], "vulnerable": [], "suspicious": []}
    a.update(over)
    return a


class TestSupplyChainMixin(unittest.TestCase):
    def test_package_and_malicious_merge(self):
        sess = FakeSession()
        w = Writer(sess)
        data = artifact(
            packages=[{"purl": "pkg:npm/lodahs@1.0.0", "name": "lodahs",
                       "version": "1.0.0", "ecosystem": "npm", "source": "osv"}],
            malicious=[{"purl": "pkg:npm/lodahs@1.0.0", "name": "lodahs",
                        "advisory_id": "MAL-2025-25502", "severity": "high",
                        "confidence": "malicious", "title": "bad"}])
        stats = w.update_graph_from_supply_chain(
            data, "u1", "p1", anchor_label="BaseURL", anchor_key="url",
            anchor_value="https://t")
        self.assertEqual(stats["packages_merged"], 1)
        self.assertEqual(stats["malicious_merged"], 1)
        self.assertEqual(stats["relationships_created"], 1)
        joined = " ".join(q for q, _ in sess.queries)
        self.assertIn("MERGE (p:Package", joined)
        self.assertIn("MERGE (mf:MalPackageFinding", joined)
        self.assertIn("DEPENDS_ON", joined)
        self.assertIn("FLAGGED_AS", joined)

    def test_tenant_scoping_in_keys(self):
        sess = FakeSession()
        w = Writer(sess)
        w.update_graph_from_supply_chain(
            artifact(packages=[{"purl": "pkg:npm/x@1", "name": "x", "ecosystem": "npm"}]),
            "u1", "p1", anchor_label="GithubRepository", anchor_key="id",
            anchor_value="repo1")
        # every package/finding MERGE carries user_id + project_id
        for q, kw in sess.queries:
            if "MERGE (p:Package" in q:
                self.assertEqual(kw["uid"], "u1")
                self.assertEqual(kw["pid"], "p1")

    def test_suspicious_routes_to_suspicious_not_malicious(self):
        sess = FakeSession()
        w = Writer(sess)
        stats = w.update_graph_from_supply_chain(
            artifact(
                packages=[{"purl": "pkg:npm/evil@1", "name": "evil", "ecosystem": "npm"}],
                suspicious=[{"purl": "pkg:npm/evil@1", "name": "evil", "ecosystem": "npm",
                             "rule": "npm-install-script", "severity": "high",
                             "confidence": "suspicious", "message": "hook"}]),
            "u1", "p1", anchor_label="BaseURL", anchor_key="url", anchor_value="https://t")
        self.assertEqual(stats["suspicious_merged"], 1)
        self.assertEqual(stats["malicious_merged"], 0)

    def test_name_only_purl_fallback_for_guarddog(self):
        sess = FakeSession()
        w = Writer(sess)
        stats = w.update_graph_from_supply_chain(
            artifact(suspicious=[{"name": "evil", "ecosystem": "npm",
                                  "rule": "typosquatting", "confidence": "suspicious"}]),
            "u1", "p1", anchor_label="BaseURL", anchor_key="url", anchor_value="https://t")
        self.assertEqual(stats["suspicious_merged"], 1)

    def test_finding_id_deterministic(self):
        a = _finding_id("pkg:npm/x@1", "MAL-1")
        b = _finding_id("pkg:npm/x@1", "MAL-1")
        c = _finding_id("pkg:npm/x@1", "MAL-2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 16)

    def test_no_depends_on_when_anchor_absent(self):
        sess = FakeSession(anchor_exists=False)
        w = Writer(sess)
        stats = w.update_graph_from_supply_chain(
            artifact(packages=[{"purl": "pkg:npm/x@1", "name": "x", "ecosystem": "npm"}]),
            "u1", "p1", anchor_label="BaseURL", anchor_key="url", anchor_value="https://absent")
        self.assertEqual(stats["packages_merged"], 1)
        self.assertEqual(stats["relationships_created"], 0)

    def test_bad_anchor_label_raises(self):
        with self.assertRaises(ValueError):
            Writer(FakeSession()).update_graph_from_supply_chain(
                artifact(), "u1", "p1", anchor_label="Domain", anchor_key="name",
                anchor_value="x")


if __name__ == "__main__":
    unittest.main()
