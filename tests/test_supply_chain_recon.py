"""Unit tests for the L2 pipeline module (supply_chain_recon) + recon graph write.

The module imports supply_chain_common at top (fine on host) and imports
harvest lazily; the OSV verdict path uses the shared to_cyclonedx, so
verdict_packages is host-testable with the osv runner mocked.

Run: python -m unittest tests.test_supply_chain_recon
"""

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

# Load the pipeline module by path (its harvest import is lazy, so this does not
# trigger the recon.helpers package __init__).
_spec = importlib.util.spec_from_file_location(
    "sc_recon",
    os.path.join(_REPO, "recon", "main_recon_modules", "supply_chain_recon.py"))
scr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scr)

from graph_db.mixins.supply_chain_mixin import SupplyChainMixin


class _FakeOsv:
    def __init__(self, parsed):
        self._parsed = parsed
        self.calls = []

    def run_osv_scan(self, target, *, mode, db_path):
        self.calls.append((target, mode))
        return {"parsed": self._parsed, "error": None}


class TestExtraction(unittest.TestCase):
    def test_extract_source_maps(self):
        cr = {"js_recon": {"source_maps": [{"source_files": ["node_modules/x/a.js"]}]}}
        self.assertEqual(len(scr._extract_source_maps(cr)), 1)
        self.assertEqual(scr._extract_source_maps({}), [])

    def test_extract_base_urls(self):
        cr = {"http_probe": {"results": [{"url": "https://a"}, {"url": "https://b"}]}}
        self.assertEqual(scr._extract_base_urls(cr), ["https://a", "https://b"])

    def test_extract_technologies(self):
        cr = {"http_probe": {"results": [
            {"technologies": [{"name": "React", "version": "17.0.2"}]}]}}
        techs = scr._extract_technologies(cr)
        self.assertEqual(techs[0]["name"], "React")


class TestVerdict(unittest.TestCase):
    def test_verdict_folds_malicious(self):
        fake = _FakeOsv({"malicious": [{"purl": "pkg:npm/lodahs@1", "name": "lodahs",
                                        "advisory_id": "MAL-1", "ecosystem": "npm"}],
                         "vulnerable": []})
        pkgs = [{"purl": "pkg:npm/lodahs@1", "name": "lodahs", "version": "1",
                 "ecosystem": "npm", "source": "sourcemap"}]
        art = scr.verdict_packages(pkgs, db_path="/osv-db", osv=fake)
        self.assertEqual(len(art["packages"]), 1)
        self.assertEqual(len(art["malicious"]), 1)
        self.assertEqual(fake.calls[0][1], "sbom")

    def test_verdict_empty_packages_no_osv_call(self):
        fake = _FakeOsv({})
        art = scr.verdict_packages([], db_path="/osv-db", osv=fake)
        self.assertEqual(art["packages"], [])
        self.assertEqual(fake.calls, [])


class _FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kw):
        self.queries.append((query, kw))

        class R:
            def single(self_inner):
                return {"c": 1} if "RETURN count" in query else None
        return R()


class _Writer(SupplyChainMixin):
    def __init__(self, s):
        class D:
            def session(self_inner):
                return s
        self.driver = D()


class TestReconGraphWrite(unittest.TestCase):
    def _artifact(self):
        return {"packages": [{"purl": "pkg:npm/x@1", "name": "x", "ecosystem": "npm"}],
                "malicious": [], "vulnerable": [], "suspicious": []}

    def test_anchors_to_each_base_url(self):
        sess = _FakeSession()
        w = _Writer(sess)
        cr = {"supply_chain_recon": {"artifact": self._artifact(),
                                     "base_urls": ["https://a", "https://b"]}}
        stats = w.update_graph_from_supply_chain_recon(cr, "u", "p")
        # package MERGEd once per base url; DEPENDS_ON attempted per url
        self.assertEqual(stats["relationships_created"], 2)
        self.assertIn("DEPENDS_ON", " ".join(q for q, _ in sess.queries))

    def test_no_base_urls_floats(self):
        sess = _FakeSession()
        w = _Writer(sess)
        cr = {"supply_chain_recon": {"artifact": self._artifact(), "base_urls": []}}
        stats = w.update_graph_from_supply_chain_recon(cr, "u", "p")
        self.assertEqual(stats["relationships_created"], 0)

    def test_missing_block(self):
        stats = _Writer(_FakeSession()).update_graph_from_supply_chain_recon({}, "u", "p")
        self.assertIn("skipped", stats)


if __name__ == "__main__":
    unittest.main()
