"""Unit tests for the L2 black-box harvest core (recon/helpers/supply_chain/harvest.py).

Pure parsing; no network, no binaries. Covers source-map mining (scoped, nested,
hostile-name skip), import extraction, technology->purl mapping, dedup/version
preference, and CycloneDX synthesis.

Run: python -m unittest tests.test_supply_chain_harvest
"""

import importlib.util
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Load harvest.py directly by path: importing it through the recon.helpers
# package would trigger that package's __init__ (which pulls in dns/other recon
# deps not present on the host). harvest.py itself needs only supply_chain_common.
_spec = importlib.util.spec_from_file_location(
    "sc_harvest",
    os.path.join(_REPO, "recon", "helpers", "supply_chain", "harvest.py"))
harvest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(harvest)


class TestSourcemapMining(unittest.TestCase):
    def test_unscoped_and_scoped(self):
        sms = [{"source_files": [
            "webpack://app/./node_modules/lodash/lodash.js",
            "webpack://app/./node_modules/@babel/runtime/helpers/x.js",
            "./src/index.js",  # not a package
        ]}]
        names = {p["name"] for p in harvest.mine_sourcemap_packages(sms)}
        self.assertEqual(names, {"lodash", "@babel/runtime"})

    def test_nested_node_modules(self):
        sms = [{"source_files": [
            "node_modules/next/node_modules/postcss/lib/x.js"]}]
        names = {p["name"] for p in harvest.mine_sourcemap_packages(sms)}
        self.assertEqual(names, {"next", "postcss"})

    def test_sources_key_fallback(self):
        sms = [{"sources": ["node_modules/react/index.js"]}]
        self.assertEqual(harvest.mine_sourcemap_packages(sms)[0]["name"], "react")

    def test_hostile_name_skipped(self):
        sms = [{"source_files": ["node_modules/$(id)/x.js"]}]
        self.assertEqual(harvest.mine_sourcemap_packages(sms), [])

    def test_dedup(self):
        sms = [{"source_files": ["node_modules/lodash/a.js",
                                 "node_modules/lodash/b.js"]}]
        self.assertEqual(len(harvest.mine_sourcemap_packages(sms)), 1)

    def test_empty_and_malformed(self):
        self.assertEqual(harvest.mine_sourcemap_packages(None), [])
        self.assertEqual(harvest.mine_sourcemap_packages([{}, "x", None]), [])


class TestImportMining(unittest.TestCase):
    def test_import_and_require(self):
        js = ["import x from 'lodash'; const y = require('@scope/pkg');",
              "import('axios')"]
        names = {p["name"] for p in harvest.mine_import_packages(js)}
        self.assertIn("lodash", names)
        self.assertIn("@scope/pkg", names)
        self.assertIn("axios", names)

    def test_relative_paths_excluded(self):
        # './foo' has a leading '.', but the regex captures bare specifiers only.
        js = ["import a from './local'; import b from '../up'"]
        names = {p["name"] for p in harvest.mine_import_packages(js)}
        self.assertNotIn("local", names)
        self.assertNotIn("up", names)


class TestTechnologies(unittest.TestCase):
    def test_known_tech_mapped_with_version(self):
        techs = [{"name": "React", "version": "17.0.2"},
                 {"name": "jQuery", "version": "3.6.0"},
                 {"name": "UnknownFramework", "version": "1.0"}]
        pkgs = {p["name"]: p for p in harvest.technologies_to_packages(techs)}
        self.assertEqual(pkgs["react"]["version"], "17.0.2")
        self.assertIn("jquery", pkgs)
        self.assertNotIn("unknownframework", pkgs)

    def test_string_form(self):
        self.assertTrue(harvest.technologies_to_packages(["Vue.js"]))


class TestHarvestAndSbom(unittest.TestCase):
    def test_dedup_prefers_versioned(self):
        pkgs = harvest.harvest_packages(
            source_maps=[{"source_files": ["node_modules/react/index.js"]}],
            technologies=[{"name": "React", "version": "17.0.2"}])
        react = [p for p in pkgs if p["name"] == "react"]
        self.assertEqual(len(react), 1)
        self.assertEqual(react[0]["version"], "17.0.2")
        self.assertEqual(react[0]["purl"], "pkg:npm/react@17.0.2")

    def test_cyclonedx_shape(self):
        pkgs = harvest.harvest_packages(
            source_maps=[{"source_files": ["node_modules/@babel/core/x.js"]}])
        sbom = harvest.to_cyclonedx(pkgs)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["components"][0]["purl"], "pkg:npm/%40babel/core")

    def test_all_purls_valid(self):
        pkgs = harvest.harvest_packages(
            source_maps=[{"source_files": [
                "node_modules/lodash/x.js", "node_modules/@vue/reactivity/y.js"]}])
        self.assertTrue(all(p["purl"].startswith("pkg:npm/") for p in pkgs))


if __name__ == "__main__":
    unittest.main()
