"""Unit tests for the L2 black-box harvest core (recon/helpers/supply_chain/harvest.py).

Pure parsing; no network, no binaries. Covers source-map mining (scoped, nested,
hostile-name skip), import extraction, technology->purl mapping, dedup/version
preference, and CycloneDX synthesis.

Run: python -m unittest tests.test_supply_chain_harvest
"""

import contextlib
import importlib.util
import os
import signal
import sys
import time
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


class TestImportRegexIsNotQuadratic(unittest.TestCase):
    """REGRESSION: catastrophic backtracking in the import-mining regex.

    The clause between `import` and `from` was an UNBOUNDED lazy `[^'"]*?`. On
    JavaScript that never satisfies the `from`, every `import` token becomes a
    start position that rescans to end-of-string, so the match is quadratic in
    file size. Measured before the fix:

        14 KB -> 0.12s     140 KB -> 13.2s     280 KB -> 64.4s

    js_recon caps each downloaded file at 5 MB, which extrapolates to HOURS of
    CPU for a single crafted file. The recon container holds the Neo4j
    credentials, and a target could hang it by serving a .js - no auth, no
    interaction. Bounding the clause makes the scan linear.
    """

    # Deliberately generous so the test is not flaky on a loaded CI box. The
    # pre-fix time for this payload was ~64s, so even a 20x slower machine
    # cannot pass it by accident.
    _BUDGET_SECONDS = 5.0

    def _worst_case(self, tokens):
        # No quotes and no `from`: the lazy clause can never match, so the
        # engine explores the maximum.
        return "import " * tokens

    @contextlib.contextmanager
    def _deadline(self, seconds):
        """Abort the regex mid-scan instead of waiting it out.

        Measuring elapsed time AFTER the call is useless as a regression guard
        here: with the bound removed the 5 MB case runs for hours, so the test
        would hang CI rather than fail it. SIGALRM interrupts the C-level regex
        loop, turning "quadratic again" into a fast, readable failure.

        Verified by mutation (raising _IMPORT_CLAUSE_MAX to 5_000_000): the
        suite goes from 4s to >120s without this, and fails in seconds with it.
        """
        if not hasattr(signal, "SIGALRM"):        # non-POSIX: fall back to timing
            yield
            return

        def _blew_the_deadline(signum, frame):
            raise AssertionError(
                "import mining exceeded {}s - the regex is quadratic again "
                "(catastrophic backtracking on attacker-served JS)".format(seconds))

        prev = signal.signal(signal.SIGALRM, _blew_the_deadline)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prev)

    def test_regression_no_quadratic_blowup_on_import_flood(self):
        payload = self._worst_case(40000)   # ~280 KB, the 64.4s case
        with self._deadline(self._BUDGET_SECONDS):
            harvest.mine_import_packages([payload])

    def test_regression_scales_linearly_not_quadratically(self):
        """4x the input must not cost ~16x the time."""
        def timed(tokens):
            payload = self._worst_case(tokens)
            started = time.monotonic()
            with self._deadline(self._BUDGET_SECONDS):
                harvest.mine_import_packages([payload])
            return time.monotonic() - started

        small = timed(20000)
        large = timed(80000)          # 4x the bytes
        # Linear would be ~4x. Quadratic would be ~16x. Allow 8x for noise, and
        # floor the baseline so a sub-millisecond `small` cannot blow up the
        # ratio on a fast machine.
        ratio = large / max(small, 0.01)
        self.assertLess(ratio, 8.0,
                        "4x input cost {:.1f}x the time - superlinear".format(ratio))

    def test_a_5mb_file_the_per_file_cap_stays_bounded(self):
        """js_recon's per-file ceiling must be survivable, not hours of CPU.

        This is the case that made the bug critical: one 5 MB served .js.
        """
        payload = self._worst_case(700000)   # ~4.9 MB
        with self._deadline(30.0):
            harvest.mine_import_packages([payload])

    def test_real_import_forms_still_match_after_bounding(self):
        """The bound must cost no legitimate detection."""
        src = (
            'import React from "react";\n'
            'import * as _ from "lodash";\n'
            'import { debounce, throttle as t } from "underscore";\n'
            'const ax = require("axios");\n'
            'import("@babel/runtime");\n'
            'export { x } from "@scope/pkg-name";\n'
        )
        names = {p["name"] for p in harvest.mine_import_packages([src])}
        self.assertEqual(names, {"react", "lodash", "underscore", "axios",
                                 "@babel/runtime", "@scope/pkg-name"})

    def test_relative_and_absolute_specifiers_still_excluded(self):
        src = 'import a from "./local";\nimport b from "/abs/path";\n'
        self.assertEqual(harvest.mine_import_packages([src]), [])

    def test_import_clause_longer_than_the_bound_still_resolves(self):
        """The bound costs nothing even on a clause that exceeds it.

        A >200-char destructuring clause makes the `import ... from` branch
        fail, but the alternation's `from\\s+` branch still matches at the
        `from "react"`. So bounding the clause loses no detection at all - it
        only removes the pathological backtracking.
        """
        long_clause = "{ " + ", ".join("a%d" % i for i in range(80)) + " }"
        self.assertGreater(len(long_clause), harvest._IMPORT_CLAUSE_MAX)
        src = 'import %s from "react";\n' % long_clause
        names = {p["name"] for p in harvest.mine_import_packages([src])}
        self.assertEqual(names, {"react"})
