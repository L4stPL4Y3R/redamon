"""Phase 0.4 integration tests: real osv-scanner / guarddog / retire binaries.

These run OFFLINE where possible and are SKIPPED when a tool is not installed on
the host (they only pass inside the built images where the binaries exist). CI
that builds the supply-chain images should run these with the OSV DB volume
mounted and OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY set.

Run: python -m unittest tests.test_supply_chain_integration
"""

import os
import shutil
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from supply_chain_common import osv_runner, guarddog_runner, retire_runner

_HAS_OSV = shutil.which("osv-scanner") is not None
_HAS_GUARDDOG = shutil.which("guarddog") is not None
_HAS_RETIRE = shutil.which("retire") is not None
_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")


@unittest.skipUnless(_HAS_OSV and _OSV_DB, "osv-scanner + offline DB required")
class TestOsvIntegration(unittest.TestCase):
    def test_known_malicious_npm_lockfile(self):
        # A lockfile pinning a known-malicious npm typosquat from the corpus.
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "package-lock.json")
            with open(lock, "w") as fh:
                fh.write(
                    '{"name":"t","version":"1.0.0","lockfileVersion":3,'
                    '"packages":{"":{"dependencies":{"lodahs":"1.0.0"}},'
                    '"node_modules/lodahs":{"version":"1.0.0"}}}')
            res = osv_runner.run_osv_scan(lock, mode="lockfile", db_path=_OSV_DB)
            self.assertIsNone(res["error"], res["error"])
            self.assertTrue(
                any(m["advisory_id"].startswith("MAL-")
                    for m in res["parsed"]["malicious"]),
                "expected a MAL- verdict for lodahs")


@unittest.skipUnless(_HAS_GUARDDOG, "guarddog required")
class TestGuarddogIntegration(unittest.TestCase):
    def test_benign_package_wellformed(self):
        res = guarddog_runner.scan_package("npm", "left-pad", version="1.3.0")
        # A benign package must at least parse to a well-formed result object.
        self.assertIsInstance(res["findings"], list)


@unittest.skipUnless(_HAS_RETIRE, "retire required")
class TestRetireIntegration(unittest.TestCase):
    def test_old_jquery_detected(self):
        with tempfile.TemporaryDirectory() as d:
            # Minimal filecontent fingerprint of an old jQuery.
            with open(os.path.join(d, "jquery.js"), "w") as fh:
                fh.write("/*! jQuery v1.12.4 */\n")
            res = retire_runner.scan_js_dir(d)
            names = {c["name"] for c in res["components"]}
            self.assertIn("jquery", names)


if __name__ == "__main__":
    unittest.main()
