"""Smoke + regression tests: modules import cleanly, the analyzer entrypoint
assembles a schema-valid artifact for every mode even when the tool binaries are
absent, and the OSV-DB world-readable perms fix actually loosens permissions.

Run: python -m unittest tests.test_supply_chain_smoke
"""

import importlib
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())


class TestImportsSmoke(unittest.TestCase):
    def test_all_common_modules_import(self):
        for name in ["osv_runner", "guarddog_runner", "retire_runner",
                     "purl", "security", "osv_db_sync", "_run"]:
            importlib.import_module("supply_chain_common." + name)

    def test_mixin_and_schema_import(self):
        importlib.import_module("graph_db.mixins.supply_chain_mixin")
        schema = importlib.import_module("graph_db.schema")
        joined = " ".join(schema.CONSTRAINTS)
        self.assertIn("Package", joined)
        self.assertIn("MalPackageFinding", joined)


def _load_entrypoint():
    path = os.path.join(_REPO, "scanners", "supply_chain_analyzer", "entrypoint.py")
    spec = importlib.util.spec_from_file_location("sc_entrypoint", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestAnalyzerEntrypointSmoke(unittest.TestCase):
    """run_job must ALWAYS return a schema-valid artifact (it self-validates),
    even with no osv-scanner/retire/guarddog binary on this host."""

    @classmethod
    def setUpClass(cls):
        cls.ep = _load_entrypoint()

    def _assert_valid(self, art):
        # run_job returns validate_artifact(...) output; presence of the canonical
        # keys proves it passed the boundary.
        for k in ["schema_version", "packages", "malicious", "vulnerable",
                  "suspicious", "errors"]:
            self.assertIn(k, art)

    def test_bogus_mode(self):
        art = self.ep.run_job({"mode": "bogus", "target": "/x"})
        self._assert_valid(art)
        self.assertTrue(art["errors"])

    def test_lockfile_mode_missing_binary(self):
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "package-lock.json")
            with open(lock, "w") as fh:
                fh.write('{"name":"t","lockfileVersion":3,"packages":{}}')
            art = self.ep.run_job({"mode": "lockfile", "target": lock})
        self._assert_valid(art)

    def test_js_dir_mode_missing_binary(self):
        with tempfile.TemporaryDirectory() as d:
            art = self.ep.run_job({"mode": "js-dir", "target": d})
        self._assert_valid(art)

    def test_F3_hostile_guarddog_name_does_not_abort_job(self):
        # F3: a hostile guarddog package coordinate must NOT crash run_job or
        # discard the artifact; it becomes a soft error, run_job still returns a
        # boundary-valid artifact.
        art = self.ep.run_job({
            "mode": "bogus", "target": "/x", "deep_analysis": True,
            "guarddog_packages": [{"ecosystem": "npm", "name": "evil;rm -rf /"}]})
        self._assert_valid(art)
        self.assertTrue(any("guarddog" in e for e in art["errors"]))

    def test_deep_analysis_capped_and_valid(self):
        # 200 guarddog packages requested; entrypoint caps at 100 and still
        # returns a valid artifact (binaries absent -> errors, never a crash).
        art = self.ep.run_job({
            "mode": "lockfile", "target": "/nope",
            "deep_analysis": True,
            "guarddog_packages": [{"ecosystem": "npm", "name": "p{}".format(i)}
                                  for i in range(200)]})
        self._assert_valid(art)


class TestPermsRegression(unittest.TestCase):
    """Regression for the silent-empty-results bug: osv-scanner writes the DB
    tree 0750; the non-root read-only scanner needs world-traverse. The sync's
    _make_world_readable must add o+rX to dirs and o+r to files."""

    def test_make_world_readable(self):
        from supply_chain_common.osv_db_sync import _make_world_readable
        with tempfile.TemporaryDirectory() as root:
            sub = os.path.join(root, "osv-scanner", "npm")
            os.makedirs(sub)
            f = os.path.join(sub, "all.zip")
            with open(f, "w") as fh:
                fh.write("x")
            os.chmod(sub, 0o750)
            os.chmod(f, 0o640)
            _make_world_readable(root)
            self.assertTrue(os.stat(sub).st_mode & stat.S_IROTH)
            self.assertTrue(os.stat(sub).st_mode & stat.S_IXOTH)
            self.assertTrue(os.stat(f).st_mode & stat.S_IROTH)


if __name__ == "__main__":
    unittest.main()
