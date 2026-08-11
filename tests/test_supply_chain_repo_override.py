"""Scan Queue Phase 6 - supply_chain_repo per-repo override.

An org-batch item scans ONE repo, passed by the orchestrator as
SUPPLY_CHAIN_REPO_OVERRIDE_* env. project_settings.load_project_settings must apply
that override on EVERY return path (both DEFAULT fallbacks AND the successful
project fetch), forcing github input mode + the batch repo, so an item never scans
the project's default target.

Run under the root-agent section (image redamon-agent).
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

_REPO = str(Path(__file__).resolve().parents[1])
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Load scanners/supply_chain_scan/project_settings.py in isolation (avoid colliding with the
# other project_settings.py modules in the tree).
_spec = importlib.util.spec_from_file_location(
    "sc_project_settings", os.path.join(_REPO, "scanners", "supply_chain_scan", "project_settings.py"))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

_OVERRIDE_ENV = (
    "SUPPLY_CHAIN_REPO_OVERRIDE_URL", "SUPPLY_CHAIN_REPO_OVERRIDE_REF",
    "SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE", "SUPPLY_CHAIN_REPO_OVERRIDE_DEEP",
    "WEBAPP_API_URL",
)


class TestRepoOverride(unittest.TestCase):
    def setUp(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        ps._settings = None
        ps._current_project_id = None

    def tearDown(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        ps._settings = None
        ps._current_project_id = None

    def test_no_override_is_a_noop(self):
        base = ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
        out = ps._apply_repo_override(base)
        self.assertEqual(out["SUPPLY_CHAIN_INPUT_MODE"], "upload")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_URL"], "")

    def test_override_forces_github_and_the_repo(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/a.git"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_REF"] = "main"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE"] = "packages/x"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_DEEP"] = "1"
        out = ps._apply_repo_override(ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy())
        self.assertEqual(out["SUPPLY_CHAIN_INPUT_MODE"], "github")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_URL"], "https://github.com/acme/a.git")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_REF"], "main")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_SCOPE"], "packages/x")
        self.assertTrue(out["SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED"])

    def test_deep_flag_off_is_respected(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/a.git"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_DEEP"] = "0"
        out = ps._apply_repo_override({**ps.DEFAULT_SUPPLY_CHAIN_SETTINGS, "SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED": True})
        self.assertFalse(out["SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED"])

    def test_load_applies_override_on_the_no_webapp_fallback(self):
        # No WEBAPP_API_URL -> DEFAULT fallback path, override must still apply.
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/b.git"
        settings = ps.load_project_settings("p1")
        self.assertEqual(settings["SUPPLY_CHAIN_INPUT_MODE"], "github")
        self.assertEqual(settings["SUPPLY_CHAIN_REPO_URL"], "https://github.com/acme/b.git")


if __name__ == "__main__":
    unittest.main()
