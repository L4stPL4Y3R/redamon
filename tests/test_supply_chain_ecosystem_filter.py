"""The Supply Chain Recon ecosystem allow-filter - the backend half of the
Ecosystems multi-select in the webapp.

The UI stores a comma-separated string; run_supply_chain_recon matches it
EXACTLY against the ecosystem of every harvested package. These tests pin that
contract from the outside (through run_supply_chain_recon, not the private
helpers) because both failure modes are silent: a mis-cased or unknown name
reports zero packages with a green scan, and an "empty" value used to report
zero packages instead of all of them.

Run: python -m pytest tests/test_supply_chain_ecosystem_filter.py
"""

import contextlib
import importlib.util
import os
import sys
import types
import unittest
from unittest import mock
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

# Same by-path load as tests/test_supply_chain_recon.py: the harvest import is
# lazy, so this does not drag in the recon.helpers package __init__.
_spec = importlib.util.spec_from_file_location(
    "sc_recon_ecofilter",
    os.path.join(_REPO, "recon", "main_recon_modules", "supply_chain_recon.py"))
scr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scr)

_HARVEST_MODULE = "recon.helpers.supply_chain.harvest"

# What the harvester emits today: every source in harvest.py hardcodes npm.
_NPM = {"purl": "pkg:npm/lodash", "name": "lodash", "version": None,
        "ecosystem": "npm", "source": "sourcemap"}
# A non-npm sighting the harvester cannot currently produce. Kept so the filter
# itself is tested rather than the harvester's present-day npm-only behaviour.
_PYPI = {"purl": "pkg:pypi/flask", "name": "flask", "version": None,
         "ecosystem": "PyPI", "source": "sourcemap"}

_UNSET = object()


def _run(ecosystems=_UNSET, packages=(_NPM, _PYPI), *, retire_artifact=None):
    """Drive run_supply_chain_recon with a fake harvest + OSV verdict.

    Returns (packages_that_reached_the_verdict, combined_result).
    """
    fake_harvest = types.ModuleType(_HARVEST_MODULE)
    fake_harvest.harvest_packages = lambda **kwargs: [dict(p) for p in packages]

    seen = {}

    def fake_verdict(pkgs, *, db_path=None, osv=None):
        seen["packages"] = [dict(p) for p in pkgs]
        artifact = scr.empty_artifact("js-dir")
        artifact["packages"] = [dict(p) for p in pkgs]
        return artifact

    settings = {"SUPPLY_CHAIN_RECON_RETIRE_ENABLED": retire_artifact is not None}
    if ecosystems is not _UNSET:
        settings["SUPPLY_CHAIN_RECON_ECOSYSTEMS"] = ecosystems

    patches = [
        # The harvest import is lazy, so injecting the fully-qualified module
        # short-circuits it without importing the real recon.helpers package.
        mock.patch.dict(sys.modules, {_HARVEST_MODULE: fake_harvest}),
        mock.patch.object(scr, "verdict_packages", fake_verdict),
        mock.patch.object(scr, "_read_js_contents", lambda *a, **k: {}),
        mock.patch.object(scr, "_cleanup_js_work_dir", lambda *a, **k: None),
    ]
    if retire_artifact is not None:
        patches.append(mock.patch.object(
            scr, "retire_js_harvest",
            lambda *a, **k: (retire_artifact, {"ran": True, "packages": 1,
                                               "malicious": 0, "vulnerable": 0,
                                               "error": None})))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        combined = scr.run_supply_chain_recon({}, settings=settings)
    return seen["packages"], combined


def _ecosystems(pkgs):
    return sorted(p["ecosystem"] for p in pkgs)


class TestAllowFilter(unittest.TestCase):
    def test_canonical_name_keeps_only_that_ecosystem(self):
        kept, combined = _run("npm")
        self.assertEqual(_ecosystems(kept), ["npm"])
        # ... and that is what the artifact (hence the graph write) carries.
        self.assertEqual(combined["supply_chain_recon"]["summary"]["packages"], 1)

    def test_multiple_selected_ecosystems_are_all_kept(self):
        kept, _ = _run("npm,PyPI")
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_surrounding_whitespace_is_tolerated(self):
        kept, _ = _run(" npm , PyPI ")
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_a_list_value_is_accepted_too(self):
        # settings may carry a list (the value is normalized per element).
        kept, _ = _run(["npm"])
        self.assertEqual(_ecosystems(kept), ["npm"])

    def test_selecting_only_a_non_harvested_ecosystem_reports_nothing(self):
        # The consequence the UI has to warn about: the harvester is npm-only,
        # so a PyPI-only selection drops the whole harvested set.
        kept, combined = _run("PyPI", packages=(_NPM,))
        self.assertEqual(kept, [])
        self.assertEqual(combined["supply_chain_recon"]["summary"]["packages"], 0)


class TestNoFilterStates(unittest.TestCase):
    def test_empty_string_means_no_filter(self):
        kept, _ = _run("")
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_missing_setting_means_no_filter(self):
        kept, _ = _run()
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_none_means_no_filter(self):
        kept, _ = _run(None)
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_whitespace_only_value_means_no_filter(self):
        # REGRESSION: "  " is truthy but parses to an empty allow-set, so the
        # old `if ecos:` guard filtered EVERY package away - the exact opposite
        # of the "" case one keystroke away from it.
        kept, _ = _run("  ")
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])

    def test_comma_only_value_means_no_filter(self):
        kept, _ = _run(" , , ")
        self.assertEqual(_ecosystems(kept), ["PyPI", "npm"])


class TestExactMatchContract(unittest.TestCase):
    """Why the widget must store canonical names - these values are all things a
    human typed into the old free-text field."""

    def test_wrong_case_matches_nothing(self):
        kept, _ = _run("NPM", packages=(_NPM,))
        self.assertEqual(kept, [])

    def test_lowercase_pypi_matches_nothing(self):
        kept, _ = _run("pypi", packages=(_PYPI,))
        self.assertEqual(kept, [])

    def test_unknown_token_is_a_live_filter_that_matches_nothing(self):
        # Not the same as no filter: "cargo" reports zero packages.
        kept, _ = _run("cargo")
        self.assertEqual(kept, [])

    def test_unknown_token_next_to_a_valid_one_keeps_the_valid_one(self):
        kept, _ = _run("npm,cargo")
        self.assertEqual(_ecosystems(kept), ["npm"])


class TestRetirePassIsNotFiltered(unittest.TestCase):
    """Characterization: the allow-filter applies to the HARVESTED set only.

    retire.js merges into the artifact after the verdict, so its components are
    reported whatever the filter says. That is deliberate (it is the only source
    of versioned components, i.e. most real verdicts), and the UI warning says
    so - but it must not change silently.
    """

    def _retire_artifact(self):
        artifact = scr.empty_artifact("js-dir")
        artifact["packages"] = [{
            "purl": "pkg:npm/jquery@1.7.2", "name": "jquery",
            "version": "1.7.2", "ecosystem": "npm", "source": "retire",
        }]
        return artifact

    def test_retire_components_survive_a_filter_that_excludes_them(self):
        _, combined = _run("PyPI", packages=(_NPM,),
                           retire_artifact=self._retire_artifact())
        artifact = combined["supply_chain_recon"]["artifact"]
        names = sorted(p["name"] for p in artifact["packages"])
        self.assertEqual(names, ["jquery"])  # harvested lodash filtered, retire kept

    def test_retire_and_harvest_are_both_reported_when_npm_is_selected(self):
        _, combined = _run("npm", packages=(_NPM,),
                           retire_artifact=self._retire_artifact())
        artifact = combined["supply_chain_recon"]["artifact"]
        names = sorted(p["name"] for p in artifact["packages"])
        self.assertEqual(names, ["jquery", "lodash"])


if __name__ == "__main__":
    unittest.main()
