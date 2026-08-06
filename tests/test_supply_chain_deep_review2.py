"""Second deep-review pass: the GuardDog deep-analysis dispatch (L2).

Targets the surface added after the first review: deep_analyze / flagged_specs /
_add_soft_error and their integration in run_supply_chain_recon. Named after the
findings so they cannot come back.

Run: python -m unittest tests.test_supply_chain_deep_review2
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

_spec = importlib.util.spec_from_file_location(
    "sc_recon_r2",
    os.path.join(_REPO, "recon", "main_recon_modules", "supply_chain_recon.py"))
scr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scr)


def _artifact_with_flagged(n=2):
    """Artifact with n OSV-flagged npm packages (the deep-analysis input set)."""
    art = {"schema_version": 1, "mode": "js-dir", "packages": [], "malicious": [],
           "vulnerable": [], "suspicious": [], "errors": []}
    for i in range(n):
        art["malicious"].append({
            "purl": "pkg:npm/bad{}@1.0.0".format(i), "name": "bad{}".format(i),
            "version": "1.0.0", "ecosystem": "npm", "advisory_id": "MAL-{}".format(i),
            "severity": "high", "confidence": "malicious",
        })
    return art


class _GD:
    """Stand-in for supply_chain_common.guarddog_runner."""

    def __init__(self, per_package):
        self.per_package = per_package  # name -> {findings, error}
        self.calls = []

    def hardened_docker_argv(self, image=None, **kw):
        return ["docker", "run", "--rm", "--cap-drop", "ALL", "--read-only",
                "--entrypoint", "guarddog", image or "img"]

    def scan_package(self, ecosystem, name, version=None, *, timeout=None,
                     argv_prefix=None):
        self.calls.append((ecosystem, name, version, timeout, tuple(argv_prefix or ())))
        return self.per_package.get(name, {"findings": [], "error": None})


class TestD1SoftErrorsSurviveInvalidArtifact(unittest.TestCase):
    """D1: on ArtifactError the fallback wiped artifact['suspicious'] wholesale.

    One bad GuardDog finding then erased every soft-error marker, so packages
    GuardDog never actually analysed went back to reading behaviourally CLEAN -
    exactly the invariant _add_soft_error exists to protect.
    """

    def test_D1_one_invalid_finding_does_not_erase_other_soft_errors(self):
        gd = _GD({
            # bad0: a finding whose severity is not in the allowed set -> the
            # artifact fails revalidation.
            "bad0": {"findings": [{"package": "bad0", "rule": "npm-obfuscation",
                                   "severity": "boom", "message": "x",
                                   "soft_error": False}], "error": None},
            # bad1: download failed -> must stay marked as NOT analysed.
            "bad1": {"findings": [], "error": "download-package: 404"},
        })
        art = _artifact_with_flagged(2)
        cr = {"js_recon": {}, "http_probe": {}}

        # run_supply_chain_recon lazily imports the harvest helper, which pulls
        # recon.helpers.__init__ (needs dns, absent on the host). Stub it.
        import types as _t
        _h = _t.ModuleType("recon.helpers.supply_chain.harvest")
        _h.harvest_packages = lambda **kw: []
        saved = {k: sys.modules.get(k) for k in
                 ("recon", "recon.helpers", "recon.helpers.supply_chain",
                  "recon.helpers.supply_chain.harvest")}
        for k in ("recon", "recon.helpers", "recon.helpers.supply_chain"):
            sys.modules.setdefault(k, _t.ModuleType(k))
        sys.modules["recon.helpers.supply_chain.harvest"] = _h

        orig_deep = scr.deep_analyze
        scr.deep_analyze = lambda a, **kw: orig_deep(a, guarddog=gd, **kw)
        orig_verdict = scr.verdict_packages
        scr.verdict_packages = lambda pkgs, **kw: art
        try:
            out = scr.run_supply_chain_recon(
                cr, settings={"SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED": True})
        finally:
            scr.deep_analyze = orig_deep
            scr.verdict_packages = orig_verdict
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

        result = out["supply_chain_recon"]["artifact"]
        # The invalid finding must be dropped, but bad1 must STILL be flagged as
        # not-analysed. A package GuardDog never scanned must never read clean.
        names = {f.get("name") for f in result["suspicious"]}
        self.assertIn("bad1", names,
                      "soft-error marker for an unanalysed package was erased")
        self.assertTrue(result["errors"], "the drop must be recorded in errors")


class TestDeepAnalyzeContract(unittest.TestCase):
    def test_guarddog_never_claims_malicious(self):
        gd = _GD({"bad0": {"findings": [{"package": "bad0", "rule": "r",
                                         "severity": "high", "message": "m",
                                         "soft_error": False}], "error": None}})
        art, stats = scr.deep_analyze(_artifact_with_flagged(1), guarddog=gd)
        self.assertTrue(all(f["confidence"] == "suspicious" for f in art["suspicious"]))
        self.assertEqual(stats["scanned"], 1)

    def test_download_failure_becomes_soft_error_not_clean(self):
        gd = _GD({"bad0": {"findings": [], "error": "download-package: gone"}})
        art, stats = scr.deep_analyze(_artifact_with_flagged(1), guarddog=gd)
        self.assertEqual(len(art["suspicious"]), 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])
        self.assertEqual(stats["failed"], 1)

    def test_dispatch_exception_isolated_per_package(self):
        class Boom(_GD):
            def scan_package(self, *a, **kw):
                raise RuntimeError("socket gone")
        art, stats = scr.deep_analyze(_artifact_with_flagged(2), guarddog=Boom({}))
        # both packages recorded as not-analysed, OSV verdicts untouched
        self.assertEqual(len(art["suspicious"]), 2)
        self.assertEqual(len(art["malicious"]), 2)
        self.assertEqual(stats["failed"], 2)

    def test_budget_exhaustion_marks_remaining_unanalysed(self):
        gd = _GD({})
        art, stats = scr.deep_analyze(_artifact_with_flagged(3), guarddog=gd,
                                      budget=-1)  # already over budget
        self.assertEqual(stats["skipped_budget"], 3)
        self.assertEqual(len(art["suspicious"]), 3)
        self.assertTrue(all(f["soft_error"] for f in art["suspicious"]))
        self.assertEqual(gd.calls, [], "no scan may run once the budget is gone")

    def test_runs_inside_hardened_container(self):
        gd = _GD({})
        scr.deep_analyze(_artifact_with_flagged(1), guarddog=gd)
        argv = gd.calls[0][4]
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--read-only", argv)

    def test_cap_reported_not_silently_truncated(self):
        art = _artifact_with_flagged(5)
        specs = scr.flagged_specs(art, limit=2)
        self.assertEqual(len(specs), 2)

    def test_unsupported_ecosystem_skipped(self):
        art = _artifact_with_flagged(0)
        art["malicious"].append({"purl": "pkg:maven/g/a@1", "name": "g:a",
                                 "version": "1", "ecosystem": "Maven",
                                 "confidence": "malicious"})
        self.assertEqual(scr.flagged_specs(art), [])

    def test_dedup_same_package_in_both_buckets(self):
        art = _artifact_with_flagged(1)
        art["vulnerable"].append({"purl": "pkg:npm/bad0@1.0.0", "name": "bad0",
                                  "version": "1.0.0", "ecosystem": "npm"})
        self.assertEqual(len(scr.flagged_specs(art)), 1)

    def test_findings_carry_the_versioned_purl(self):
        # Without the purl the graph writer MERGEs a second, versionless Package.
        gd = _GD({"bad0": {"findings": [{"package": "bad0", "rule": "r",
                                         "severity": "low", "message": "m"}],
                           "error": None}})
        art, _ = scr.deep_analyze(_artifact_with_flagged(1), guarddog=gd)
        self.assertEqual(art["suspicious"][0]["purl"], "pkg:npm/bad0@1.0.0")


if __name__ == "__main__":
    unittest.main()
