"""Second deep-review pass: the GuardDog deep-analysis dispatch (L2).

Targets the surface added after the first review: deep_analyze / flagged_specs /
_add_soft_error and their integration in run_supply_chain_recon. Named after the
findings so they cannot come back.

Run: python -m unittest tests.test_supply_chain_deep_review2
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from supply_chain_common import analyzer_dispatch
from supply_chain_common.artifact import empty_artifact

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
    """Stand-in for the ANALYZER DISPATCH, which is where GuardDog now runs.

    This used to fake supply_chain_common.guarddog_runner, because deep_analyze
    called gd_mod.scan_package directly. It no longer does: every hostile-byte
    operation - retire.js, osv-scanner, GuardDog - goes through one analyzer job
    contract, so the dispatch is the only seam that controls what comes back.

    Faking the wrong seam did not fail loudly. deep_analyze quietly spawned REAL
    docker, every package errored, and most assertions here were satisfied BY
    THAT FAILURE - a download-failure test passes just as well when the failure
    is "no such image". Two tests broke honestly; the rest passed for the wrong
    reason and made the suite depend on a docker daemon.

    `per_package` maps a package name to what the analyzer returns for it:
      {"suspicious": [...], "error": "...", "no_artifact": True}
    """

    def __init__(self, per_package):
        self.per_package = per_package  # name -> analyzer outcome
        self.calls = []                 # (ecosystem, name, version, timeout, argv)
        self.jobs = []
        self._dirs = []

    def new_work_dir(self, prefix="sc-job"):
        d = tempfile.mkdtemp(prefix=prefix + "-")
        self._dirs.append(d)
        return d

    def run_analyzer_job(self, job, work_dir, sc_common, *, image=None,
                         allow_registry_egress=False, timeout=None, **kw):
        self.jobs.append({"job": job, "image": image, "timeout": timeout,
                          "allow_registry_egress": allow_registry_egress})
        specs = job.get("guarddog_packages") or []
        spec = specs[0] if specs else {}
        # Build the argv the REAL dispatch would build for this job, so the
        # hardening assertions below check the actual builder with the actual
        # arguments deep_analyze passed - not a stub's idea of them.
        argv = analyzer_dispatch.analyzer_docker_argv(
            work_dir, sc_common, image=image,
            allow_registry_egress=allow_registry_egress)
        self.calls.append((spec.get("ecosystem"), spec.get("name"),
                           spec.get("version"), timeout, tuple(argv)))

        outcome = self.per_package.get(spec.get("name"), {})
        if outcome.get("no_artifact"):
            return {"artifact": None, "exit_code": 1,
                    "error": outcome.get("error") or "analyzer produced no artifact"}
        art = empty_artifact("purls")
        art["suspicious"].extend(outcome.get("suspicious") or [])
        art["errors"].extend(outcome.get("errors") or [])
        return {"artifact": art, "exit_code": 0, "error": outcome.get("error")}


def _suspicious(name, rule="r", severity="high", message="m", soft_error=False,
                version="1.0.0"):
    """One `suspicious` entry as the analyzer emits it (pre-mapping)."""
    return {"name": name, "version": version, "ecosystem": "npm",
            "purl": "pkg:npm/{}@{}".format(name, version), "rule": rule,
            "severity": severity, "message": message,
            "confidence": "suspicious", "soft_error": soft_error}


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
            "bad0": {"suspicious": [_suspicious("bad0", rule="npm-obfuscation",
                                                severity="boom", message="x")]},
            # bad1: download failed -> must stay marked as NOT analysed.
            "bad1": {"error": "download-package: 404"},
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
        scr.deep_analyze = lambda a, **kw: orig_deep(a, dispatch=gd, **kw)
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
        gd = _GD({"bad0": {"suspicious": [_suspicious("bad0")]}})
        art, stats = scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        self.assertTrue(all(f["confidence"] == "suspicious" for f in art["suspicious"]))
        self.assertEqual(stats["scanned"], 1)

    def test_download_failure_becomes_soft_error_not_clean(self):
        gd = _GD({"bad0": {"error": "download-package: gone"}})
        art, stats = scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        self.assertEqual(len(art["suspicious"]), 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])
        self.assertEqual(stats["failed"], 1)

    def test_analyzer_returning_no_artifact_is_not_clean(self):
        """A dead socket / unpulled image yields no artifact at all. That must
        read as 'not analysed', never as 'analysed and nothing found'."""
        gd = _GD({"bad0": {"no_artifact": True, "error": "no such image"}})
        art, stats = scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        self.assertEqual(stats["scanned"], 0)
        self.assertEqual(stats["failed"], 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])

    def test_dispatch_exception_isolated_per_package(self):
        class Boom(_GD):
            def run_analyzer_job(self, *a, **kw):
                raise RuntimeError("socket gone")
        art, stats = scr.deep_analyze(_artifact_with_flagged(2), dispatch=Boom({}))
        # both packages recorded as not-analysed, OSV verdicts untouched
        self.assertEqual(len(art["suspicious"]), 2)
        self.assertEqual(len(art["malicious"]), 2)
        self.assertEqual(stats["failed"], 2)

    def test_budget_exhaustion_marks_remaining_unanalysed(self):
        gd = _GD({})
        art, stats = scr.deep_analyze(_artifact_with_flagged(3), dispatch=gd,
                                      budget=-1)  # already over budget
        self.assertEqual(stats["skipped_budget"], 3)
        self.assertEqual(len(art["suspicious"]), 3)
        self.assertTrue(all(f["soft_error"] for f in art["suspicious"]))
        self.assertEqual(gd.calls, [], "no scan may run once the budget is gone")

    def test_runs_inside_hardened_container(self):
        gd = _GD({})
        scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        argv = gd.calls[0][4]
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--read-only", argv)
        # No secret may ride along: a full RCE inside the analyzer must find no
        # Neo4j password, no internal-API key, no GitHub token.
        joined = " ".join(argv)
        for leak in ("NEO4J", "PASSWORD", "TOKEN", "API_KEY", "SECRET"):
            self.assertNotIn(leak, joined.upper())

    def test_guarddog_gets_registry_egress_and_the_package_coordinates(self):
        """GuardDog is the one leg that MUST reach the registry - it downloads
        the tarball it analyses. The OSV/retire legs must not."""
        gd = _GD({})
        scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        self.assertTrue(gd.jobs[0]["allow_registry_egress"])
        job = gd.jobs[0]["job"]
        self.assertTrue(job["deep_analysis"])
        self.assertEqual([(p["ecosystem"], p["name"], p["version"])
                          for p in job["guarddog_packages"]],
                         [("npm", "bad0", "1.0.0")])

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
        gd = _GD({"bad0": {"suspicious": [_suspicious("bad0", severity="low")]}})
        art, _ = scr.deep_analyze(_artifact_with_flagged(1), dispatch=gd)
        self.assertEqual(art["suspicious"][0]["purl"], "pkg:npm/bad0@1.0.0")


if __name__ == "__main__":
    unittest.main()
