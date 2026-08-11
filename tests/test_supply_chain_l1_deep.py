"""Unit tests for L1 deep behavioural analysis (supply_chain_scan/deep_analysis).

`SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED` was parsed by project_settings.py and read
NOWHERE - a dead switch in the UI. L1 also had no way to reach the analyzer: its
container was spawned with no broker socket and no DOCKER_HOST.

Run: python -m pytest tests/test_supply_chain_l1_deep.py
"""

import os
import shutil
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from supply_chain_scan import deep_analysis as da           # noqa: E402
from supply_chain_common.artifact import empty_artifact     # noqa: E402
from supply_chain_common.security import validate_artifact  # noqa: E402
from supply_chain_common.deep_recovery import (              # noqa: E402
    recover_invalid_deep_artifact,
)


def _flagged(name, version, eco="npm", bucket="malicious"):
    return {"name": name, "version": version, "ecosystem": eco,
            "purl": "pkg:{}/{}@{}".format(eco.lower(), name, version),
            "advisory_id": "MAL-1" if bucket == "malicious" else "GHSA-1",
            "severity": "high", "confidence": "malicious"}


def _artifact(malicious=(), vulnerable=()):
    a = empty_artifact("lockfile")
    a["malicious"].extend(malicious)
    a["vulnerable"].extend(vulnerable)
    return a


class _FakeDispatch:
    def __init__(self, suspicious=None, error=None, raises=None):
        self.suspicious = suspicious or []
        self.error = error
        self.raises = raises
        self.jobs = []

    def new_work_dir(self, prefix="sc-job"):
        return tempfile.mkdtemp(prefix=prefix + "-")

    def run_analyzer_job(self, job, work_dir, sc_common, **kw):
        if self.raises:
            raise self.raises
        self.jobs.append({"job": job, "kw": kw})
        if self.error:
            return {"artifact": None, "exit_code": 1, "error": self.error}
        art = empty_artifact("purls")
        art["suspicious"].extend(self.suspicious)
        return {"artifact": art, "exit_code": 0, "error": None}


def _susp(name, version, rule, severity="low", soft=False):
    return {"name": name, "version": version, "ecosystem": "npm",
            "rule": rule, "severity": severity, "confidence": "suspicious",
            "message": "m", "soft_error": soft}


class TestFlaggedSpecs(unittest.TestCase):

    def test_only_flagged_packages_selected(self):
        art = _artifact(malicious=[_flagged("axios", "1.14.1")])
        art["packages"].append({"purl": "pkg:npm/lodash", "name": "lodash",
                                "ecosystem": "npm", "source": "osv"})
        self.assertEqual([s["name"] for s in da.flagged_specs(art)], ["axios"])

    def test_malicious_before_vulnerable(self):
        art = _artifact(malicious=[_flagged("mal", "1.0")],
                        vulnerable=[_flagged("vul", "2.0", bucket="vulnerable")])
        self.assertEqual([s["name"] for s in da.flagged_specs(art)], ["mal", "vul"])

    def test_dedups_across_buckets(self):
        f = _flagged("axios", "1.14.1")
        art = _artifact(malicious=[f], vulnerable=[dict(f)])
        self.assertEqual(len(da.flagged_specs(art)), 1)

    def test_skips_ecosystems_guarddog_cannot_analyse(self):
        art = _artifact(vulnerable=[_flagged("g:a", "1.0", eco="Maven")])
        self.assertEqual(da.flagged_specs(art), [])

    def test_cap_is_not_silent(self):
        import contextlib
        import io
        art = _artifact(malicious=[_flagged("p%d" % i, "1.0") for i in range(5)])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            specs = da.flagged_specs(art, limit=2)
        self.assertEqual(len(specs), 2)
        self.assertIn("cap", buf.getvalue().lower())

    def test_empty_artifact(self):
        self.assertEqual(da.flagged_specs(empty_artifact()), [])


class TestDeepAnalyze(unittest.TestCase):

    def test_regression_l1_deep_analysis_actually_runs(self):
        """REGRESSION: SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED was parsed and read
        nowhere, and L1 had no broker socket to reach the analyzer with."""
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        d = _FakeDispatch(suspicious=[_susp("jquery", "3.4.1", "capability-process-spawn")])
        art, stats = da.deep_analyze(art, dispatch=d)
        self.assertEqual(stats["scanned"], 1)
        self.assertEqual(stats["suspicious"], 1)
        self.assertEqual(len(art["suspicious"]), 1)

    def test_findings_carry_the_versioned_purl(self):
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        d = _FakeDispatch(suspicious=[_susp("jquery", "3.4.1", "r1")])
        art, _ = da.deep_analyze(art, dispatch=d)
        self.assertEqual(art["suspicious"][0]["purl"], "pkg:npm/jquery@3.4.1")

    def test_registry_egress_is_opted_in(self):
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        d = _FakeDispatch()
        da.deep_analyze(art, dispatch=d)
        self.assertTrue(d.jobs[0]["kw"]["allow_registry_egress"])

    def test_job_carries_every_flagged_package(self):
        art = _artifact(malicious=[_flagged("a", "1"), _flagged("b", "2")])
        d = _FakeDispatch()
        da.deep_analyze(art, dispatch=d)
        names = {p["name"] for p in d.jobs[0]["job"]["guarddog_packages"]}
        self.assertEqual(names, {"a", "b"})

    def test_no_flagged_packages_means_no_dispatch(self):
        d = _FakeDispatch()
        _, stats = da.deep_analyze(empty_artifact(), dispatch=d)
        self.assertEqual(d.jobs, [])
        self.assertEqual(stats["scanned"], 0)

    def test_regression_dispatch_failure_is_not_a_silent_clean(self):
        """The graph writer never reads artifact["errors"], so a failed run must
        leave a visible soft-error finding on each package."""
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        art, stats = da.deep_analyze(
            art, dispatch=_FakeDispatch(error="analyzer exit 125: no such image"))
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(len(art["suspicious"]), 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])
        self.assertEqual(art["suspicious"][0]["rule"], "guarddog-not-run")

    def test_raised_exception_is_also_recorded(self):
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        art, stats = da.deep_analyze(
            art, dispatch=_FakeDispatch(raises=RuntimeError("docker exploded")))
        self.assertEqual(stats["failed"], 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])

    def test_guarddog_soft_error_counted_separately(self):
        art = _artifact(malicious=[_flagged("axios", "1.14.1")])
        d = _FakeDispatch(suspicious=[_susp("axios", "1.14.1", "download-package", soft=True)])
        art, stats = da.deep_analyze(art, dispatch=d)
        self.assertEqual(stats["soft_errors"], 1)
        self.assertEqual(stats["suspicious"], 0)

    def test_result_clears_the_boundary_validator(self):
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        d = _FakeDispatch(suspicious=[_susp("jquery", "3.4.1", "r1", "medium")])
        art, _ = da.deep_analyze(art, dispatch=d)
        validate_artifact(art)

    def test_osv_verdicts_are_preserved(self):
        art = _artifact(malicious=[_flagged("jquery", "3.4.1")])
        art, _ = da.deep_analyze(art, dispatch=_FakeDispatch())
        self.assertEqual(len(art["malicious"]), 1)


class TestL1ContainerCanReachTheAnalyzer(unittest.TestCase):
    """The code above is useless unless the spawned L1 container can actually
    run `docker`. It holds the Neo4j creds, so it gets the BROKER socket - the
    same posture the recon container has always had, and narrower than an
    orchestrator API key."""

    def _spawn_block(self):
        src = open(os.path.join(_REPO, "recon_orchestrator",
                                "container_manager.py")).read()
        i = src.index("def start_supply_chain")
        return src[i:i + 9000]

    def test_regression_l1_gets_the_broker_socket(self):
        self.assertIn("BROKER_SOCKET_VOLUME", self._spawn_block())

    def test_l1_gets_docker_host_pointing_at_the_broker(self):
        self.assertIn("unix:///var/run/broker/docker.sock", self._spawn_block())

    def test_l1_never_gets_the_raw_docker_socket(self):
        block = self._spawn_block()
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", block)

    def test_l1_knows_the_host_path_for_the_analyzer_mount(self):
        self.assertIn("SUPPLY_CHAIN_COMMON_HOST_PATH", self._spawn_block())


class TestD1SoftErrorsSurviveInvalidArtifactInL1(unittest.TestCase):
    """REGRESSION: the D1 false-clean, in the L1 standalone scan.

    L2 was hardened so one unvalidatable GuardDog finding could not erase the
    soft-error markers that record "this package was never actually analysed".
    L1 kept `artifact["suspicious"] = []` - the exact wipe D1 was about - so a
    single malformed finding made every un-analysed package read as
    behaviourally CLEAN, which is the one thing those markers exist to prevent.

    Both layers now share supply_chain_common.deep_recovery.
    """

    def _artifact_with(self, findings):
        art = _artifact(malicious=[_flagged("bad0", "1.0.0"),
                                   _flagged("bad1", "1.0.0")])
        art["suspicious"].extend(findings)
        return art

    def test_D1_l1_one_invalid_finding_does_not_erase_other_soft_errors(self):
        good_soft = {"name": "bad1", "version": "1.0.0", "ecosystem": "npm",
                     "purl": "pkg:npm/bad1@1.0.0", "rule": "guarddog-not-run",
                     "severity": "low", "confidence": "suspicious",
                     "message": "download failed", "soft_error": True}
        # severity "boom" is outside the allowed set -> the whole artifact fails.
        bad = {"name": "bad0", "version": "1.0.0", "ecosystem": "npm",
               "purl": "pkg:npm/bad0@1.0.0", "rule": "npm-obfuscation",
               "severity": "boom", "confidence": "suspicious",
               "message": "x", "soft_error": False}
        art = self._artifact_with([bad, good_soft])

        with self.assertRaises(Exception):
            validate_artifact(art)

        out = recover_invalid_deep_artifact(
            art, "severity boom", validate=validate_artifact,
            flagged_specs=da.flagged_specs, add_soft_error=da._soft_error)

        names = {f["name"] for f in out["suspicious"]}
        self.assertIn("bad1", names,
                      "the surviving soft-error marker was erased")
        self.assertIn("bad0", names,
                      "bad0 lost its finding and must be re-marked NOT analysed")
        self.assertTrue(
            all(f["soft_error"] for f in out["suspicious"] if f["name"] == "bad0"),
            "a package whose result was dropped must never read as analysed")
        self.assertTrue(out["errors"], "the drop must be recorded")

    def test_D1_l1_valid_findings_are_not_collateral_damage(self):
        """A real GuardDog hit must survive a malformed sibling."""
        real = {"name": "bad1", "version": "1.0.0", "ecosystem": "npm",
                "purl": "pkg:npm/bad1@1.0.0", "rule": "npm-obfuscation",
                "severity": "high", "confidence": "suspicious",
                "message": "obfuscated payload", "soft_error": False}
        bad = {"name": "bad0", "version": "1.0.0", "ecosystem": "npm",
               "purl": "pkg:npm/bad0@1.0.0", "rule": "r",
               "severity": "nope", "confidence": "suspicious",
               "message": "x", "soft_error": False}
        out = recover_invalid_deep_artifact(
            self._artifact_with([bad, real]), "bad severity",
            validate=validate_artifact, flagged_specs=da.flagged_specs,
            add_soft_error=da._soft_error)
        kept = [f for f in out["suspicious"] if f["name"] == "bad1"]
        self.assertEqual(len(kept), 1)
        self.assertFalse(kept[0]["soft_error"])
        self.assertEqual(kept[0]["rule"], "npm-obfuscation")

    def test_D1_l1_main_no_longer_wipes_the_suspicious_list(self):
        """Source-level guard: the wholesale wipe must not come back.

        Comments are stripped first - the fix documents the old line verbatim
        so the reason survives, and matching that would make this test assert
        against its own explanation.
        """
        src = open(os.path.join(_REPO, "scanners", "supply_chain_scan", "main.py")).read()
        code = "\n".join(l for l in src.splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn('artifact["suspicious"] = []', code)
        self.assertIn("recover_invalid_deep_artifact", code)

    def test_D1_both_layers_use_the_same_recovery(self):
        """The drift itself was the bug: two copies of one security invariant."""
        for path in (("scanners", "supply_chain_scan", "main.py"),
                     ("recon", "main_recon_modules", "supply_chain_recon.py")):
            src = open(os.path.join(_REPO, *path)).read()
            self.assertIn("recover_invalid_deep_artifact", src,
                          "{} must use the shared recovery".format(path[-1]))


if __name__ == "__main__":
    unittest.main()
