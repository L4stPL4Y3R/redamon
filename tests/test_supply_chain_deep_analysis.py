"""Unit tests for L2 GuardDog deep analysis (SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED).

Covers the dispatch layer the existing suite never touched: argv construction
(tests/test_supply_chain_runners.py only exercised parse_guarddog), the
flagged-package gate, and every path where GuardDog fails to produce a verdict.

Every regression test is named after the bug it pins so it cannot come back.

No binaries, no network, no Docker: the guarddog module is injected.

Run: python -m pytest tests/test_supply_chain_deep_analysis.py
 or: python -m unittest tests.test_supply_chain_deep_analysis
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

_spec = importlib.util.spec_from_file_location(
    "sc_recon_deep",
    os.path.join(_REPO, "recon", "main_recon_modules", "supply_chain_recon.py"))
scr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scr)

from supply_chain_common import guarddog_runner, analyzer_dispatch
from supply_chain_common.artifact import empty_artifact, add_guarddog_findings
from supply_chain_common.security import validate_artifact, SanitizeError
from graph_db.mixins.supply_chain_mixin import SupplyChainMixin


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

class _FakeGuardDog:
    """Stands in for the ANALYZER DISPATCH, which is where GuardDog now runs.

    This used to fake supply_chain_common.guarddog_runner, because deep_analyze
    called gd_mod.scan_package(..., argv_prefix=...) directly. It no longer
    does: every hostile-byte operation goes through one analyzer job contract,
    so the dispatch is the only seam that controls what comes back.

    Faking the removed seam did not fail loudly - deep_analyze quietly spawned
    REAL docker, every package errored into a `guarddog-not-run` soft error,
    and the suite went from 1.8s to 17s while asserting nothing it claimed to.

    Kept as `_FakeGuardDog` with a `results` map keyed by package name so the
    15 existing call sites read unchanged; only the plumbing moved.
    """

    def __init__(self, results=None, raises=None):
        # results: {name: {"findings": [...], "error": str|None}}
        self.results = results or {}
        self.raises = raises or {}
        self.calls = []
        self.jobs = []
        self._dirs = []

    def new_work_dir(self, prefix="sc-job"):
        d = tempfile.mkdtemp(prefix=prefix + "-")
        self._dirs.append(d)
        return d

    def run_analyzer_job(self, job, work_dir, sc_common, *, image=None,
                         allow_registry_egress=False, timeout=None, **kw):
        spec = (job.get("guarddog_packages") or [{}])[0]
        name = spec.get("name")
        # Record the argv the REAL dispatch would build, so the hardening
        # assertions check the actual builder with the arguments deep_analyze
        # passed rather than a stub's invention.
        argv = analyzer_dispatch.analyzer_docker_argv(
            work_dir, sc_common, image=image,
            allow_registry_egress=allow_registry_egress)
        self.calls.append({"ecosystem": spec.get("ecosystem"), "name": name,
                           "version": spec.get("version"), "timeout": timeout,
                           "argv_prefix": list(argv)})
        self.jobs.append({"job": job, "allow_registry_egress": allow_registry_egress})

        if name in self.raises:
            raise self.raises[name]

        outcome = self.results.get(name, {"findings": [], "error": None})
        art = empty_artifact("purls")
        # deep_analyze consumes artifact["suspicious"]; the fixtures describe
        # GuardDog findings, so map them into that shape here.
        for f in outcome.get("findings") or []:
            art["suspicious"].append({
                "name": f.get("package") or name,
                "version": f.get("version") or spec.get("version"),
                "ecosystem": "npm",
                "purl": "pkg:npm/{}@{}".format(name, spec.get("version")),
                "rule": f.get("rule"), "severity": f.get("severity"),
                "message": f.get("message") or "", "confidence": "suspicious",
                "soft_error": bool(f.get("soft_error")),
            })
        return {"artifact": art, "exit_code": 0, "error": outcome.get("error")}


def _finding(rule="capability-process-spawn", severity="low", soft_error=False):
    return {"package": None, "version": None, "rule": rule,
            "severity": severity, "confidence": "suspicious",
            "message": "m", "soft_error": soft_error}


def _artifact_with(malicious=(), vulnerable=()):
    art = empty_artifact("js-dir")
    for m in malicious:
        art["malicious"].append(m)
    for v in vulnerable:
        art["vulnerable"].append(v)
    return art


def _osv_finding(name, version, eco="npm", purl=None, advisory="MAL-1"):
    return {"name": name, "version": version, "ecosystem": eco,
            "purl": purl if purl is not None else "pkg:npm/{}@{}".format(name, version),
            "advisory_id": advisory, "severity": "high",
            "confidence": "malicious", "title": "t"}


# --------------------------------------------------------------------------
# argv construction  (the layer the old suite never covered)
# --------------------------------------------------------------------------

class TestGuardDogArgv(unittest.TestCase):
    """scan/verify command shape. The old suite only tested parse_guarddog,
    which is why the verify regression below shipped undetected."""

    def _argv(self, fn, *a, **kw):
        seen = {}

        def fake_run_argv(argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            return {"stdout": "{}", "stderr": "", "exit_code": 0,
                    "timed_out": False, "error": None}

        orig = guarddog_runner.run_argv
        guarddog_runner.run_argv = fake_run_argv
        try:
            fn(*a, **kw)
        finally:
            guarddog_runner.run_argv = orig
        return seen["argv"]

    def test_scan_passes_no_sandbox(self):
        # Without --no-sandbox GuardDog 3.x fails to build its own kernel
        # sandbox inside a container and returns a FALSE CLEAN (exit 0,
        # issues: 0, cause hidden in errors["download-package"]).
        argv = self._argv(guarddog_runner.scan_package, "npm", "lodash", "4.17.20")
        self.assertIn("--no-sandbox", argv)
        self.assertEqual(argv[:4], ["guarddog", "npm", "scan", "lodash"])
        self.assertIn("--version", argv)
        self.assertIn("4.17.20", argv)

    def test_regression_verify_lockfile_must_not_pass_no_sandbox(self):
        """REGRESSION: `guarddog <eco> verify` has NO --no-sandbox option
        (only `scan` does). Passing it makes click exit 2 with
        "No such option: --no-sandbox", i.e. every lockfile verification fails.
        Verified against GuardDog 3.0.1."""
        argv = self._argv(guarddog_runner.verify_lockfile, "npm", "/tmp/package-lock.json")
        self.assertNotIn("--no-sandbox", argv)
        self.assertIn("verify", argv)
        self.assertIn("--output-format", argv)

    def test_argv_prefix_replaces_bare_binary(self):
        prefix = guarddog_runner.hardened_docker_argv("myimage:1")
        argv = self._argv(guarddog_runner.scan_package, "npm", "lodash", None,
                          argv_prefix=prefix)
        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        self.assertNotIn("guarddog", argv[:3])
        self.assertEqual(argv[len(prefix):len(prefix) + 3], ["npm", "scan", "lodash"])

    def test_hardened_argv_keeps_the_container_boundary(self):
        # --no-sandbox is only defensible because the CONTAINER is the sandbox.
        argv = guarddog_runner.hardened_docker_argv()
        self.assertIn("--cap-drop", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertTrue(any(a.startswith("/tmp:size=") for a in argv))
        self.assertEqual(argv[-1], guarddog_runner.ANALYZER_IMAGE)

    def test_hardened_argv_keeps_registry_egress(self):
        # guarddog must download the tarball; --network none would break it.
        self.assertNotIn("none", guarddog_runner.hardened_docker_argv())

    def _finalize_with(self, stdout="", stderr="", exit_code=0, error=None):
        return guarddog_runner._finalize(
            {"stdout": stdout, "stderr": stderr, "exit_code": exit_code,
             "timed_out": False, "error": error}, "pkg")

    def test_regression_empty_stdout_is_an_error_not_a_clean_result(self):
        """REGRESSION (found by live verification, not by a mock): run_argv
        deliberately does NOT treat a non-zero exit as an error, because tools
        signal 'findings present' that way. So a docker CLI that ran but failed
        (unreachable DOCKER_HOST, missing image, broker denial, click usage
        error) returned error=None + findings=[] and every caller read it as
        'analysed, nothing found'. Verified live: DOCKER_HOST pointed at a
        nonexistent socket produced scanned=1, failed=0, zero findings."""
        res = self._finalize_with(stdout="", stderr="cannot connect", exit_code=1)
        self.assertIsNotNone(res["error"])
        self.assertIn("no output", res["error"])
        self.assertIn("cannot connect", res["error"])
        self.assertEqual(res["findings"], [])

    def test_whitespace_only_stdout_is_also_an_error(self):
        self.assertIsNotNone(self._finalize_with(stdout="   \n ", exit_code=0)["error"])

    def test_non_json_stdout_is_an_error_carrying_the_output(self):
        res = self._finalize_with(stdout="Error: No such option '--no-sandbox'",
                                  exit_code=2)
        self.assertIn("non-JSON", res["error"])
        self.assertIn("No such option", res["error"])

    def test_valid_json_with_nonzero_exit_is_not_an_error(self):
        # guarddog exits 1 with --exit-non-zero-on-finding; that is a result.
        res = self._finalize_with(
            stdout='{"package":"x","issues":0,"errors":{},"results":{}}',
            exit_code=1)
        self.assertIsNone(res["error"])

    def test_unsupported_ecosystem_never_spawns(self):
        res = guarddog_runner.scan_package("maven", "org.x:y", "1.0")
        self.assertIn("unsupported ecosystem", res["error"])
        self.assertEqual(res["findings"], [])

    def test_hostile_name_raises_before_spawn(self):
        for bad in ["evil;whoami", "../../etc/passwd", "-rf", "a`b`"]:
            with self.assertRaises(SanitizeError):
                guarddog_runner.scan_package("npm", bad)


# --------------------------------------------------------------------------
# flagged_specs: the gate that keeps this off the whole dependency set
# --------------------------------------------------------------------------

class TestFlaggedSpecs(unittest.TestCase):

    def test_only_flagged_packages_are_selected(self):
        art = _artifact_with(malicious=[_osv_finding("axios", "1.14.1")])
        art["packages"].append({"purl": "pkg:npm/lodash", "name": "lodash",
                                "ecosystem": "npm", "source": "sourcemap"})
        specs = scr.flagged_specs(art)
        self.assertEqual([s["name"] for s in specs], ["axios"])

    def test_malicious_ordered_before_vulnerable(self):
        art = _artifact_with(
            malicious=[_osv_finding("mal-pkg", "1.0")],
            vulnerable=[_osv_finding("vuln-pkg", "2.0", advisory="GHSA-x")])
        self.assertEqual([s["name"] for s in scr.flagged_specs(art)],
                         ["mal-pkg", "vuln-pkg"])

    def test_dedups_same_package_across_buckets(self):
        f = _osv_finding("axios", "1.14.1")
        art = _artifact_with(malicious=[f], vulnerable=[f, f])
        self.assertEqual(len(scr.flagged_specs(art)), 1)

    def test_skips_ecosystems_guarddog_cannot_analyse(self):
        art = _artifact_with(vulnerable=[
            _osv_finding("org.apache:x", "1.0", eco="Maven", purl="pkg:maven/org.apache/x@1.0"),
            _osv_finding("lodash", "4.0", eco="npm"),
        ])
        self.assertEqual([s["ecosystem"] for s in scr.flagged_specs(art)], ["npm"])

    def test_osv_ecosystem_maps_to_guarddog_slug(self):
        art = _artifact_with(vulnerable=[
            _osv_finding("requests", "2.0", eco="PyPI", purl="pkg:pypi/requests@2.0")])
        self.assertEqual(scr.flagged_specs(art)[0]["ecosystem"], "pypi")
        self.assertEqual(scr.flagged_specs(art)[0]["osv_ecosystem"], "PyPI")

    def test_boundary_empty_artifact(self):
        self.assertEqual(scr.flagged_specs(empty_artifact()), [])

    def test_boundary_limit_zero_selects_nothing(self):
        art = _artifact_with(malicious=[_osv_finding("a", "1")])
        self.assertEqual(scr.flagged_specs(art, limit=0), [])

    def test_regression_cap_is_not_silent(self):
        """REGRESSION: flagged_specs used to `return` the moment it hit the
        limit, so packages beyond it vanished with no log line - a truncated
        scan that reads as a complete one."""
        art = _artifact_with(malicious=[_osv_finding("p%d" % i, "1.0")
                                        for i in range(5)])
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            specs = scr.flagged_specs(art, limit=2)
        self.assertEqual(len(specs), 2)
        out = buf.getvalue()
        self.assertIn("cap", out.lower())
        self.assertIn("3", out)  # 3 dropped

    def test_finding_without_name_is_skipped(self):
        art = _artifact_with(malicious=[{"name": None, "ecosystem": "npm",
                                         "purl": None, "advisory_id": "MAL-1",
                                         "severity": "high"}])
        self.assertEqual(scr.flagged_specs(art), [])


# --------------------------------------------------------------------------
# deep_analyze: happy path + EVERY failure path
# --------------------------------------------------------------------------

class TestDeepAnalyzeHappyPath(unittest.TestCase):

    def test_findings_become_suspicious_with_versioned_purl(self):
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1",
                                                     purl="pkg:npm/jquery@3.4.1")])
        gd = _FakeGuardDog({"jquery": {"findings": [_finding()], "error": None}})
        art, stats = scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(stats["scanned"], 1)
        self.assertEqual(stats["suspicious"], 1)
        self.assertEqual(len(art["suspicious"]), 1)
        s = art["suspicious"][0]
        self.assertEqual(s["purl"], "pkg:npm/jquery@3.4.1")
        self.assertEqual(s["confidence"], "suspicious")
        self.assertFalse(s["soft_error"])

    def test_result_clears_the_boundary_validator(self):
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
        gd = _FakeGuardDog({"jquery": {
            "findings": [_finding("threat-runtime-obfuscation-general", "medium")],
            "error": None}})
        art, _ = scr.deep_analyze(art, dispatch=gd)
        validate_artifact(art)  # must not raise

    def test_guarddog_is_never_a_malicious_verdict(self):
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
        gd = _FakeGuardDog({"jquery": {"findings": [_finding()], "error": None}})
        art, _ = scr.deep_analyze(art, dispatch=gd)
        self.assertTrue(all(s["confidence"] == "suspicious"
                            for s in art["suspicious"]))
        self.assertEqual(len(art["malicious"]), 1)  # unchanged

    def test_osv_verdicts_are_preserved(self):
        art = _artifact_with(malicious=[_osv_finding("axios", "1.14.1")])
        before = len(art["malicious"])
        gd = _FakeGuardDog({"axios": {"findings": [], "error": None}})
        art, _ = scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(len(art["malicious"]), before)

    def test_no_flagged_packages_means_no_dispatch(self):
        art = empty_artifact("js-dir")
        gd = _FakeGuardDog()
        art, stats = scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(gd.calls, [])
        self.assertEqual(stats["scanned"], 0)

    def test_dispatch_uses_the_hardened_prefix(self):
        art = _artifact_with(malicious=[_osv_finding("axios", "1.14.1")])
        gd = _FakeGuardDog()
        scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(gd.calls[0]["argv_prefix"][:3], ["docker", "run", "--rm"])


class TestDeepAnalyzeFailurePaths(unittest.TestCase):
    """Every path where GuardDog does NOT produce a verdict must be visible in
    the graph, because the writer never reads artifact["errors"]."""

    def test_regression_dispatch_error_is_not_a_silent_clean(self):
        """REGRESSION: when the dispatch failed (no docker socket, image not
        pulled, timeout, non-JSON), findings came back empty and the error went
        ONLY to artifact["errors"] - which the graph writer never reads. The
        package then showed zero behavioural findings and read as
        'deep analysis ran, nothing found'."""
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
        gd = _FakeGuardDog({"jquery": {
            "findings": [],
            "error": "spawn failed: [Errno 2] No such file or directory: 'docker'"}})
        art, stats = scr.deep_analyze(art, dispatch=gd)

        self.assertEqual(stats["scanned"], 0, "a failed dispatch is not a scan")
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(len(art["suspicious"]), 1,
                         "the failure must reach the graph, not just errors[]")
        s = art["suspicious"][0]
        self.assertTrue(s["soft_error"])
        self.assertEqual(s["rule"], "guarddog-not-run")
        self.assertEqual(s["purl"], "pkg:npm/jquery@3.4.1")
        self.assertTrue(any("spawn failed" in e for e in art["errors"]))

    def test_timeout_is_not_a_silent_clean(self):
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
        gd = _FakeGuardDog({"jquery": {"findings": [],
                                       "error": "timeout after 180s"}})
        art, stats = scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(stats["failed"], 1)
        self.assertTrue(art["suspicious"][0]["soft_error"])

    def test_raised_exception_is_isolated_and_recorded(self):
        art = _artifact_with(malicious=[_osv_finding("bad", "1.0"),
                                        _osv_finding("good", "2.0")])
        gd = _FakeGuardDog(results={"good": {"findings": [_finding()], "error": None}},
                           raises={"bad": SanitizeError("hostile name")})
        art, stats = scr.deep_analyze(art, dispatch=gd)
        # The good package still got analysed.
        self.assertEqual(stats["scanned"], 1)
        self.assertEqual(stats["failed"], 1)
        names = {s["name"] for s in art["suspicious"]}
        self.assertEqual(names, {"bad", "good"})
        bad = [s for s in art["suspicious"] if s["name"] == "bad"][0]
        self.assertTrue(bad["soft_error"])

    def test_guarddog_soft_error_finding_is_counted_separately(self):
        # GuardDog itself reporting errors["download-package"] (unpublished
        # malicious release) - a real verdict-less result, not a dispatch failure.
        art = _artifact_with(malicious=[_osv_finding("axios", "1.14.1")])
        gd = _FakeGuardDog({"axios": {
            "findings": [_finding("download-package", "low", soft_error=True)],
            "error": None}})
        art, stats = scr.deep_analyze(art, dispatch=gd)
        self.assertEqual(stats["scanned"], 1)
        self.assertEqual(stats["soft_errors"], 1)
        self.assertEqual(stats["suspicious"], 0)

    def test_error_with_findings_keeps_the_findings(self):
        art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
        gd = _FakeGuardDog({"jquery": {"findings": [_finding()],
                                       "error": "partial stderr noise"}})
        art, stats = scr.deep_analyze(art, dispatch=gd)
        rules = {s["rule"] for s in art["suspicious"]}
        self.assertIn("capability-process-spawn", rules)
        self.assertNotIn("guarddog-not-run", rules,
                         "do not synthesize a soft error when findings exist")

    def test_regression_budget_exhaustion_marks_remaining_packages(self):
        """REGRESSION: worst case was MAX_PACKAGES x TIMEOUT (10 x 180s = 30
        min) of a recon scan blocked on a hanging registry. With a budget, the
        packages that never ran must still be recorded, not dropped."""
        art = _artifact_with(malicious=[_osv_finding("a", "1"),
                                        _osv_finding("b", "2"),
                                        _osv_finding("c", "3")])
        gd = _FakeGuardDog()
        # budget=0 -> exhausted before the first package.
        art, stats = scr.deep_analyze(art, dispatch=gd, budget=0.0000001)
        self.assertEqual(gd.calls, [], "nothing may be dispatched past the budget")
        self.assertEqual(stats["skipped_budget"], 3)
        self.assertEqual(len(art["suspicious"]), 3)
        self.assertTrue(all(s["soft_error"] for s in art["suspicious"]))

    def test_per_package_timeout_shrinks_to_remaining_budget(self):
        art = _artifact_with(malicious=[_osv_finding("a", "1")])
        gd = _FakeGuardDog()
        scr.deep_analyze(art, dispatch=gd, timeout=180, budget=5)
        self.assertLessEqual(gd.calls[0]["timeout"], 5)

    def test_boundary_purl_missing_does_not_fabricate_one(self):
        # OSV finding with no purl: the suspicious entry must simply carry no
        # purl rather than a versionless guess.
        no_purl = _osv_finding("x", "1.0")
        no_purl["purl"] = None
        art = _artifact_with(malicious=[no_purl])
        gd = _FakeGuardDog({"x": {"findings": [_finding()], "error": None}})
        art, _ = scr.deep_analyze(art, dispatch=gd)
        self.assertIsNone(art["suspicious"][0].get("purl"))


# --------------------------------------------------------------------------
# add_guarddog_findings purl propagation
# --------------------------------------------------------------------------

class TestAddGuardDogFindings(unittest.TestCase):

    def test_regression_purl_is_propagated(self):
        """REGRESSION: add_guarddog_findings did not accept a purl, so the graph
        writer fell back to "pkg:<eco>/<name>" and MERGEd a SECOND, versionless
        Package node beside the versioned one the verdict came from."""
        art = empty_artifact()
        add_guarddog_findings(art, [_finding()], ecosystem="npm", name="jquery",
                              version="3.4.1", purl="pkg:npm/jquery@3.4.1")
        self.assertEqual(art["suspicious"][0]["purl"], "pkg:npm/jquery@3.4.1")

    def test_version_falls_back_to_the_caller_value(self):
        art = empty_artifact()
        add_guarddog_findings(art, [_finding()], ecosystem="npm", name="jquery",
                              version="3.4.1")
        self.assertEqual(art["suspicious"][0]["version"], "3.4.1")

    def test_no_purl_key_when_none_given(self):
        art = empty_artifact()
        add_guarddog_findings(art, [_finding()], ecosystem="npm", name="jquery")
        self.assertNotIn("purl", art["suspicious"][0])

    def test_empty_findings_is_a_noop(self):
        art = empty_artifact()
        add_guarddog_findings(art, [], ecosystem="npm", name="x")
        add_guarddog_findings(art, None, ecosystem="npm", name="x")
        self.assertEqual(art["suspicious"], [])


# --------------------------------------------------------------------------
# Graph write: suspicious findings + tenant isolation
# --------------------------------------------------------------------------

class _FakeSession:
    def __init__(self, sink):
        self.sink = sink

    def run(self, query, **params):
        self.sink.append((query, params))
        res = MagicMock()
        res.single.return_value = {"c": 1}
        return res

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeDriver:
    def __init__(self, sink):
        self.sink = sink

    def session(self):
        return _FakeSession(self.sink)


class _Client(SupplyChainMixin):
    def __init__(self):
        self.sink = []
        self.driver = _FakeDriver(self.sink)


class TestSuspiciousGraphWrite(unittest.TestCase):

    def _write(self, artifact, uid="u1", pid="p1"):
        c = _Client()
        stats = c.update_graph_from_supply_chain(artifact, uid, pid)
        return c.sink, stats

    def test_suspicious_finding_is_written_as_verdict_suspicious(self):
        art = empty_artifact()
        art["suspicious"].append({
            "name": "jquery", "version": "3.4.1", "ecosystem": "npm",
            "purl": "pkg:npm/jquery@3.4.1", "rule": "capability-process-spawn",
            "severity": "low", "confidence": "suspicious", "message": "m",
            "soft_error": False})
        sink, stats = self._write(validate_artifact(art))
        self.assertEqual(stats["suspicious_merged"], 1)
        params = [p for _, p in sink if p.get("verdict") == "suspicious"]
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]["source_tool"], "guarddog")
        self.assertEqual(params[0]["purl"], "pkg:npm/jquery@3.4.1")

    def test_regression_no_versionless_package_when_purl_present(self):
        """REGRESSION: the mixin builds pkg:<eco>/<name> when a finding has no
        purl. With the purl propagated, the versioned node must be used."""
        art = empty_artifact()
        art["suspicious"].append({
            "name": "jquery", "version": "3.4.1", "ecosystem": "npm",
            "purl": "pkg:npm/jquery@3.4.1", "rule": "r1", "severity": "low",
            "confidence": "suspicious", "message": "m", "soft_error": False})
        sink, _ = self._write(validate_artifact(art))
        purls = {p.get("purl") for _, p in sink if p.get("purl")}
        self.assertIn("pkg:npm/jquery@3.4.1", purls)
        self.assertNotIn("pkg:npm/jquery", purls)

    def test_every_write_carries_tenant_keys(self):
        art = empty_artifact()
        art["suspicious"].append({
            "name": "jquery", "version": "3.4.1", "ecosystem": "npm",
            "purl": "pkg:npm/jquery@3.4.1", "rule": "r1", "severity": "low",
            "confidence": "suspicious", "message": "m", "soft_error": False})
        sink, _ = self._write(validate_artifact(art), uid="userA", pid="projA")
        self.assertTrue(sink)
        for _, params in sink:
            self.assertEqual(params.get("uid"), "userA")
            self.assertEqual(params.get("pid"), "projA")


# --------------------------------------------------------------------------
# Boundary / hostile input through the DIRTY -> CLEAN gate
# --------------------------------------------------------------------------

class TestHostileGuardDogOutput(unittest.TestCase):
    """GuardDog output quotes attacker-authored package source, so it crosses
    the DIRTY -> CLEAN boundary and must clear validate_artifact."""

    def _suspicious(self, **over):
        base = {"name": "pkg", "version": "1.0", "ecosystem": "npm",
                "purl": "pkg:npm/pkg@1.0", "rule": "capability-process-spawn",
                "severity": "low", "confidence": "suspicious",
                "message": "m", "soft_error": False}
        base.update(over)
        return base

    def test_hostile_rule_name_is_rejected(self):
        art = empty_artifact()
        art["suspicious"].append(self._suspicious(rule="evil;whoami"))
        with self.assertRaises(Exception):
            validate_artifact(art)

    def test_hostile_purl_is_rejected(self):
        art = empty_artifact()
        art["suspicious"].append(self._suspicious(purl="pkg:npm/x`id`"))
        with self.assertRaises(Exception):
            validate_artifact(art)

    def test_free_text_message_survives_but_is_capped(self):
        art = empty_artifact()
        art["suspicious"].append(self._suspicious(
            message="'; DROP TABLE x; -- <script>alert(1)</script> " + "A" * 9000))
        out = validate_artifact(art)
        self.assertLessEqual(len(out["suspicious"][0]["message"]), 4096)

    def test_unicode_message_survives(self):
        art = empty_artifact()
        art["suspicious"].append(self._suspicious(message="é中文\U0001f600"))
        validate_artifact(art)

    def test_unknown_field_is_rejected(self):
        art = empty_artifact()
        art["suspicious"].append(self._suspicious(injected="x"))
        with self.assertRaises(Exception):
            validate_artifact(art)


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------

class TestIdempotency(unittest.TestCase):

    def test_same_input_yields_same_suspicious_set(self):
        def run():
            art = _artifact_with(malicious=[_osv_finding("jquery", "3.4.1")])
            gd = _FakeGuardDog({"jquery": {"findings": [_finding()], "error": None}})
            art, _ = scr.deep_analyze(art, dispatch=gd)
            return art["suspicious"]
        self.assertEqual(run(), run())

    def test_finding_id_is_stable_for_the_same_rule(self):
        from graph_db.mixins.supply_chain_mixin import _finding_id
        a = _finding_id("pkg:npm/jquery@3.4.1", "capability-process-spawn")
        b = _finding_id("pkg:npm/jquery@3.4.1", "capability-process-spawn")
        self.assertEqual(a, b)
        self.assertNotEqual(a, _finding_id("pkg:npm/jquery@3.4.1", "other-rule"))


# --------------------------------------------------------------------------
# run_supply_chain_recon wiring: the opt-in gate and the validation fallback
# --------------------------------------------------------------------------

class TestRunSupplyChainReconWiring(unittest.TestCase):
    """The gate and the ArtifactError fallback are the branches an operator
    actually toggles; unit-cover them with the lazy harvest import stubbed."""

    def setUp(self):
        self._saved = {k: sys.modules.get(k) for k in
                       ("recon", "recon.helpers", "recon.helpers.supply_chain",
                        "recon.helpers.supply_chain.harvest")}
        harvest = MagicMock()
        harvest.harvest_packages.return_value = []
        pkg = MagicMock()
        pkg.harvest = harvest
        sys.modules["recon"] = MagicMock()
        sys.modules["recon.helpers"] = MagicMock()
        sys.modules["recon.helpers.supply_chain"] = pkg
        sys.modules["recon.helpers.supply_chain.harvest"] = harvest
        self._osv = scr._osv_runner
        scr._osv_runner = MagicMock()
        scr._osv_runner.run_osv_scan.return_value = {
            "parsed": {"packages": [], "malicious": [], "vulnerable": []},
            "error": None}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        scr._osv_runner = self._osv

    def _combined(self):
        return {"domain": "t", "http_probe": {"by_url": {}},
                "metadata": {"project_id": "p", "modules_executed": []}}

    def test_gate_off_means_no_deep_analysis(self):
        called = []
        orig = scr.deep_analyze
        scr.deep_analyze = lambda *a, **kw: called.append(1) or (a[0], {})
        try:
            out = scr.run_supply_chain_recon(self._combined(), settings={
                "SUPPLY_CHAIN_RECON_ENABLED": True})
        finally:
            scr.deep_analyze = orig
        self.assertEqual(called, [])
        self.assertIsNone(out["supply_chain_recon"]["summary"]["deep_analysis"])

    def test_gate_on_runs_deep_analysis(self):
        called = []

        def fake(artifact, **kw):
            called.append(1)
            return artifact, {"scanned": 1, "suspicious": 0, "soft_errors": 0,
                              "failed": 0, "skipped_budget": 0}

        orig = scr.deep_analyze
        scr.deep_analyze = fake
        try:
            out = scr.run_supply_chain_recon(self._combined(), settings={
                "SUPPLY_CHAIN_RECON_ENABLED": True,
                "SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED": True})
        finally:
            scr.deep_analyze = orig
        self.assertEqual(called, [1])
        self.assertEqual(out["supply_chain_recon"]["summary"]["deep_analysis"]["scanned"], 1)

    def test_hostile_guarddog_output_is_dropped_not_fatal(self):
        """If GuardDog smuggles a value past the finding schema, the offending
        finding is dropped and the OSV verdicts still ship.

        D1: this used to drop the WHOLE suspicious set, which also erased the
        soft-error markers for packages GuardDog never analysed, making them
        read behaviourally clean. Now only unvalidatable entries are dropped and
        any flagged package left without a finding is re-marked as unanalysed
        (see test_supply_chain_deep_review2)."""
        def fake(artifact, **kw):
            artifact["suspicious"].append({
                "name": "x", "version": "1.0", "ecosystem": "npm",
                "purl": "pkg:npm/x@1.0", "rule": "evil;whoami",
                "severity": "low", "confidence": "suspicious",
                "message": "m", "soft_error": False})
            return artifact, {"scanned": 1, "suspicious": 1, "soft_errors": 0,
                              "failed": 0, "skipped_budget": 0}

        orig = scr.deep_analyze
        scr.deep_analyze = fake
        try:
            out = scr.run_supply_chain_recon(self._combined(), settings={
                "SUPPLY_CHAIN_RECON_ENABLED": True,
                "SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED": True})
        finally:
            scr.deep_analyze = orig
        art = out["supply_chain_recon"]["artifact"]
        # the hostile entry is gone, and the drop is recorded
        self.assertEqual([f for f in art["suspicious"] if not f.get("soft_error")], [])
        self.assertTrue(any("dropped" in e and "deep analysis" in e
                            for e in art["errors"]))

    def test_deep_analysis_crash_does_not_kill_the_module(self):
        def boom(artifact, **kw):
            raise RuntimeError("docker exploded")

        orig = scr.deep_analyze
        scr.deep_analyze = boom
        try:
            out = scr.run_supply_chain_recon(self._combined(), settings={
                "SUPPLY_CHAIN_RECON_ENABLED": True,
                "SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED": True})
        finally:
            scr.deep_analyze = orig
        art = out["supply_chain_recon"]["artifact"]
        self.assertTrue(any("deep analysis failed" in e for e in art["errors"]))
        self.assertIn("packages", art)


def _pkg(name, version, source="retirejs"):
    purl = "pkg:npm/{}@{}".format(name, version) if version else "pkg:npm/{}".format(name)
    return {"purl": purl, "name": name, "version": version,
            "ecosystem": "npm", "source": source}


def _versionless_pkg(name, source="wappalyzer"):
    """What the technology / source-map paths produce: a name, no version.

    Unverdictable on its own - OSV needs a version - which is why a retire.js
    sighting of the same library must win rather than sit beside it.
    """
    return _pkg(name, None, source)


def _art(packages=(), malicious=(), vulnerable=()):
    a = empty_artifact("js-dir")
    a["packages"].extend(packages)
    a["malicious"].extend(malicious)
    a["vulnerable"].extend(vulnerable)
    return a


class TestMergeArtifacts(unittest.TestCase):
    """merge_artifacts folds the retire.js artifact into the OSV one.

    NOTE: this class had no coverage at all in the committed tree - the
    function was reachable from every L2 scan and entirely untested. It is the
    join point between the two harvest halves, so a dedup mistake here shows up
    as duplicate graph nodes rather than as a crash.
    """

    def test_findings_dedup_on_purl_and_advisory(self):
        f = {"purl": "pkg:npm/jquery@3.4.1", "name": "jquery", "version": "3.4.1",
             "ecosystem": "npm", "advisory_id": "GHSA-x", "severity": "high",
             "confidence": "suspicious"}
        out = scr.merge_artifacts(_art(vulnerable=[f]), _art(vulnerable=[dict(f)]))
        self.assertEqual(len(out["vulnerable"]), 1)

    def test_different_advisories_on_one_package_both_kept(self):
        mk = lambda adv: {"purl": "pkg:npm/jquery@3.4.1", "name": "jquery",
                          "version": "3.4.1", "ecosystem": "npm",
                          "advisory_id": adv, "severity": "high",
                          "confidence": "suspicious"}
        out = scr.merge_artifacts(_art(vulnerable=[mk("GHSA-a")]),
                                  _art(vulnerable=[mk("GHSA-b")]))
        self.assertEqual(len(out["vulnerable"]), 2)

    def test_merging_none_is_a_noop(self):
        base = _art(packages=[_pkg("jquery", "3.4.1")])
        self.assertEqual(len(scr.merge_artifacts(base, None)["packages"]), 1)

    def test_errors_are_carried_over(self):
        extra = _art()
        extra["errors"].append("retire: dropped hostile component")
        out = scr.merge_artifacts(_art(), extra)
        self.assertIn("retire: dropped hostile component", out["errors"])

    # -- identity dedup: (ecosystem, name), NOT the purl string -------------
    #
    # REGRESSION. harvest_packages has always keyed packages by NAME with the
    # versioned sighting winning; merge_artifacts keyed on the PURL STRING. So
    # `pkg:npm/lodash` (wappalyzer, versionless) and `pkg:npm/lodash@4.17.4`
    # (retire.js) were two different keys and BOTH survived - one library, two
    # Package nodes, one of them permanently unverdictable because OSV needs a
    # version. retire.js is the only source that reads a version out of the
    # served bytes, so the package it upgrades is routinely one the other
    # sources already reported WITHOUT one; this is the common case, not a
    # corner one.

    def test_versioned_retire_sighting_replaces_the_versionless_one(self):
        out = scr.merge_artifacts(_art(packages=[_versionless_pkg("lodash")]),
                                  _art(packages=[_pkg("lodash", "4.17.4")]))
        self.assertEqual(len(out["packages"]), 1)
        self.assertEqual(out["packages"][0]["version"], "4.17.4")
        self.assertEqual(out["packages"][0]["purl"], "pkg:npm/lodash@4.17.4")

    def test_versionless_extra_never_displaces_a_known_version(self):
        out = scr.merge_artifacts(_art(packages=[_pkg("lodash", "4.17.4")]),
                                  _art(packages=[_versionless_pkg("lodash")]))
        self.assertEqual(len(out["packages"]), 1)
        self.assertEqual(out["packages"][0]["version"], "4.17.4")

    def test_same_name_in_a_different_ecosystem_is_a_different_package(self):
        pypi = {"purl": "pkg:pypi/lodash@1.0.0", "name": "lodash",
                "version": "1.0.0", "ecosystem": "pypi", "source": "retirejs"}
        out = scr.merge_artifacts(_art(packages=[_versionless_pkg("lodash")]),
                                  _art(packages=[pypi]))
        self.assertEqual(len(out["packages"]), 2)

    def test_two_concrete_versions_keep_first_seen(self):
        """The harvest side already deduped its own sources; do not
        second-guess it, and never end up with both."""
        out = scr.merge_artifacts(_art(packages=[_pkg("lodash", "4.17.4")]),
                                  _art(packages=[_pkg("lodash", "4.17.20")]))
        self.assertEqual(len(out["packages"]), 1)
        self.assertEqual(out["packages"][0]["version"], "4.17.4")

    def test_replacement_happens_in_place_not_by_appending(self):
        """Position matters: an append-then-drop would reorder the list and
        silently change which package a caller reading packages[0] sees."""
        base = _art(packages=[_versionless_pkg("lodash"), _pkg("jquery", "3.4.1")])
        out = scr.merge_artifacts(base, _art(packages=[_pkg("lodash", "4.17.4")]))
        self.assertEqual([p["name"] for p in out["packages"]], ["lodash", "jquery"])

    def test_upgraded_package_still_clears_the_boundary_validator(self):
        out = scr.merge_artifacts(_art(packages=[_versionless_pkg("lodash")]),
                                  _art(packages=[_pkg("lodash", "4.17.4")]))
        validate_artifact(out)


if __name__ == "__main__":
    unittest.main()
