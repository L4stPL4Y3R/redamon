"""Phase 0.4 unit tests for supply_chain_common parsers + sanitizer.

Pure-function tests against committed fixtures (no binaries, no network). The
integration tests that exercise the real osv-scanner/guarddog/retire binaries
offline live in tests/test_supply_chain_integration.py and are skipped when the
tools are not installed.

Run: python -m pytest tests/test_supply_chain_runners.py
 or: python -m unittest tests.test_supply_chain_runners
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from supply_chain_common import osv_runner, guarddog_runner, retire_runner
from supply_chain_common.security import sanitize_name, sanitize_version, SanitizeError
from supply_chain_common.purl import build_purl, normalize_name

_FIX = os.path.join(_REPO, "tests", "fixtures", "supply_chain")


def load(name):
    with open(os.path.join(_FIX, name)) as fh:
        return json.load(fh)


class TestSanitizeName(unittest.TestCase):
    def test_accepts_legit_names(self):
        for good in ["lodash", "@angular/core", "flask-login", "requests",
                     "github.com/pkg/errors", "org.apache.commons:commons-lang3",
                     "left_pad", "some.pkg+build"]:
            self.assertEqual(sanitize_name(good), good)

    def test_rejects_shell_metacharacters(self):
        for bad in ["; id", "$(whoami)", "a`b`", "a|b", "a&b", "a>b", "a b",
                    "a\nb", "a$b"]:
            with self.assertRaises(SanitizeError):
                sanitize_name(bad)

    def test_rejects_path_traversal(self):
        for bad in ["../../etc/passwd", "@scope/../x", "a/../../b"]:
            with self.assertRaises(SanitizeError):
                sanitize_name(bad)

    def test_rejects_leading_dash_and_slash(self):
        with self.assertRaises(SanitizeError):
            sanitize_name("-rf")
        with self.assertRaises(SanitizeError):
            sanitize_name("/etc/passwd")

    def test_rejects_empty_and_oversized(self):
        with self.assertRaises(SanitizeError):
            sanitize_name("")
        with self.assertRaises(SanitizeError):
            sanitize_name("a" * 500)

    def test_rejects_non_string(self):
        with self.assertRaises(SanitizeError):
            sanitize_name(None)

    def test_version_validation(self):
        self.assertEqual(sanitize_version("1.2.3"), "1.2.3")
        self.assertEqual(sanitize_version("2.0.0-rc.1+build5"), "2.0.0-rc.1+build5")
        self.assertIsNone(sanitize_version(None))
        with self.assertRaises(SanitizeError):
            sanitize_version("1.0; rm -rf /")


class TestPurl(unittest.TestCase):
    def test_basic_npm(self):
        self.assertEqual(build_purl("npm", "lodash", "4.17.21"),
                         "pkg:npm/lodash@4.17.21")

    def test_scoped_npm_encodes_at(self):
        self.assertEqual(build_purl("npm", "@angular/core", "12.0.0"),
                         "pkg:npm/%40angular/core@12.0.0")

    def test_pypi_normalization(self):
        # PEP 503: Flask_Login and flask-login are the same package.
        self.assertEqual(normalize_name("PyPI", "Flask_Login"), "flask-login")
        self.assertEqual(build_purl("PyPI", "Flask_Login", "0.6.3"),
                         "pkg:pypi/flask-login@0.6.3")

    def test_no_version(self):
        self.assertEqual(build_purl("npm", "jquery"), "pkg:npm/jquery")

    def test_hostile_name_raises(self):
        with self.assertRaises(SanitizeError):
            build_purl("npm", "$(id)", "1.0.0")


class TestOsvParser(unittest.TestCase):
    def test_malicious_split(self):
        parsed = osv_runner.parse_osv_json(load("osv_mal_npm.json"))
        self.assertEqual(len(parsed["malicious"]), 1)
        self.assertEqual(parsed["malicious"][0]["advisory_id"], "MAL-2025-25502")
        self.assertEqual(parsed["malicious"][0]["purl"], "pkg:npm/lodahs@1.0.0")
        self.assertEqual(len(parsed["vulnerable"]), 0)
        self.assertEqual(len(parsed["packages"]), 1)

    def test_cve_goes_to_vulnerable_not_malicious(self):
        parsed = osv_runner.parse_osv_json(load("osv_cve_npm.json"))
        self.assertEqual(len(parsed["malicious"]), 0)
        self.assertEqual(len(parsed["vulnerable"]), 2)
        ids = {v["advisory_id"] for v in parsed["vulnerable"]}
        self.assertIn("CVE-2021-23337", ids)
        self.assertIn("GHSA-p6mc-m468-83gg", ids)

    def test_empty_and_none_tolerance(self):
        self.assertEqual(osv_runner.parse_osv_json(load("osv_empty.json"))["packages"], [])
        empty = osv_runner.parse_osv_json(None)
        self.assertEqual(empty["malicious"], [])
        self.assertEqual(osv_runner.parse_osv_json({"results": None})["packages"], [])

    def test_run_unknown_mode(self):
        res = osv_runner.run_osv_scan("/x", mode="bogus")
        self.assertIsNotNone(res["error"])


class TestGuarddogParser(unittest.TestCase):
    def test_scan_issues_both_shapes(self):
        findings = guarddog_runner.parse_guarddog(load("guarddog_scan_issues.json"))
        rules = {f["rule"] for f in findings}
        # typosquatting (string/metadata) + install-script + obfuscation (lists)
        self.assertIn("typosquatting", rules)
        self.assertIn("npm-install-script", rules)
        self.assertIn("npm-obfuscation", rules)
        # null-valued rules (empty_information, release_zero) did not fire
        self.assertNotIn("empty_information", rules)
        # confidence is always suspicious, never malicious
        self.assertTrue(all(f["confidence"] == "suspicious" for f in findings))

    def test_severity_mapping(self):
        findings = guarddog_runner.parse_guarddog(load("guarddog_scan_issues.json"))
        by_rule = {f["rule"]: f["severity"] for f in findings}
        self.assertEqual(by_rule["npm-install-script"], "high")
        self.assertEqual(by_rule["typosquatting"], "medium")
        self.assertEqual(by_rule["npm-obfuscation"], "medium")

    def test_clean_scan_no_findings(self):
        self.assertEqual(guarddog_runner.parse_guarddog(load("guarddog_scan_clean.json")), [])

    def test_verify_list_shape(self):
        findings = guarddog_runner.parse_guarddog(load("guarddog_verify_list.json"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["package"], "sketchy-dep")
        self.assertEqual(findings[0]["rule"], "npm-exec-base64")
        self.assertEqual(findings[0]["severity"], "high")

    def test_download_error_is_soft_error_not_clean(self):
        findings = guarddog_runner.parse_guarddog(load("guarddog_download_error.json"))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["soft_error"])
        self.assertEqual(findings[0]["rule"], "download-package")

    def test_none_tolerance(self):
        self.assertEqual(guarddog_runner.parse_guarddog(None), [])


class TestRetireParser(unittest.TestCase):
    def test_components_and_vulns(self):
        parsed = retire_runner.parse_retire_json(load("retire_json.json"))
        comps = {c["name"]: c for c in parsed["components"]}
        self.assertIn("jquery", comps)
        self.assertIn("lodash", comps)
        self.assertEqual(comps["jquery"]["version"], "1.12.4")
        self.assertEqual(comps["lodash"]["detection"], "hash")
        # jquery has a CVE, lodash does not, but both are harvested
        self.assertEqual(len(parsed["vulns"]), 1)
        self.assertIn("CVE-2015-9251", parsed["vulns"][0]["cves"])

    def test_to_purls(self):
        parsed = retire_runner.parse_retire_json(load("retire_json.json"))
        purls = set(retire_runner.to_purls(parsed["components"]))
        self.assertIn("pkg:npm/jquery@1.12.4", purls)
        self.assertIn("pkg:npm/lodash@4.17.21", purls)

    def test_none_tolerance(self):
        parsed = retire_runner.parse_retire_json(None)
        self.assertEqual(parsed["components"], [])
        self.assertEqual(parsed["vulns"], [])


class TestRetireErrorSurfacing(unittest.TestCase):
    """A retire.js run that could not load its signature repository writes a
    WELL-FORMED report: `data` is empty and the reason is only in `errors`.

    That is the false-clean shape - valid JSON, zero components, no parse
    failure - and it is not hypothetical: retire.js downloads
    jsrepository-v5.json from raw.githubusercontent.com on every run, and the
    analyzer's /tmp is a tmpfs so nothing caches between runs. One DNS blip and
    every JS library on the target reads as clean.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="retire-err-")
        self.out = os.path.join(self.dir, "out.json")
        self._orig = retire_runner.run_argv
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.addCleanup(setattr, retire_runner, "run_argv", self._orig)

    def _stub(self, payload, exit_code=0):
        def fake(argv, timeout=None):
            with open(self.out, "w") as fh:
                json.dump(payload, fh)
            return {"exit_code": exit_code, "stdout": "", "stderr": "", "error": None}
        retire_runner.run_argv = fake

    def test_reported_errors_become_the_runner_error(self):
        self._stub({"version": "5.4.3", "data": [], "errors": [
            "Error downloading: https://raw.githubusercontent.com/RetireJS/"
            "retire.js/master/repository/jsrepository-v5.json: "
            "Error: getaddrinfo EAI_AGAIN raw.githubusercontent.com"]})
        res = retire_runner.scan_js_dir(self.dir, out_path=self.out)
        self.assertIsNotNone(res["error"])
        self.assertIn("jsrepository", res["error"])
        self.assertEqual(res["components"], [])

    def test_exit_zero_does_not_launder_a_reported_error(self):
        """--exitwith already reassigns the findings exit code, so tying
        'did the scan work' to it is the coupling that produced the GuardDog
        false-clean. Exit 0 plus a reported error is still an error."""
        self._stub({"data": [], "errors": ["repository load failed"]}, exit_code=0)
        res = retire_runner.scan_js_dir(self.dir, out_path=self.out)
        self.assertIn("repository load failed", res["error"])

    def test_empty_errors_list_is_a_genuine_clean_result(self):
        """retire.js reports `data: []` for a CLEAN component too - its JSON
        reporter emits only components carrying vulnerabilities. Empty errors
        is the only thing separating that from a failed run."""
        self._stub({"version": "5.4.3", "data": [], "errors": []})
        res = retire_runner.scan_js_dir(self.dir, out_path=self.out)
        self.assertIsNone(res["error"])
        self.assertEqual(res["components"], [])

    def test_missing_errors_key_is_tolerated(self):
        self._stub({"version": "5.4.3", "data": []})
        self.assertIsNone(retire_runner.scan_js_dir(self.dir, out_path=self.out)["error"])

    def test_findings_still_parse_when_errors_are_present(self):
        """A partial run must not lose the components it did identify."""
        self._stub({"data": [{"file": "/work/js/a.js", "results": [
            {"component": "handlebars", "version": "4.0.5",
             "detection": "filecontent", "vulnerabilities": []}]}],
            "errors": ["some non-fatal complaint"]})
        res = retire_runner.scan_js_dir(self.dir, out_path=self.out)
        self.assertIn("some non-fatal complaint", res["error"])
        self.assertEqual([c["name"] for c in res["components"]], ["handlebars"])

    def test_a_spawn_error_is_not_overwritten_by_the_reported_one(self):
        def fake(argv, timeout=None):
            with open(self.out, "w") as fh:
                json.dump({"data": [], "errors": ["secondary"]}, fh)
            return {"exit_code": 127, "stdout": "", "stderr": "",
                    "error": "binary not found"}
        retire_runner.run_argv = fake
        self.assertEqual(
            retire_runner.scan_js_dir(self.dir, out_path=self.out)["error"],
            "binary not found")


if __name__ == "__main__":
    unittest.main()
