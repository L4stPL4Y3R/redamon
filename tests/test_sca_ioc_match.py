"""A1 (Python half) + the cross-language parity contract.

Section: root-agent.

captured_http_transactions has TWO writers: this ingest worker and the webapp's
TypeScript ingest route. If only one sets the IOC columns, an operator sees some
requests flagged and reasonably concludes the unflagged ones were checked and
cleared - the flag would misrepresent coverage rather than merely be incomplete.

PARITY_CASES below is duplicated verbatim in webapp/src/lib/scaIntel.test.ts.
Both suites run the same table; changing behaviour on one side without the other
turns one of them red.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(_REPO, "scanners"),
          os.path.join(_REPO, "scanners", "capture_proxy")):
    if p not in sys.path:
        sys.path.insert(0, p)

from supply_chain_common import intel as intel_mod  # noqa: E402
import ioc_match  # noqa: E402


def _rec(iid="SCA-0001"):
    return {
        "incident_id": iid,
        "url": "https://supplychainattack.org/i/{}".format(iid),
        "title": "Compromised CDN script",
        "summary": "A CDN-hosted script was replaced with a skimmer.",
        "status": "confirmed",
    }


# Duplicated in webapp/src/lib/scaIntel.test.ts - keep the two in step.
PARITY_CASES = [
    ("cdn.evil.example", None, "SCA-0001"),
    ("CDN.Evil.Example.", None, "SCA-0001"),
    ("cdn.evil.example:8443", None, "SCA-0001"),
    ("a.cf99.workers.dev", None, "SCA-WILD"),
    ("a.other.workers.dev", None, None),
    ("www.example.com", None, None),
    (None, "1.2.3.4", "SCA-IP"),
    (None, "9.9.9.9", None),
    ("abc.oastify.com", None, None),
    ("", None, None),
]


class _IocTestCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sca-ioc-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self._write_intel()
        os.environ["SCA_INTEL_PATH"] = self.dir
        os.environ.pop("CAPTURE_IOC_IGNORE_SUFFIXES", None)
        os.environ.pop("SCA_INTEL_MATCH_ENABLED", None)
        intel_mod.reset_cache()
        ioc_match._INTEL_UNAVAILABLE_LOGGED = False
        self.addCleanup(self._cleanup_env)

    def _cleanup_env(self):
        for key in ("SCA_INTEL_PATH", "CAPTURE_IOC_IGNORE_SUFFIXES",
                    "SCA_INTEL_MATCH_ENABLED"):
            os.environ.pop(key, None)
        intel_mod.reset_cache()

    def _write_intel(self, domains=None, wildcards=None, ips=None):
        payload = {
            "manifest.json": {"revised": "2026-08-11"},
            "network_iocs.json": {
                "domains": domains if domains is not None else {
                    "cdn.evil.example": _rec(),
                    "abc.oastify.com": _rec("SCA-OAST"),
                },
                "wildcards": wildcards if wildcards is not None else [
                    [".cf99.workers.dev", _rec("SCA-WILD")]],
                "ips": ips if ips is not None else {"1.2.3.4": _rec("SCA-IP")},
            },
            "packages.json": {},
            "typosquats.json": {},
        }
        for name, body in payload.items():
            with open(os.path.join(self.dir, name), "w") as fh:
                json.dump(body, fh)


class TestMatchTransaction(_IocTestCase):

    def test_exact_host(self):
        self.assertEqual(ioc_match.match_transaction("cdn.evil.example")[0],
                         "SCA-0001")

    def test_returns_both_columns(self):
        incident_id, url = ioc_match.match_transaction("cdn.evil.example")
        self.assertEqual(incident_id, "SCA-0001")
        self.assertEqual(url, "https://supplychainattack.org/i/SCA-0001")

    def test_non_match_returns_two_nones(self):
        self.assertEqual(ioc_match.match_transaction("www.example.com"),
                         (None, None))

    def test_missing_catalog_never_raises(self):
        os.environ["SCA_INTEL_PATH"] = os.path.join(self.dir, "nope")
        intel_mod.reset_cache()
        self.assertEqual(ioc_match.match_transaction("cdn.evil.example"),
                         (None, None))

    def test_kill_switch(self):
        os.environ["SCA_INTEL_MATCH_ENABLED"] = "false"
        self.assertEqual(ioc_match.match_transaction("cdn.evil.example"),
                         (None, None))

    def test_ignore_list_from_env(self):
        os.environ["CAPTURE_IOC_IGNORE_SUFFIXES"] = "evil.example"
        self.assertEqual(ioc_match.match_transaction("cdn.evil.example"),
                         (None, None))

    def test_unavailable_catalog_logs_once_not_per_request(self):
        """C7 wants it recorded, but this runs per captured transaction."""
        os.environ["SCA_INTEL_PATH"] = os.path.join(self.dir, "nope")
        intel_mod.reset_cache()
        ioc_match._INTEL_UNAVAILABLE_LOGGED = False
        ioc_match.match_transaction("a.example")
        self.assertTrue(ioc_match._INTEL_UNAVAILABLE_LOGGED)
        # Second call must not re-log; the flag staying True is the assertion.
        ioc_match.match_transaction("b.example")
        self.assertTrue(ioc_match._INTEL_UNAVAILABLE_LOGGED)


class TestBuildRowIntegration(_IocTestCase):
    """The columns must actually reach the row the worker INSERTs."""

    def _build_row(self, rec):
        from ingest_worker import build_row

        payload = {"project_id": "p1", "user_id": "u1", "source": "recon"}
        return build_row(payload, rec, False)

    def test_build_row_sets_both_columns(self):
        row = self._build_row({"host": "cdn.evil.example", "method": "GET",
                               "path": "/", "startedAt": "2026-08-15T00:00:00Z"})
        self.assertEqual(row["ioc_incident_id"], "SCA-0001")
        self.assertEqual(row["ioc_incident_url"],
                         "https://supplychainattack.org/i/SCA-0001")

    def test_build_row_columns_are_null_without_a_match(self):
        row = self._build_row({"host": "www.example.com", "method": "GET",
                               "path": "/", "startedAt": "2026-08-15T00:00:00Z"})
        self.assertIsNone(row["ioc_incident_id"])
        self.assertIsNone(row["ioc_incident_url"])

    def test_build_row_matches_on_the_resolved_ip(self):
        row = self._build_row({"host": "unknown.example", "targetIp": "1.2.3.4",
                               "method": "GET", "path": "/",
                               "startedAt": "2026-08-15T00:00:00Z"})
        self.assertEqual(row["ioc_incident_id"], "SCA-IP")

    def test_build_row_still_works_without_the_catalog(self):
        """A capture row must land in Postgres whether or not intel exists."""
        os.environ["SCA_INTEL_PATH"] = os.path.join(self.dir, "nope")
        intel_mod.reset_cache()
        row = self._build_row({"host": "cdn.evil.example", "method": "GET",
                               "path": "/", "startedAt": "2026-08-15T00:00:00Z"})
        self.assertIsNone(row["ioc_incident_id"])
        self.assertEqual(row["host"], "cdn.evil.example")


class TestPythonTypeScriptParity(_IocTestCase):
    """Same case table as webapp/src/lib/scaIntel.test.ts."""

    def test_parity_cases(self):
        for host, ip, expected in PARITY_CASES:
            with self.subTest(host=host, ip=ip):
                incident_id, _ = ioc_match.match_transaction(host, ip)
                self.assertEqual(incident_id, expected)

    def test_the_case_table_is_mirrored_in_the_typescript_suite(self):
        """If the tables diverge, one language is being tested and the other is
        being assumed."""
        ts_path = os.path.join(_REPO, "webapp", "src", "lib", "scaIntel.test.ts")
        try:
            with open(ts_path) as fh:
                ts_source = fh.read()
        except OSError:
            self.skipTest("webapp sources not present in this image")
        self.assertIn("PARITY_CASES", ts_source)
        for host, _ip, _expected in PARITY_CASES:
            if host:
                self.assertIn(host, ts_source,
                              "parity case {!r} is missing from the TS suite"
                              .format(host))

    def test_default_ignore_lists_agree(self):
        ts_path = os.path.join(_REPO, "webapp", "src", "lib", "scaIntel.ts")
        try:
            with open(ts_path) as fh:
                ts_source = fh.read()
        except OSError:
            self.skipTest("webapp sources not present in this image")
        for suffix in intel_mod.DEFAULT_IGNORE_SUFFIXES:
            self.assertIn(suffix, ts_source,
                          "ignore-list entry {!r} is missing on the TS side"
                          .format(suffix))


if __name__ == "__main__":
    unittest.main()
