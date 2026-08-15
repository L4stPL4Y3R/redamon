"""A2: malicious-host correlation over hosts the scan already observed.

Section: recon.

The rules that matter here:
  - inputs come from the graph/pipeline, never from a new fetch
  - the operator's OAST providers are suppressed, or a pentester flags their own
    Burp Collaborator callbacks on every engagement
  - a missing catalog reports available=False rather than "nothing matched"
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (_REPO, os.path.join(_REPO, "scanners")):
    if p not in sys.path:
        sys.path.insert(0, p)

from recon.main_recon_modules.sca_intel_correlate import (  # noqa: E402
    collect_candidate_hosts, correlate_hosts,
)


class _Intel:
    def __init__(self, domains=None, wildcards=None, ips=None, available=True):
        self.domains = domains or {}
        self.wildcards = wildcards or []
        self.ips = ips or {}
        self.packages = {}
        self.typosquats = {}
        self.revised = "2026-08-11"
        self.available = available


def _rec(iid="SCA-0001"):
    return {"incident_id": iid, "url": "https://supplychainattack.org/i/" + iid,
            "title": "Compromised CDN script", "status": "confirmed",
            "summary": "A CDN-hosted script was replaced with a skimmer.",
            "blast_radius": "3,000 sites", "remediation": ["Remove the script"],
            "attack_vectors": ["compromised-cdn"], "last_updated": "2026-08-01"}


def _combined(js_hosts=()):
    return {"js_recon": {"external_domains": [
        {"domain": h, "urls": ["https://{}/app.js".format(h)]} for h in js_hosts]}}


class TestCollectCandidateHosts(unittest.TestCase):

    def test_base_url_hosts_are_candidates(self):
        hosts = collect_candidate_hosts({}, ["https://target.example.com",
                                             "http://api.example.com:8080"])
        self.assertIn("target.example.com", hosts)
        self.assertIn("api.example.com", hosts)

    def test_js_hosts_are_candidates(self):
        hosts = collect_candidate_hosts(_combined(["cdn.evil.example"]), [])
        self.assertIn("cdn.evil.example", hosts)
        self.assertEqual(hosts["cdn.evil.example"],
                         "https://cdn.evil.example/app.js")

    def test_no_input_yields_no_candidates(self):
        self.assertEqual(collect_candidate_hosts({}, []), {})

    def test_malformed_base_url_is_skipped_not_fatal(self):
        hosts = collect_candidate_hosts({}, ["not a url", "https://ok.example"])
        self.assertIn("ok.example", hosts)


class TestCorrelateHosts(unittest.TestCase):

    def test_matching_js_host_produces_a_correlation(self):
        intel = _Intel(domains={"cdn.evil.example": _rec()})
        out = correlate_hosts(_combined(["cdn.evil.example"]),
                              ["https://target.example.com"], intel=intel,
                              ignore_suffixes=[])
        self.assertTrue(out["available"])
        self.assertEqual(len(out["correlations"]), 1)
        hit = out["correlations"][0]
        self.assertEqual(hit["matched_host"], "cdn.evil.example")
        self.assertEqual(hit["evidence"], "graph-host-match")
        # Anchors to the TARGET's BaseURL, not to the attacker host.
        self.assertEqual(hit["base_url"], "https://target.example.com")

    def test_wildcard_suffix_matches(self):
        intel = _Intel(wildcards=[(".cf99.workers.dev", _rec("SCA-WILD"))])
        out = correlate_hosts(_combined(["a.cf99.workers.dev"]),
                              ["https://target.example.com"], intel=intel,
                              ignore_suffixes=[])
        self.assertEqual(out["correlations"][0]["incident"]["incident_id"],
                         "SCA-WILD")

    def test_no_match_yields_nothing_but_still_reports_available(self):
        intel = _Intel(domains={"other.example": _rec()})
        out = correlate_hosts(_combined(["cdn.clean.example"]),
                              ["https://target.example.com"], intel=intel,
                              ignore_suffixes=[])
        self.assertEqual(out["correlations"], [])
        self.assertTrue(out["available"])
        self.assertEqual(out["checked"], 2)

    def test_unavailable_catalog_is_distinguishable_from_no_match(self):
        """C7: 'the pass did not run' must not look like 'nothing found'."""
        out = correlate_hosts(_combined(["cdn.evil.example"]),
                              ["https://target.example.com"],
                              intel=_Intel(available=False))
        self.assertEqual(out["correlations"], [])
        self.assertFalse(out["available"])

    def test_oast_providers_are_suppressed_by_the_ignore_list(self):
        intel = _Intel(domains={"abc.oastify.com": _rec("SCA-OAST")})
        out = correlate_hosts(_combined(["abc.oastify.com"]),
                              ["https://target.example.com"], intel=intel,
                              ignore_suffixes=["oastify.com"])
        self.assertEqual(out["correlations"], [])

    def test_ignore_list_read_from_env_when_not_passed(self):
        intel = _Intel(domains={"abc.oastify.com": _rec("SCA-OAST")})
        os.environ["CAPTURE_IOC_IGNORE_SUFFIXES"] = "oastify.com"
        try:
            out = correlate_hosts(_combined(["abc.oastify.com"]),
                                  ["https://target.example.com"], intel=intel)
        finally:
            os.environ.pop("CAPTURE_IOC_IGNORE_SUFFIXES", None)
        self.assertEqual(out["correlations"], [])

    def test_a_matching_base_url_anchors_to_itself(self):
        intel = _Intel(domains={"target.example.com": _rec()})
        out = correlate_hosts({}, ["https://other.example.com",
                                   "https://target.example.com"],
                              intel=intel, ignore_suffixes=[])
        self.assertEqual(out["correlations"][0]["base_url"],
                         "https://target.example.com")

    def test_no_network_call_is_made(self):
        """The module must never fetch: harvest is network-free by contract."""
        import recon.main_recon_modules.sca_intel_correlate as mod

        source = open(mod.__file__).read()
        for banned in ("requests.get", "urlopen", "httpx.", "socket."):
            self.assertNotIn(banned, source,
                             "correlation must not make network calls")


if __name__ == "__main__":
    unittest.main()
