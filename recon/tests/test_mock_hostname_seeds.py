"""REGRESSION: mock IP hostnames must never become crawl seeds.

When an IP has no PTR record, recon/main.py labels it with the IP's dots turned
into dashes ("192.88.99.10" -> "192-88-99-10") so the graph has a name to show.
That label does not resolve and never will.

Feeding it to the crawlers was silently destructive: a non-resolving seed made
hakrawler return ZERO urls overall and collapsed katana's stdout to zero lines,
while both still exited 0 with no stderr - so every URL they really crawled was
thrown away. Bisected against the supply-chain guinea pig on 2026-08-07:

    real seeds only ............. katana 25, hakrawler 48
    + the two mock seeds ........ katana  0, hakrawler  0

crawl depth and crawl-duration were ruled out; the mock seeds alone flip it.
This affected EVERY IP-only target, and downstream it looked exactly like "the
target serves no JavaScript".

Run: python -m unittest recon.tests.test_mock_hostname_seeds
"""

import importlib.util
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Load by path: recon.helpers.__init__ pulls dns/other deps not present here.
_spec = importlib.util.spec_from_file_location(
    "sc_target_helpers",
    os.path.join(_REPO, "recon", "helpers", "target_helpers.py"))
th = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(th)


class TestIsMockIpHostname(unittest.TestCase):
    def test_ipv4_placeholder_is_mock(self):
        self.assertTrue(th._is_mock_ip_hostname("192-88-99-10"))
        self.assertTrue(th._is_mock_ip_hostname("10-0-0-1"))
        self.assertTrue(th._is_mock_ip_hostname("255-255-255-255"))

    def test_real_domains_are_never_mock(self):
        for host in ("example.com", "mail-01.example.com", "api.test.io",
                     "192-88-99-10.example.com", "my-app.internal"):
            self.assertFalse(th._is_mock_ip_hostname(host), host)

    def test_dashed_but_not_an_ip_is_not_mock(self):
        """A hostname of digits and dashes that is NOT a valid IP stays."""
        for host in ("999-999-999-999", "1-2-3", "1-2-3-4-5", "8-8"):
            self.assertFalse(th._is_mock_ip_hostname(host), host)

    def test_empty_and_none_are_safe(self):
        self.assertFalse(th._is_mock_ip_hostname(""))
        self.assertFalse(th._is_mock_ip_hostname(None))


class TestBuildTargetUrlsSkipsMockHostnames(unittest.TestCase):
    """The end-to-end behaviour the crawlers depend on."""

    def _recon(self):
        return {"http_probe": {"by_url": {
            "http://192.88.99.10": {"url": "http://192.88.99.10", "status_code": 200},
            "http://192.88.99.10:8080": {"url": "http://192.88.99.10:8080", "status_code": 200},
        }}}

    def test_regression_mock_hostname_never_becomes_a_seed(self):
        urls = th.build_target_urls({"192-88-99-10"}, set(), self._recon(), False)
        self.assertNotIn("http://192-88-99-10", urls)
        self.assertNotIn("https://192-88-99-10", urls)

    def test_the_real_ip_urls_survive(self):
        """Skipping the placeholder must not cost real coverage - httpx
        already supplies the genuine URLs for that same host."""
        urls = th.build_target_urls({"192-88-99-10"}, set(), self._recon(), False)
        self.assertIn("http://192.88.99.10", urls)
        self.assertIn("http://192.88.99.10:8080", urls)

    def test_ip_only_target_yields_only_resolvable_seeds(self):
        urls = th.build_target_urls({"192-88-99-10"}, set(), self._recon(), False)
        self.assertEqual(sorted(urls),
                         ["http://192.88.99.10", "http://192.88.99.10:8080"])

    def test_real_subdomains_are_still_added(self):
        """The mock filter must not break the legitimate fallback."""
        urls = th.build_target_urls({"new.example.com"}, set(), self._recon(), False)
        self.assertIn("http://new.example.com", urls)
        self.assertIn("https://new.example.com", urls)

    def test_mixed_real_and_mock(self):
        urls = th.build_target_urls({"192-88-99-10", "new.example.com"},
                                    set(), self._recon(), False)
        self.assertIn("http://new.example.com", urls)
        self.assertNotIn("http://192-88-99-10", urls)


if __name__ == "__main__":
    unittest.main()
