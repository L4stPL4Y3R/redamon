"""Scan-scope filtering for the recon graph mixins (issue #172).

An IP-mode scan mints a dashed placeholder hostname per IP
("21.40.250.84" -> "21-40-250-84") so a Subdomain node has a name, but every
scanner targets and reports the IP literal. The mixins used to scope on
recon_data["subdomains"] alone, so 100% of an IP-mode scan's Nuclei findings
and crawled endpoints were dropped as "out of scan scope".

The scope must still reject genuinely foreign hosts (a crawler wandering onto
a CDN), so both directions are asserted here.

Run: python -m unittest tests.test_graph_scan_scope
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402
from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402
from graph_db.mixins.recon.scope import (  # noqa: E402
    build_host_scope, host_in_scope,
)
from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402

IP = "21.40.250.84"
MOCK_NAME = "21-40-250-84"
PROJECT = "b268ce93223747c29623fb5fe"


class FakeResult:
    def single(self):
        return {"linked": 0, "count": 0, "c": 0}

    def __iter__(self):
        return iter([])


class FakeSession:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        return FakeResult()


class FakeDriver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return FakeSession(self.queries)


class Client(VulnMixin, ResourceMixin, HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = FakeDriver(self.queries)


def _nuclei_findings(n, host, port="8080"):
    return [{
        "template_id": f"CVE-2024-{1000 + i}",
        "name": f"Finding {i}",
        "severity": "high",
        "category": "cve",
        "matched_at": f"http://{host}:{port}/",
        "cves": [f"CVE-2024-{1000 + i}"],
        "raw": {"info": {}, "host": host, "port": port},
    } for i in range(n)]


def _ip_mode_recon(by_target):
    """recon_data as recon.main.run_ip_recon builds it for a single PTR-less IP."""
    return {
        "metadata": {
            "ip_mode": True,
            "root_domain": f"ip-targets.{PROJECT}",
            "target_ips": [IP],
            "expanded_ips": [IP],
            "filtered_mode": True,
            "subdomain_filter": [IP, MOCK_NAME],
        },
        "domain": f"ip-targets.{PROJECT}",
        "subdomains": [MOCK_NAME],
        "vuln_scan": {
            "scan_metadata": {},
            "discovered_urls": {},
            "by_target": by_target,
        },
    }


class TestBuildHostScope(unittest.TestCase):
    def test_ip_mode_scope_contains_the_ip_literal(self):
        scope = build_host_scope(_ip_mode_recon({}))
        self.assertIn(IP, scope)
        self.assertIn(MOCK_NAME, scope)

    def test_synthetic_ip_targets_domain_is_not_in_scope(self):
        # The pseudo-domain is a label, never a scannable host.
        self.assertNotIn(f"ip-targets.{PROJECT}", build_host_scope(_ip_mode_recon({})))

    def test_domain_mode_scope_is_the_subdomains(self):
        scope = build_host_scope({"domain": "example.com",
                                  "subdomains": ["api.example.com", "www.example.com"]})
        self.assertEqual(scope, {"api.example.com", "www.example.com"})

    def test_apex_only_scan_falls_back_to_the_domain(self):
        self.assertEqual(build_host_scope({"domain": "example.com", "subdomains": []}),
                         {"example.com"})

    def test_no_targets_at_all_means_no_filter(self):
        self.assertEqual(build_host_scope({}), set())

    def test_host_forms_the_scanners_actually_emit(self):
        scope = {"example.com", "21.40.250.84"}
        for value in ("example.com", "example.com:8443", "https://example.com/foo",
                      "EXAMPLE.COM", "21.40.250.84:80"):
            with self.subTest(value=value):
                self.assertTrue(host_in_scope(value, scope))
        self.assertFalse(host_in_scope("cdn.thirdparty.net", scope))

    def test_ipv6_literal_keeps_its_address(self):
        self.assertTrue(host_in_scope("[fe80::1]:443", {"fe80::1"}))

    def test_empty_scope_is_no_filter(self):
        self.assertTrue(host_in_scope("anything.example", set()))


class TestVulnScanIpMode(unittest.TestCase):
    """Issue #172: 16 Nuclei findings reported, 0 imported."""

    def test_ip_mode_findings_reach_the_graph(self):
        client = Client()
        stats = client.update_graph_from_vuln_scan(
            _ip_mode_recon({IP: {"findings": _nuclei_findings(16, IP)}}), "u1", "p1")
        self.assertEqual(stats["vulnerabilities_created"], 16)
        self.assertEqual(stats.get("skipped_out_of_scope", 0), 0)
        self.assertEqual(stats["errors"], [])

    def test_out_of_scope_host_is_still_dropped(self):
        client = Client()
        recon = _ip_mode_recon({
            IP: {"findings": _nuclei_findings(2, IP)},
            "cdn.thirdparty.net": {"findings": _nuclei_findings(3, "cdn.thirdparty.net")},
        })
        stats = client.update_graph_from_vuln_scan(recon, "u1", "p1")
        self.assertEqual(stats["vulnerabilities_created"], 2)
        self.assertEqual(stats["skipped_out_of_scope"], 1)

    def test_vulnerability_nodes_carry_the_tenant_triple(self):
        client = Client()
        client.update_graph_from_vuln_scan(
            _ip_mode_recon({IP: {"findings": _nuclei_findings(1, IP)}}), "u1", "p1")
        vuln_writes = [(q, kw) for q, kw in client.queries if ":Vulnerability" in q]
        self.assertTrue(vuln_writes)
        for _, kwargs in vuln_writes:
            props = kwargs.get("props", kwargs)
            self.assertEqual(props.get("user_id"), "u1")
            self.assertEqual(props.get("project_id"), "p1")

    def test_domain_mode_is_unchanged(self):
        client = Client()
        recon = {
            "domain": "example.com",
            "subdomains": ["api.example.com"],
            "vuln_scan": {"scan_metadata": {}, "discovered_urls": {}, "by_target": {
                "api.example.com": {"findings": _nuclei_findings(4, "api.example.com", "443")},
                "evil.example.org": {"findings": _nuclei_findings(9, "evil.example.org")},
            }},
        }
        stats = client.update_graph_from_vuln_scan(recon, "u1", "p1")
        self.assertEqual(stats["vulnerabilities_created"], 4)
        self.assertEqual(stats["skipped_out_of_scope"], 1)


class TestResourceEnumIpMode(unittest.TestCase):
    """The same filter drops crawled endpoints in IP mode."""

    def _recon(self):
        recon = _ip_mode_recon({})
        recon.pop("vuln_scan")
        recon["resource_enum"] = {
            "scan_metadata": {},
            "by_base_url": {
                f"http://{IP}:8080": {"endpoints": {
                    "/admin": {"methods": ["GET"], "category": "admin"},
                }},
                "http://cdn.thirdparty.net": {"endpoints": {
                    "/lib.js": {"methods": ["GET"], "category": "static"},
                }},
            },
            "forms": [],
        }
        return recon

    def test_ip_base_urls_produce_endpoints(self):
        client = Client()
        stats = client.update_graph_from_resource_enum(self._recon(), "u1", "p1")
        self.assertEqual(stats["endpoints_created"], 1)
        self.assertEqual(stats["skipped_out_of_scope"], 1)


class TestHttpProbeIpMode(unittest.TestCase):
    """httpx probes the IP; the Subdomain node is the dashed placeholder. The
    'no HTTP response' sweep must not demote a host that was in fact probed."""

    def _recon(self):
        return {
            "metadata": {"ip_mode": True, "ip_to_hostname": {IP: MOCK_NAME}},
            "domain": f"ip-targets.{PROJECT}",
            "subdomains": [MOCK_NAME],
            "http_probe": {
                "scan_metadata": {},
                "by_url": {},
                "by_host": {IP: {"urls": [f"http://{IP}:8080/"], "technologies": [],
                                 "servers": [], "status_codes": [200]}},
            },
        }

    def _no_http_hosts(self, client):
        for query, kwargs in client.queries:
            if "'no_http'" in query:
                return set(kwargs.get("hosts", []))
        return set()

    def test_probed_ip_does_not_demote_its_placeholder_subdomain(self):
        client = Client()
        client.update_graph_from_http_probe(self._recon(), "u1", "p1")
        self.assertEqual(self._no_http_hosts(client), set())

    def test_unprobed_host_is_still_demoted(self):
        client = Client()
        recon = self._recon()
        recon["subdomains"].append("9-9-9-9")
        recon["metadata"]["ip_to_hostname"]["9.9.9.9"] = "9-9-9-9"
        client.update_graph_from_http_probe(recon, "u1", "p1")
        self.assertEqual(self._no_http_hosts(client), {"9-9-9-9"})


if __name__ == "__main__":
    unittest.main()
