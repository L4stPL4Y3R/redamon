"""Unit tests for the supply-chain incident-intel sync (Step 0 writer).

Section: root-agent. Runs inside the redamon-agent image, where
/repo/scanners is on PYTHONPATH.

No network: every test drives `sync_intel` through an injected fetcher.
"""

import json
import os
import shutil
import tempfile
import time
import unittest

from supply_chain_common import intel_sync
from supply_chain_common.security import SanitizeError, sanitize_hostname


def _feed(incidents, revised="2026-08-11", count=None):
    return {
        "revised": revised,
        "count": len(incidents) if count is None else count,
        "incidents": incidents,
    }


def _incident(iid="SCA-0001", **kw):
    base = {
        "id": iid,
        "url": "https://supplychainattack.org/incident/{}".format(iid),
        "title": "Malicious package {}".format(iid),
        "status": "confirmed",
        "severity": "high",
        "summary": "A malicious package was published.",
        "blastRadius": "3,000 downloads",
        "remediation": ["Remove the package", "Rotate credentials"],
        "attackVectors": ["malicious-package"],
        "lastUpdated": "2026-08-01",
        "iocs": {},
    }
    base.update(kw)
    return base


class TestSanitizeHostname(unittest.TestCase):
    """The charset gate that drops the feed's dirty 'domains' entries."""

    def test_accepts_plain_host(self):
        self.assertEqual(sanitize_hostname("Evil.Example.COM"), "evil.example.com")

    def test_accepts_leading_wildcard(self):
        self.assertEqual(sanitize_hostname("*.cf99-9b3.workers.dev"),
                         "*.cf99-9b3.workers.dev")

    def test_rejects_prose_sentence(self):
        # 13 of the feed's 216 "domains" are prose. They must not load.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("attacker used a compromised CDN")

    def test_rejects_slash_joined_entry(self):
        # The documented malformed entry: '/' is not LDH.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("cf103-070/cf102-baf/cf99-9b3.workers.dev")

    def test_rejects_ip_literal(self):
        # Must be routed to the IP validator instead, so the private-range drop
        # applies to it.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("192.0.2.1")

    def test_rejects_non_leading_wildcard(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("evil.*.com")

    def test_rejects_single_label(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("localhost")

    def test_rejects_double_dot(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("evil..com")


class TestNormalize(unittest.TestCase):

    def test_prose_domains_dropped_and_counted(self):
        inc = _incident(iocs={"domains": [
            "evil.example.com",
            "attacker used a compromised CDN",
            "cf103-070/cf102-baf/cf99-9b3.workers.dev",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertIn("evil.example.com", norm["network_iocs"]["domains"])
        # Dropped, and visible as a count rather than silence.
        self.assertEqual(norm["stats"]["domains_dropped"], 2)
        self.assertEqual(norm["stats"]["domains"], 1)

    def test_bare_public_apex_wildcard_dropped(self):
        inc = _incident(iocs={"domains": [
            "*.workers.dev",
            "ai-script.test0ing7.workers.dev",
            "*.cf99-9b3.workers.dev",
        ]})
        norm = intel_sync.normalize([inc])
        suffixes = [w[0] for w in norm["network_iocs"]["wildcards"]]

        # '*.workers.dev' is all of Cloudflare Workers: dropped, counted.
        self.assertNotIn(".workers.dev", suffixes)
        self.assertEqual(norm["stats"]["wildcards_dropped_public_apex"], 1)
        # A specific attacker deployment survives as an exact host.
        self.assertIn("ai-script.test0ing7.workers.dev",
                      norm["network_iocs"]["domains"])
        # A deeper wildcard scopes to one attacker subdomain: kept.
        self.assertIn(".cf99-9b3.workers.dev", suffixes)

    def test_non_global_ips_dropped(self):
        inc = _incident(iocs={"ips": [
            "1.2.3.4",        # globally routable, kept
            "127.0.0.1",      # loopback
            "10.1.2.3",       # private
            "169.254.1.1",    # link-local
            "100.64.0.1",     # CGNAT: NOT covered by is_private
            "224.0.0.1",      # multicast
            "0.0.0.0",        # unspecified
            "203.0.113.10",   # TEST-NET-3 documentation range
            "not-an-ip",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(list(norm["network_iocs"]["ips"]), ["1.2.3.4"])
        self.assertEqual(norm["stats"]["ips"], 1)
        self.assertEqual(norm["stats"]["ips_dropped"], 8)

    def test_cgnat_is_dropped(self):
        """Regression: is_private does NOT cover 100.64.0.0/10.

        Shared carrier-grade NAT space reaching the IOC set would let a poisoned
        feed flag traffic on any CGNAT-addressed network.
        """
        inc = _incident(iocs={"ips": ["100.64.0.1", "100.127.255.254"]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["network_iocs"]["ips"], {})
        self.assertEqual(norm["stats"]["ips_dropped"], 2)

    def test_raw_ip_in_domains_array_routed_to_ip_validator(self):
        inc = _incident(iocs={"domains": ["1.2.3.4", "10.0.0.5"]})
        norm = intel_sync.normalize([inc])
        self.assertIn("1.2.3.4", norm["network_iocs"]["ips"])
        self.assertNotIn("10.0.0.5", norm["network_iocs"]["ips"])
        self.assertEqual(norm["stats"]["ips_dropped"], 1)

    def test_strings_are_capped(self):
        inc = _incident(summary="A" * 99999)
        norm = intel_sync.normalize([inc])
        inc2 = _incident("SCA-0002", iocs={"packages": [{"name": "evil-pkg"}]})
        norm2 = intel_sync.normalize([inc, inc2])
        rec = norm2["packages"]["npm/evil-pkg"]
        self.assertLessEqual(len(rec["summary"]), 4096)
        self.assertTrue(norm["stats"]["incidents"], 1)

    def test_package_key_is_ecosystem_and_name(self):
        inc = _incident(iocs={"packages": [
            {"name": "evil-pkg", "ecosystem": "npm"},
            {"name": "bad-lib", "ecosystem": "PyPI"},
            "bare-string-pkg",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertIn("npm/evil-pkg", norm["packages"])
        self.assertIn("pypi/bad-lib", norm["packages"])
        self.assertIn("npm/bare-string-pkg", norm["packages"])

    def test_hostile_package_name_dropped(self):
        inc = _incident(iocs={"packages": [{"name": "evil;rm -rf /"}]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["packages"], {})
        self.assertEqual(norm["stats"]["packages_dropped"], 1)

    def test_typosquat_pairs_extracted(self):
        inc = _incident(
            attackVectors=["typosquatting"],
            affectedEntities=[{"name": "lodahs", "note": "typosquat of lodash"}],
        )
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["typosquats"]["lodahs"]["original"], "lodash")

    def test_typosquat_pairs_ignored_without_the_vector(self):
        inc = _incident(
            attackVectors=["malicious-package"],
            affectedEntities=[{"name": "lodahs", "note": "typosquat of lodash"}],
        )
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["typosquats"], {})

    def test_incident_without_id_dropped(self):
        norm = intel_sync.normalize([_incident(id=None), "not-a-dict"])
        self.assertEqual(norm["stats"]["incidents"], 0)
        self.assertEqual(norm["stats"]["incidents_dropped"], 2)


class TestEnvelope(unittest.TestCase):

    def test_rejects_non_object(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope([])

    def test_rejects_missing_incidents(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": 3})

    def test_rejects_non_integer_count(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": "3", "incidents": [{}]})

    def test_rejects_bool_count(self):
        # bool is an int subclass; it must not pass as a count.
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": True, "incidents": [{}]})

    def test_rejects_empty_incidents(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": 0, "incidents": []})


class TestSyncIntel(unittest.TestCase):

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="sca-intel-test-")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def _sync(self, payload, **kw):
        def fetcher(url, timeout=None):
            if isinstance(payload, Exception):
                raise payload
            return payload
        return intel_sync.sync_intel(self.out, fetcher=fetcher, **kw)

    def test_writes_all_files_and_manifest(self):
        res = self._sync(_feed([_incident(iocs={"domains": ["evil.example.com"]})]))
        self.assertEqual(res["status"], "synced")
        for name in ("network_iocs.json", "packages.json", "typosquats.json",
                     "manifest.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)

        with open(os.path.join(self.out, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["revised"], "2026-08-11")
        self.assertEqual(manifest["count_ingested"], 1)
        self.assertIn("stats", manifest)

    def test_envelope_rejection_preserves_previous_files(self):
        first = self._sync(_feed([_incident(iocs={"domains": ["evil.example.com"]})]))
        self.assertEqual(first["status"], "synced")
        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            before = fh.read()

        # A malformed feed must never truncate good data to empty.
        res = self._sync({"garbage": True}, force=True)
        self.assertEqual(res["status"], "failed")
        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            self.assertEqual(fh.read(), before)

    def test_fetch_failure_never_raises(self):
        res = self._sync(intel_sync.FeedError("feed unreachable"), force=True)
        self.assertEqual(res["status"], "failed")
        self.assertIn("unreachable", res["detail"])

    def test_unexpected_exception_never_raises(self):
        res = self._sync(RuntimeError("boom"), force=True)
        self.assertEqual(res["status"], "failed")

    def test_ttl_marker_honoured(self):
        self._sync(_feed([_incident()]))
        # Second call within the TTL is a no-op.
        res = self._sync(_feed([_incident()]))
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["detail"], "within TTL")

    def test_ttl_expiry_refetches(self):
        self._sync(_feed([_incident()]))
        old = time.time() - (48 * 3600)
        for name in (intel_sync.MANIFEST_NAME, intel_sync.ATTEMPT_MARKER):
            os.utime(os.path.join(self.out, name), (old, old))
        res = self._sync(_feed([_incident()]))
        self.assertEqual(res["status"], "synced")

    def test_retry_floor_blocks_a_hammering_retry(self):
        """A broken feed must not be re-fetched on every scan spawn.

        The envelope contract leaves the previous files in place on rejection, so
        manifest.json never advances and a naive TTL check would refetch forever.
        """
        res = self._sync({"garbage": True}, force=True)
        self.assertEqual(res["status"], "failed")
        # manifest.json does not exist, so the TTL check alone would refetch.
        self.assertFalse(os.path.exists(os.path.join(self.out,
                                                     intel_sync.MANIFEST_NAME)))
        res2 = self._sync({"garbage": True})
        self.assertEqual(res2["status"], "skipped")
        self.assertEqual(res2["detail"], "within retry floor")

    def test_attempt_marker_written_before_the_fetch(self):
        self._sync(intel_sync.FeedError("down"), force=True)
        self.assertTrue(os.path.exists(
            os.path.join(self.out, intel_sync.ATTEMPT_MARKER)))

    def test_output_is_world_readable(self):
        # Scan containers run non-root + read-only; a 0640 file is an empty DB.
        self._sync(_feed([_incident()]))
        mode = os.stat(os.path.join(self.out, "manifest.json")).st_mode
        self.assertTrue(mode & 0o004, "manifest.json is not world-readable")


class TestFetchGuards(unittest.TestCase):

    def test_refuses_off_allowlist_host(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.fetch_feed("https://evil.example.com/incidents.json")

    def test_refuses_non_http_scheme(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.fetch_feed("file:///etc/passwd")

    def test_redirect_to_off_allowlist_host_is_refused(self):
        import urllib.error

        class _Resp:
            headers = {"Location": "https://evil.example.com/x.json"}

        def opener(req, timeout):
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", _Resp.headers, None)

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("off-allowlist", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
