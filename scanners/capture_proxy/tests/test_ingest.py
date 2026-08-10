"""
Unit tests for the traffic-ingest pure logic: tenant stamping from the VERIFIED
tag, redaction, int4 clamping, and INSERT column shaping.

Run: python3 -m unittest capture_proxy.tests.test_ingest
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ingest_worker as iw  # noqa: E402

PAYLOAD = {
    "source": "recon", "project_id": "p1", "user_id": "u1",
    "run_id": "run-1", "tool": "katana", "phase": "informational",
}

REC = {
    "method": "get", "scheme": "https", "host": "x.example", "port": 443,
    "path": "/a", "query": "?q=1",
    "reqHeaders": {"authorization": "Bearer secret", "user-agent": "x"},
    "respHeaders": {"set-cookie": "sid=1", "server": "nginx"},
    "statusCode": 200, "respBody": "hi", "respBodySize": 2, "respBodySha": "abc",
    "respBodySize_full": 2, "isTls": True, "hasSetCookie": True,
    "securityHeadersMissing": ["content-security-policy"], "startedAt": "2026-07-19T00:00:00Z",
}


class TestTenantStamping(unittest.TestCase):
    def test_tenant_from_verified_payload(self):
        row = iw.build_row(PAYLOAD, dict(REC, host="attacker-controlled"), redact=False)
        # Tenant + attribution come only from the signed payload.
        self.assertEqual(row["project_id"], "p1")
        self.assertEqual(row["user_id"], "u1")
        self.assertEqual(row["source"], "recon")
        self.assertEqual(row["run_id"], "run-1")
        self.assertEqual(row["tool"], "katana")

    def test_record_cannot_override_tenant(self):
        # Even if the untrusted record carries a userId/projectId, build_row
        # never reads them (they aren't in the column map from `rec`).
        row = iw.build_row(PAYLOAD, dict(REC, user_id="EVIL", project_id="EVIL"), redact=False)
        self.assertEqual(row["user_id"], "u1")
        self.assertEqual(row["project_id"], "p1")

    def test_id_is_generated(self):
        row = iw.build_row(PAYLOAD, REC, redact=False)
        self.assertTrue(row["id"])


class TestRedaction(unittest.TestCase):
    def test_redaction_masks_sensitive_headers(self):
        row = iw.build_row(PAYLOAD, REC, redact=True)
        req = json.loads(row["req_headers"])
        resp = json.loads(row["resp_headers"])
        self.assertTrue(req["authorization"].startswith("[redacted:"))
        self.assertTrue(resp["set-cookie"].startswith("[redacted:"))
        self.assertEqual(req["user-agent"], "x")  # non-sensitive untouched
        self.assertTrue(row["redacted"])
        self.assertIn("authorization", json.loads(row["redacted_fields"]))

    def test_redaction_off_keeps_plaintext(self):
        row = iw.build_row(PAYLOAD, REC, redact=False)
        self.assertEqual(json.loads(row["req_headers"])["authorization"], "Bearer secret")
        self.assertFalse(row["redacted"])
        self.assertIsNone(row["redacted_fields"])

    def test_same_secret_same_hash(self):
        a = iw._mask("Bearer x")
        b = iw._mask("Bearer x")
        self.assertEqual(a, b)
        self.assertNotEqual(a, iw._mask("Bearer y"))


class TestClampAndShape(unittest.TestCase):
    def test_int4_clamp(self):
        row = iw.build_row(PAYLOAD, dict(REC, respBodySize=9999999999999), redact=False)
        self.assertEqual(row["resp_body_size"], iw.INT4_MAX)

    def test_method_uppercased_scheme_lowercased(self):
        row = iw.build_row(PAYLOAD, REC, redact=False)
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["scheme"], "https")
        self.assertTrue(row["is_tls"])

    def test_default_port(self):
        row = iw.build_row(PAYLOAD, dict(REC, port=None, scheme="http"), redact=False)
        self.assertEqual(row["port"], 80)

    def test_insert_sql_shape(self):
        row = iw.build_row(PAYLOAD, REC, redact=False)
        sql, values = iw._insert_sql(row)
        self.assertTrue(sql.startswith("INSERT INTO captured_http_transactions ("))
        self.assertEqual(len(values), len(row))
        # jsonb columns get a ::jsonb cast
        self.assertIn('"req_headers"', sql)
        self.assertIn("%s::jsonb", sql)


if __name__ == "__main__":
    unittest.main()
