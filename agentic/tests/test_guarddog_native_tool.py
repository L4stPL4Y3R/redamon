"""Agent-native execute_guarddog (supply_chain_tools.py).

GuardDog moved out of the Kali MCP server: dispatching the attacker-tarball
analyzer needs the Docker socket the least-trusted Kali worker must never hold
(docs/readmes/README.TM.SYSTEM_OVERVIEW.md, TB4). It now rides the agent->webapp->
orchestrator internal lane. These tests cover arg parsing, the ecosystem/charset
gate, the exact HTTP request shape (so the trust lane can't silently regress),
and output framing - all with httpx mocked, no network.

Run: python -m unittest tests.test_guarddog_native_tool
"""

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # agentic/

os.environ.setdefault("INTERNAL_API_KEY", "unit-test-internal-key")

import supply_chain_tools as sct  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _invoke(args: str) -> str:
    # Call the real coroutine impl directly. This is immune to a sibling focused
    # test having stubbed langchain_core.tools.tool into a MagicMock (which would
    # make the wrapped `execute_guarddog` a mock). The impl carries all the logic;
    # the wrapper only adapts it for the executor.
    return _run(sct._guarddog_impl(args))


class _FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class _FakeClient:
    """Async context manager standing in for httpx.AsyncClient."""
    def __init__(self, resp=None, boom=None):
        self._resp = resp
        self._boom = boom
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        if self._boom:
            raise self._boom
        return self._resp


class ArgValidationTests(unittest.TestCase):
    def test_missing_name(self):
        self.assertIn("[ERROR]", _invoke("npm"))
        self.assertIn("usage", _invoke("npm"))

    def test_unsupported_ecosystem(self):
        out = _invoke("cargoX left-pad")
        self.assertIn("unsupported ecosystem", out)

    def test_unparseable_args(self):
        self.assertIn("[ERROR]", _invoke('npm "unterminated'))

    def test_bad_ecosystem_never_dispatches(self):
        client = _FakeClient(_FakeResp(200, {"issues": 0}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            _invoke("cargoX evil")
        self.assertEqual(client.calls, [], "a rejected ecosystem must not hit the network")

    def test_leading_dash_name_rejected_before_dispatch(self):
        # "--help" must never reach GuardDog's argv as a flag.
        client = _FakeClient(_FakeResp(200, {"issues": 0}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm --help")
        self.assertIn("[ERROR]", out)
        self.assertIn("invalid package name", out)
        self.assertEqual(client.calls, [], "a rejected name must not hit the network")

    def test_leading_dash_version_rejected(self):
        client = _FakeClient(_FakeResp(200, {"issues": 0}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm lodash -rf")
        self.assertIn("[ERROR]", out)
        self.assertIn("invalid version", out)
        self.assertEqual(client.calls, [])

    def test_scoped_npm_name_is_accepted(self):
        # @scope/name legitimately starts with @ - must NOT be rejected.
        client = _FakeClient(_FakeResp(200, {"issues": 0, "rules_fired": [], "errors": []}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            _invoke("npm @angular/core 12.0.0")
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["json"]["name"], "@angular/core")


class DispatchTests(unittest.TestCase):
    def test_request_shape_is_the_internal_lane(self):
        client = _FakeClient(_FakeResp(200, {"issues": 0, "rules_fired": [], "errors": []}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            _invoke("npm event-stream 3.3.6")
        self.assertEqual(len(client.calls), 1)
        call = client.calls[0]
        self.assertTrue(call["url"].endswith("/api/internal/supply-chain/guarddog"))
        # Auth header carries the internal key, never a raw orchestrator key.
        self.assertEqual(call["headers"].get("X-Internal-Key"), "unit-test-internal-key")
        self.assertEqual(call["json"], {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"})

    def test_version_optional(self):
        client = _FakeClient(_FakeResp(200, {"issues": 0}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            _invoke("pypi requests")
        self.assertEqual(client.calls[0]["json"], {"ecosystem": "pypi", "name": "requests", "version": ""})

    def test_summarizes_a_hit_as_suspicious_not_malicious(self):
        payload = {"issues": 2, "rules_fired": ["typosquatting", "npm-obfuscation"], "errors": []}
        client = _FakeClient(_FakeResp(200, payload))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil 1.0.0")
        self.assertIn("[DATA]", out)
        self.assertIn("SUSPICIOUS", out)
        self.assertIn("issues: 2", out)
        self.assertIn("typosquatting", out)

    def test_orchestrator_error_is_surfaced(self):
        client = _FakeClient(_FakeResp(200, {"error": "guarddog dispatch failed: no image"}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil")
        self.assertIn("[ERROR]", out)
        self.assertIn("no image", out)

    def test_unauthorized_is_clear(self):
        client = _FakeClient(_FakeResp(401, {}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil")
        self.assertIn("[ERROR]", out)
        self.assertIn("unauthorized", out.lower())

    def test_transport_failure_is_caught(self):
        client = _FakeClient(boom=RuntimeError("connection refused"))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil")
        self.assertIn("[ERROR]", out)
        self.assertIn("dispatch failed", out)

    def test_non_dict_json_does_not_crash(self):
        # A hostile/misconfigured hop returns a JSON array; .get() would raise
        # AttributeError and crash the loop. Must fail as data.
        client = _FakeClient(_FakeResp(200, ["not", "a", "dict"]))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil")
        self.assertIn("[ERROR]", out)
        self.assertIn("unexpected JSON shape", out)

    def test_download_error_is_not_reported_as_clean(self):
        # issues:0 + a download error = analysis could not run. This MUST NOT
        # read as clean (false-clean class, cf. L1 D1).
        payload = {"issues": 0, "rules_fired": [], "errors": ["download-package"]}
        client = _FakeClient(_FakeResp(200, payload))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm event-stream 3.3.6")
        self.assertIn("ANALYSIS INCOMPLETE", out)
        self.assertIn("does NOT mean", out)
        self.assertIn("download-package", out)
        self.assertNotIn("rules fired", out)

    def test_incomplete_still_shows_partial_rules(self):
        # errors AND some fired rules: report both, but keep the incomplete flag.
        payload = {"issues": 1, "rules_fired": ["typosquatting"], "errors": ["metadata"]}
        client = _FakeClient(_FakeResp(200, payload))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil 1.0.0")
        self.assertIn("ANALYSIS INCOMPLETE", out)
        self.assertIn("typosquatting", out)

    def test_clean_result_has_no_incomplete_banner(self):
        payload = {"issues": 0, "rules_fired": [], "errors": []}
        client = _FakeClient(_FakeResp(200, payload))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm lodash 4.17.21")
        self.assertNotIn("INCOMPLETE", out)
        self.assertIn("issues: 0", out)

    def test_bad_request_from_webapp_is_surfaced(self):
        # webapp validation (400) returns {error}. The tool surfaces it.
        client = _FakeClient(_FakeResp(400, {"error": "Unsupported ecosystem: cargo"}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm evil")  # ecosystem npm ok here; simulate webapp 400
        self.assertIn("[ERROR]", out)
        self.assertIn("Unsupported ecosystem", out)


class AdmissionRefusalTests(unittest.TestCase):
    """The memory governor now admits the analyzer container before spawning it,
    so a saturated host answers 409 with a TYPED limit payload instead of a
    result. FastAPI wraps HTTPException(detail=...) as {"detail": {...}}, which
    is a different response shape from GuarddogResult - hence its own tests.

    The failure mode being guarded is not a crash: it is an agent that reads
    "HTTP 409" as "the tool is broken" and stops using it, or worse, reads a
    refusal as a clean package. Every branch must say RETRY and NOT ANALYZED.
    """

    RAM_REFUSAL = {"detail": {
        "admitted": False, "limitType": "ram", "resource": "scan",
        "current": 1234, "ceiling": 5678, "settingName": None,
        "detail": "host memory critically low"}}
    HARD_REFUSAL = {"detail": {
        "admitted": False, "limitType": "hard", "resource": "scan",
        "current": 30, "ceiling": 30,
        "settingName": "RECON_MAX_CONCURRENT_GLOBAL",
        "detail": "30 of 30 concurrent scans allowed"}}

    def _refuse(self, payload):
        client = _FakeClient(_FakeResp(409, payload))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            return _invoke("npm event-stream")

    def test_ram_refusal_is_marked_retryable(self):
        out = self._refuse(self.RAM_REFUSAL)
        self.assertIn("[ERROR]", out)
        self.assertIn("TEMPORARY", out)
        self.assertIn("retry", out.lower())
        self.assertIn("low on memory", out)

    def test_refusal_never_reads_as_a_clean_package(self):
        # The exact false-clean class the soft_error design exists to prevent.
        out = self._refuse(self.RAM_REFUSAL)
        self.assertIn("NOT analyzed", out)
        self.assertNotIn("issues: 0", out)
        self.assertNotIn("[DATA]", out)

    def test_count_cap_is_not_reported_as_a_memory_problem(self):
        """A 'hard' refusal is an operator-set concurrency ceiling, not memory.
        Calling it 'no free memory' sends whoever reads the transcript after the
        wrong problem, and the fix (raise the setting) is completely different."""
        out = self._refuse(self.HARD_REFUSAL)
        self.assertIn("concurrency limit", out)
        self.assertIn("RECON_MAX_CONCURRENT_GLOBAL", out)
        self.assertNotIn("low on memory", out)

    def test_underlying_detail_is_passed_through(self):
        self.assertIn("host memory critically low", self._refuse(self.RAM_REFUSAL))
        self.assertIn("30 of 30 concurrent scans", self._refuse(self.HARD_REFUSAL))

    def test_malformed_409_payloads_still_produce_a_retryable_message(self):
        # A hostile or refactored hop could send any of these; none may crash the
        # tool or degrade into a clean-looking result.
        for payload in ({"detail": "just a string"}, {"detail": None}, {},
                        {"detail": []}, {"detail": {"limitType": None}}):
            out = self._refuse(payload)
            self.assertIn("[ERROR]", out, payload)
            self.assertIn("TEMPORARY", out, payload)
            self.assertIn("NOT analyzed", out, payload)

    def test_a_409_does_not_fall_through_to_the_generic_error_branch(self):
        # Before the typed branch this rendered as a bare "guarddog HTTP 409".
        self.assertNotIn("guarddog HTTP 409", self._refuse(self.RAM_REFUSAL))

    def test_other_4xx_still_use_the_generic_branch(self):
        client = _FakeClient(_FakeResp(503, {"error": "Service not initialized"}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm lodash")
        self.assertIn("Service not initialized", out)
        self.assertNotIn("TEMPORARY", out)

    def test_success_path_is_untouched_by_the_new_branch(self):
        client = _FakeClient(_FakeResp(200, {"issues": 0, "rules_fired": [],
                                             "errors": [], "error": None}))
        with patch.object(sct.httpx, "AsyncClient", return_value=client):
            out = _invoke("npm lodash")
        self.assertIn("[DATA]", out)
        self.assertIn("issues: 0", out)
        self.assertNotIn("TEMPORARY", out)


class RegistrationTests(unittest.TestCase):
    def test_builder_exposes_the_tool(self):
        self.assertIn("execute_guarddog", sct.build_supply_chain_tools())


if __name__ == "__main__":
    unittest.main()
