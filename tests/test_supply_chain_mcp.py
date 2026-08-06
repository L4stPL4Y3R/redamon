"""Unit tests for the L3 MCP tools (execute_osv_scanner, execute_guarddog).

network_recon_server imports `fastmcp`, which lives only in the kali image. We
stub it with identity decorators so the real tool functions are importable and
callable on the host, then mock `subprocess` so no real binary/Docker is needed.
Focus: argument validation (S6/S7) and output framing (data-not-instructions).

Run: python -m unittest tests.test_supply_chain_mcp
"""

import importlib.util
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_server():
    # Stub fastmcp: FastMCP().tool() must return an identity decorator so the
    # decorated functions stay real (a MagicMock decorator would replace them).
    class _FakeMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda fn: fn

        def run(self, *a, **k):
            pass

    fake = types.ModuleType("fastmcp")
    fake.FastMCP = _FakeMCP
    sys.modules["fastmcp"] = fake

    path = os.path.join(_REPO, "mcp", "servers", "network_recon_server.py")
    spec = importlib.util.spec_from_file_location("network_recon_server", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Res:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class TestExecuteOsvScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_server()

    def test_empty_args(self):
        self.assertIn("[ERROR]", self.m.execute_osv_scanner("   "))

    def test_hostile_purl_rejected(self):
        out = self.m.execute_osv_scanner("pkg:npm/$(id)")
        self.assertIn("[ERROR]", out)
        self.assertIn("invalid purl", out)

    def test_relative_path_rejected(self):
        self.assertIn("[ERROR]", self.m.execute_osv_scanner("relative/path.json"))

    def test_traversal_path_rejected(self):
        self.assertIn("[ERROR]", self.m.execute_osv_scanner("/work/../../etc/passwd"))

    def test_purl_scans_and_reports_mal(self):
        raw = ('{"results":[{"packages":[{"package":{"name":"lodahs",'
               '"version":"1.0.0","ecosystem":"npm"},"vulnerabilities":'
               '[{"id":"MAL-2025-1"}]}]}]}')
        with patch.object(self.m.subprocess, "run", return_value=_Res(1, raw)):
            out = self.m.execute_osv_scanner("pkg:npm/lodahs@1.0.0")
        self.assertIn("[DATA]", out)
        self.assertIn("MALICIOUS", out)
        self.assertIn("MAL-2025-1", out)

    def test_tool_error_exit_surfaced(self):
        with patch.object(self.m.subprocess, "run", return_value=_Res(127, "", "boom")):
            out = self.m.execute_osv_scanner("pkg:npm/x@1")
        self.assertIn("[ERROR]", out)


class TestExecuteGuarddog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_server()

    def test_missing_args(self):
        self.assertIn("[ERROR]", self.m.execute_guarddog("npm"))

    def test_bad_ecosystem(self):
        self.assertIn("unsupported ecosystem", self.m.execute_guarddog("cargoX left-pad"))

    def test_hostile_name_rejected(self):
        out = self.m.execute_guarddog("npm ;rm-rf")
        self.assertIn("[ERROR]", out)

    def test_dispatches_and_summarizes(self):
        raw = '{"package":"evil","issues":2,"errors":{},"results":{"typosquatting":"x","npm-obfuscation":[{"message":"y"}]}}'
        with patch.object(self.m.subprocess, "run", return_value=_Res(1, raw)) as p:
            out = self.m.execute_guarddog("npm evil 1.0.0")
        # dispatched via docker run of the hardened analyzer image, not inline
        argv = p.call_args[0][0]
        self.assertEqual(argv[0], "docker")
        self.assertIn("--cap-drop", argv)
        self.assertIn("[DATA]", out)
        self.assertIn("issues: 2", out)


class TestSafeNameHelper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_server()

    def test_inline_charset_gate_matches_shared_one(self):
        good = ["lodash", "@angular/core", "pkg:npm/lodash@4.17.21"]
        bad = ["$(id)", "; rm", "../x", "-flag", "a b", "a\x00b"]
        for g in good:
            self.assertTrue(self.m._sc_safe_name(g), g)
        for b in bad:
            self.assertFalse(self.m._sc_safe_name(b), b)


if __name__ == "__main__":
    unittest.main()
