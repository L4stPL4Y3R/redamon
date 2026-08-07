"""
Regression + integration tests for the complete removal of the Tor / proxychains
anonymity feature (branch feat-remove_tor_integrate_mitmproxy).

Written specifically to catch failure modes that ordinary import checks and the
pre-existing suite would MISS:

  1. A dangling reference to a removed symbol (use_proxy, is_tor_running,
     USE_TOR_FOR_RECON, get_tor_session, ...) anywhere in production recon code
     -- would only blow up at scan runtime, not at import time.
  2. A changed helper signature that a caller still invokes with `use_proxy`,
     or a POSITIONAL-argument shift from removing use_proxy from the middle of a
     signature -- a runtime TypeError with no `use_proxy` token left behind.
  3. Command builders that still emit a `-proxy`/`-x`/socks5 flag.
  4. The graphql-cop path still emitting `-T` / `-x` from a stale
     USE_TOR_FOR_RECON / HTTP_PROXY setting.

Pure-Python: no docker, no network, no third-party test deps (plain unittest so
it runs under the repo's `python -m unittest` convention as well as pytest).
"""

import ast
import inspect
import os
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
RECON_DIR = REPO_ROOT / "recon"

REMOVED_IDENTIFIERS = {
    "use_proxy", "use_tor", "is_tor_running", "get_tor_session", "get_tor_exit_ip",
    "check_tor_connection", "get_proxychains_cmd", "get_proxychains_prefix",
    "is_proxychains_available", "print_anonymity_status", "run_through_tor",
    "run_command_anonymous", "require_tor", "TorProxy",
    "USE_TOR_FOR_RECON", "TOR_ENABLED",
}
REMOVED_STRING_FRAGMENTS = ("proxychains", "socks5://127.0.0.1:9050", "127.0.0.1:9050")

CHANGED_HELPERS = [
    "recon.helpers.nuclei_helpers.build_nuclei_command",
    "recon.helpers.resource_enum.katana_helpers.run_katana_crawler",
    "recon.helpers.resource_enum.katana_helpers.fetch_forms_from_urls",
    "recon.helpers.resource_enum.gau_helpers.run_gau_discovery",
    "recon.helpers.resource_enum.gau_helpers.verify_gau_urls",
    "recon.helpers.resource_enum.gau_helpers.detect_gau_methods",
    "recon.helpers.resource_enum.hakrawler_helpers.run_hakrawler_crawler",
    "recon.helpers.resource_enum.jsluice_helpers.run_jsluice_analysis",
    "recon.helpers.resource_enum.jsluice_helpers.verify_jsluice_urls",
    "recon.helpers.resource_enum.kiterunner_helpers.run_kiterunner_discovery",
    "recon.helpers.resource_enum.kiterunner_helpers.detect_kiterunner_methods",
    "recon.helpers.resource_enum.ffuf_helpers.run_ffuf_discovery",
    "recon.helpers.resource_enum.arjun_helpers.run_arjun_discovery",
    "recon.helpers.resource_enum.paramspider_helpers.run_paramspider_discovery",
    "recon.helpers.resource_enum.endpoint_helpers.organize_endpoints",
    "recon.helpers.resource_enum.zap_ajax_spider_helpers.run_zap_ajax_spider",
    "recon.main_recon_modules.port_scan.build_naabu_command",
    "recon.main_recon_modules.http_probe.build_httpx_command",
]

TOUCHED_MODULES = [
    "recon.main", "recon.helpers", "recon.project_settings",
    "recon.main_recon_modules.port_scan", "recon.main_recon_modules.masscan_scan",
    "recon.main_recon_modules.vuln_scan", "recon.main_recon_modules.http_probe",
    "recon.main_recon_modules.domain_recon", "recon.main_recon_modules.resource_enum",
    "recon.main_recon_modules.subdomain_takeover",
    "recon.partial_recon_modules.web_crawling",
    "recon.partial_recon_modules.parameter_discovery",
    "recon.partial_recon_modules.subdomain_discovery",
    "recon.graphql_scan.misconfig",
]

# name -> module(s) that define the changed function.
_CHANGED_FUNC_MODULES = {
    "build_nuclei_command": ["recon.helpers.nuclei_helpers"],
    "run_katana_crawler": ["recon.helpers.resource_enum.katana_helpers"],
    "fetch_forms_from_urls": ["recon.helpers.resource_enum.katana_helpers"],
    "run_gau_discovery": ["recon.helpers.resource_enum.gau_helpers"],
    "verify_gau_urls": ["recon.helpers.resource_enum.gau_helpers"],
    "detect_gau_methods": ["recon.helpers.resource_enum.gau_helpers"],
    "run_hakrawler_crawler": ["recon.helpers.resource_enum.hakrawler_helpers"],
    "run_jsluice_analysis": ["recon.helpers.resource_enum.jsluice_helpers"],
    "verify_jsluice_urls": ["recon.helpers.resource_enum.jsluice_helpers"],
    "run_kiterunner_discovery": ["recon.helpers.resource_enum.kiterunner_helpers"],
    "detect_kiterunner_methods": ["recon.helpers.resource_enum.kiterunner_helpers"],
    "run_ffuf_discovery": ["recon.helpers.resource_enum.ffuf_helpers"],
    "run_arjun_discovery": ["recon.helpers.resource_enum.arjun_helpers"],
    "run_paramspider_discovery": ["recon.helpers.resource_enum.paramspider_helpers"],
    "organize_endpoints": ["recon.helpers.resource_enum.endpoint_helpers"],
    "run_zap_ajax_spider": ["recon.helpers.resource_enum.zap_ajax_spider_helpers"],
    "build_naabu_command": ["recon.main_recon_modules.port_scan"],
    "build_httpx_command": ["recon.main_recon_modules.http_probe"],
}

_SENT = object()


def _production_py_files():
    for root, _dirs, files in os.walk(RECON_DIR):
        parts = Path(root).parts
        if "tests" in parts or "__pycache__" in root or "output" in parts:
            continue
        for f in files:
            if f.endswith(".py"):
                yield Path(root) / f


def _resolve(dotted):
    mod_name, _, attr = dotted.rpartition(".")
    mod = __import__(mod_name, fromlist=[attr])
    return getattr(mod, attr)


def _flat(cmd):
    return " ".join(str(c) for c in cmd)


class TestNoDanglingReferences(unittest.TestCase):
    def test_no_removed_identifiers(self):
        offenders = []
        for path in _production_py_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                name = None
                if isinstance(node, ast.Name):
                    name = node.id
                elif isinstance(node, ast.Attribute):
                    name = node.attr
                elif isinstance(node, ast.arg):
                    name = node.arg
                elif isinstance(node, ast.keyword):
                    name = node.arg
                if name in REMOVED_IDENTIFIERS:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{getattr(node, 'lineno', '?')} -> {name}")
        self.assertEqual([], offenders, "Dangling Tor/anonymity identifiers found")

    def test_no_removed_string_fragments(self):
        offenders = []
        for path in _production_py_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for frag in REMOVED_STRING_FRAGMENTS:
                        if frag in node.value:
                            offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} -> {frag!r}")
        self.assertEqual([], offenders, "Tor/proxy string literals found")

    def test_anonymity_module_deleted(self):
        self.assertFalse((RECON_DIR / "helpers" / "anonymity.py").exists())

    def test_removed_helper_symbols_not_importable(self):
        import recon.helpers as h
        for gone in ("is_tor_running", "get_tor_session", "TorProxy", "run_through_tor",
                     "run_command_anonymous", "get_proxychains_cmd", "print_anonymity_status"):
            self.assertFalse(hasattr(h, gone), f"recon.helpers still exports {gone}")


class TestSignatures(unittest.TestCase):
    def test_helpers_dropped_use_proxy(self):
        for dotted in CHANGED_HELPERS:
            with self.subTest(fn=dotted):
                params = inspect.signature(_resolve(dotted)).parameters
                self.assertNotIn("use_proxy", params)
                self.assertNotIn("use_tor", params)


class TestCommandBuildersNoProxy(unittest.TestCase):
    def test_build_naabu_command(self):
        from recon.main_recon_modules.port_scan import build_naabu_command
        from recon.project_settings import DEFAULT_SETTINGS
        cmd = build_naabu_command("/tmp/t.txt", "/tmp/o.json", dict(DEFAULT_SETTINGS))
        self.assertNotIn("-proxy", cmd)
        self.assertNotIn("9050", _flat(cmd))
        self.assertNotIn("socks5", _flat(cmd))

    def test_build_httpx_command(self):
        from recon.main_recon_modules.http_probe import build_httpx_command
        from recon.project_settings import DEFAULT_SETTINGS
        cmd = build_httpx_command("/tmp/t.txt", "/tmp/o.json", dict(DEFAULT_SETTINGS))
        self.assertNotIn("-proxy", cmd)
        self.assertNotIn("9050", _flat(cmd))
        self.assertNotIn("socks5", _flat(cmd))

    def test_build_nuclei_command(self):
        from recon.helpers.nuclei_helpers import build_nuclei_command
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.json",
            docker_image="projectdiscovery/nuclei:latest",
            severity=["high"], tags=["cve"],
        )
        self.assertNotIn("-proxy", cmd)
        self.assertNotIn("9050", _flat(cmd))
        self.assertNotIn("socks5", _flat(cmd))


class TestGraphqlCopNoTorFlags(unittest.TestCase):
    def test_ignores_stale_tor_and_proxy_settings(self):
        from recon.graphql_scan import misconfig
        captured = {}

        class _FakeResult:
            returncode = 0
            stdout = "[]"
            stderr = ""

        def _fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return _FakeResult()

        settings = {
            "GRAPHQL_COP_ENABLED": True,
            "USE_TOR_FOR_RECON": True,                      # stale, must be ignored
            "HTTP_PROXY": "http://malicious-leak:8080",     # stale, must be ignored
        }
        with mock.patch.object(misconfig.subprocess, "run", _fake_run):
            misconfig.run_graphql_cop("http://target/graphql", {}, settings)

        self.assertIn("cmd", captured, "subprocess.run was never called")
        cmd = captured["cmd"]
        self.assertNotIn("-T", cmd)
        self.assertNotIn("-x", cmd)
        self.assertNotIn("http://malicious-leak:8080", _flat(cmd))
        self.assertIn("--net=host", cmd)  # preserved invariant


class TestSettingsContract(unittest.TestCase):
    def test_default_settings_no_tor_key(self):
        from recon.project_settings import DEFAULT_SETTINGS
        bad = [k for k in DEFAULT_SETTINGS if k.upper() in ("USE_TOR_FOR_RECON", "TOR_ENABLED")]
        self.assertEqual([], bad)

    def test_anonymous_mode_key_retained_and_false(self):
        src = (RECON_DIR / "main.py").read_text()
        self.assertIn('"anonymous_mode": False', src)


class TestCrossLayerSchema(unittest.TestCase):
    def test_prisma_schema_no_tor_column(self):
        schema = (REPO_ROOT / "webapp" / "prisma" / "schema.prisma").read_text()
        self.assertNotIn("use_tor_for_recon", schema)
        self.assertNotIn("useTorForRecon", schema)

    def test_webapp_preset_schema_no_tor_field(self):
        ts = (REPO_ROOT / "webapp" / "src" / "lib" / "recon-preset-schema.ts").read_text()
        self.assertNotIn("useTorForRecon", ts)


class TestImportSafety(unittest.TestCase):
    def test_touched_modules_import(self):
        for mod in TOUCHED_MODULES:
            with self.subTest(module=mod):
                __import__(mod)


class TestCallSiteArity(unittest.TestCase):
    """Every call to a changed function still binds to its NEW signature.

    Catches a positional-argument SHIFT from removing use_proxy from the middle
    of a signature -- invisible to the identifier scan because no token remains.
    """

    @staticmethod
    def _build_sigs():
        sigs = {}
        for name, mods in _CHANGED_FUNC_MODULES.items():
            for mod in mods:
                m = __import__(mod, fromlist=[name])
                sigs.setdefault(name, []).append(inspect.signature(getattr(m, name)))
        return sigs

    @staticmethod
    def _binds_any(sig_list, npos, kwnames):
        for sig in sig_list:
            try:
                sig.bind(*([_SENT] * npos), **{k: _SENT for k in kwnames})
                return True
            except TypeError:
                continue
        return False

    @staticmethod
    def _call_shape(args, keywords):
        npos = 0
        for a in args:
            if isinstance(a, ast.Starred):
                return None
            npos += 1
        kw = []
        for k in keywords:
            if k.arg is None:
                return None
            kw.append(k.arg)
        return npos, kw

    def test_call_sites_bind(self):
        sigs = self._build_sigs()
        offenders = []
        checked = 0
        for path in _production_py_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                callee = None
                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee = node.func.attr
                if callee in sigs:
                    shape = self._call_shape(node.args, node.keywords)
                    if shape is not None:
                        npos, kw = shape
                        if not self._binds_any(sigs[callee], npos, kw):
                            offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} {callee}(pos={npos},kw={kw})")
                        checked += 1
                # executor.submit(fn, *args, **kw)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "submit" and node.args:
                    first = node.args[0]
                    fn = first.id if isinstance(first, ast.Name) else None
                    if fn in sigs:
                        shape = self._call_shape(node.args[1:], node.keywords)
                        if shape is not None:
                            npos, kw = shape
                            if not self._binds_any(sigs[fn], npos, kw):
                                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} submit->{fn}(pos={npos},kw={kw})")
                            checked += 1
        self.assertGreaterEqual(checked, 15, f"expected many call sites, checked only {checked}")
        self.assertEqual([], offenders, "Call sites incompatible with new signatures")


if __name__ == "__main__":
    unittest.main()
