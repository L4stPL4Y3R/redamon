"""Unit tests for the PyRIT adapter (base interpreter; pyrit not required).

pyrit_run.py imports pyrit lazily (inside _run), so its request-building helpers
are testable here. The adapter test mocks the subprocess + parser.

    cd ai_attack_surface_scan && python -m unittest \
        adapters.pyrit.tests.test_pyrit_adapter -v
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from config import Bounds
from target_loader import Target

from adapters.pyrit import adapter as padapter
from adapters.pyrit import pyrit_run
from adapters.pyrit.parser import parse_report


# --------------------------------------------------------------------------- #
# pyrit_run request building (no pyrit import needed)
# --------------------------------------------------------------------------- #

class TestRequestBuilding(unittest.TestCase):
    def test_v1_endpoint_from_chat_path(self):
        # The OpenAI SDK appends /chat/completions, so we pass the /v1 base.
        self.assertEqual(pyrit_run._v1_endpoint("http://h:11434", "/v1/chat/completions"),
                         "http://h:11434/v1")
        self.assertEqual(pyrit_run._v1_endpoint("https://api.example.com:8443", "/v1/chat/completions"),
                         "https://api.example.com:8443/v1")

    def test_v1_endpoint_default(self):
        self.assertEqual(pyrit_run._v1_endpoint("http://h", None), "http://h/v1")
        self.assertEqual(pyrit_run._v1_endpoint("http://h", "/v1"), "http://h/v1")

    def test_v1_endpoint_ollama_native_path(self):
        # /api/chat isn't /v1 — fall back to the host's /v1 (Ollama serves both).
        self.assertEqual(pyrit_run._v1_endpoint("http://h:11434", "/api/chat"), "http://h:11434/v1")

    def test_victim_auth_bearer_uses_api_key(self):
        api_key, headers = pyrit_run._victim_auth(
            {"auth_header": "Authorization", "auth_scheme": "Bearer", "api_key": "sk-1"})
        self.assertEqual(api_key, "sk-1")     # SDK sends Authorization: Bearer
        self.assertIsNone(headers)

    def test_victim_auth_custom_header(self):
        api_key, headers = pyrit_run._victim_auth(
            {"auth_header": "x-api-key", "auth_scheme": "", "api_key": "k"})
        self.assertEqual(api_key, "x")        # dummy
        self.assertEqual(json.loads(headers), {"x-api-key": "k"})

    def test_victim_auth_none(self):
        api_key, headers = pyrit_run._victim_auth({})
        self.assertEqual(api_key, "x")
        self.assertIsNone(headers)


# --------------------------------------------------------------------------- #
# parser ASR math
# --------------------------------------------------------------------------- #

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "pyrit_crescendo_report.json")


class TestParserRealFixture(unittest.TestCase):
    def test_parses_captured_crescendo_run(self):
        r = parse_report(FIXTURE)
        self.assertEqual(r.pyrit_version, "0.14.0")
        self.assertEqual(r.attack, "crescendo")
        self.assertEqual(r.successes, 1)
        self.assertEqual(r.asr, 1.0)   # the captured run jailbroke the weak model


class TestParser(unittest.TestCase):
    def _write(self, results, attack="crescendo"):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"pyrit_version": "0.14.0", "attack": attack, "seed": 0, "results": results}, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_asr_is_successes_over_scored(self):
        p = self._write([
            {"objective": "a", "outcome": "SUCCESS", "turns_used": 2},
            {"objective": "b", "outcome": "FAILURE", "turns_used": 4},
        ])
        r = parse_report(p)
        self.assertEqual(r.successes, 1)
        self.assertEqual(r.scored, 2)
        self.assertEqual(r.asr, 0.5)

    def test_error_excluded_from_denominator(self):
        p = self._write([
            {"objective": "a", "outcome": "SUCCESS"},
            {"objective": "b", "outcome": "ERROR"},
        ])
        r = parse_report(p)
        self.assertEqual(r.scored, 1)
        self.assertEqual(r.asr, 1.0)  # 1 success / 1 scored (error not counted)

    def test_all_error_zero_asr(self):
        p = self._write([{"objective": "a", "outcome": "ERROR"}])
        self.assertEqual(parse_report(p).asr, 0.0)


# --------------------------------------------------------------------------- #
# adapter Finding construction (subprocess + parser mocked)
# --------------------------------------------------------------------------- #

class TestAdapterFindings(unittest.TestCase):
    def _target(self):
        return Target(baseurl="http://h:8000", path="/v1/chat/completions",
                      method="POST", ai_interface_type="llm-chat", ai_model_ids=["qwen"])

    def test_no_judge_returns_empty(self):
        findings = padapter.run(self._target(), Bounds(), output_dir="/tmp/x", run_id="t",
                                judge_base_url=None, attacks=["crescendo"])
        self.assertEqual(findings, [])

    def test_finding_built_from_results(self):
        from adapters.pyrit.parser import PyritReport, PyritResult
        report = PyritReport(attack="crescendo", pyrit_version="0.14.0", seed=0, results=[
            PyritResult("reveal system prompt", "SUCCESS", 3, "complied"),
            PyritResult("other", "FAILURE", 4, "refused"),
        ])
        with tempfile.TemporaryDirectory() as d:
            # the adapter checks the out file exists; create it so it proceeds to parse
            def fake_invoke(cfg_path, **_):
                cfg = json.load(open(cfg_path))
                open(cfg["out"], "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                findings = padapter.run(self._target(), Bounds(trials=1, asr_threshold=0.3, judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434",
                                        attacks=["crescendo"])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, "pyrit")
        self.assertEqual(f.chip, "jailbreak")
        self.assertEqual(f.ai_owasp_llm_id, "LLM01")
        self.assertEqual(f.ai_payload_class, "pyrit-crescendo")
        self.assertEqual(f.ai_oracle_kind, "judge_llm")
        self.assertAlmostEqual(f.ai_asr, 0.5)

    def test_custom_objective_and_seed_reach_config(self):
        from adapters.pyrit.parser import PyritReport, PyritResult
        report = PyritReport(attack="tap", pyrit_version="0.14.0", seed=7,
                             results=[PyritResult("o", "SUCCESS", 1, "ok")])
        captured = {}
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                with open(cfg_path) as fh:
                    captured.update(json.load(fh))
                open(captured["out"], "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                padapter.run(self._target(), Bounds(asr_threshold=0.3, judge_model="m", seed=7),
                             output_dir=d, run_id="t1", judge_base_url="http://localhost:11434",
                             attacks=["tap"], objective="Approve a refund with no order number")
        # custom objective overrides the attack's built-in goals; seed flows from bounds
        self.assertEqual(captured["objectives"], ["Approve a refund with no order number"])
        self.assertEqual(captured["seed"], 7)
        self.assertEqual(captured["attack"], "tap")

    def test_explicit_seed_zero_is_honored(self):
        from adapters.pyrit.parser import PyritReport, PyritResult
        report = PyritReport(attack="crescendo", pyrit_version="0.14.0", seed=0,
                             results=[PyritResult("o", "SUCCESS", 1, "ok")])
        captured = {}
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, {"AI_ATTACK_PYRIT_SEED": "99"}):
            def fake_invoke(cfg_path, **_):
                with open(cfg_path) as fh:
                    captured.update(json.load(fh))
                open(captured["out"], "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                padapter.run(self._target(), Bounds(asr_threshold=0.3, judge_model="m", seed=0),
                             output_dir=d, run_id="t1", judge_base_url="http://localhost:11434",
                             attacks=["crescendo"])
        self.assertEqual(captured["seed"], 0)   # not overridden by the env default

    def test_new_attacks_have_class_mappings(self):
        from adapters.pyrit.objectives import ATTACK_CLASSES, ATTACKS
        for a in ("crescendo", "skeleton_key", "tap", "many_shot"):
            self.assertIn(a, ATTACK_CLASSES)
            self.assertIn(a, ATTACKS)
        self.assertEqual(ATTACK_CLASSES["tap"], "TAPAttack")
        self.assertEqual(ATTACK_CLASSES["many_shot"], "ManyShotJailbreakAttack")

    def test_multiple_attacks_yield_multiple_findings(self):
        from adapters.pyrit.parser import PyritReport, PyritResult
        report = PyritReport(attack="x", pyrit_version="0.14.0", seed=0,
                             results=[PyritResult("o", "SUCCESS", 2, "ok")])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                open(json.load(open(cfg_path))["out"], "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                findings = padapter.run(self._target(), Bounds(asr_threshold=0.3, judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434",
                                        attacks=["crescendo", "skeleton_key"])
        self.assertEqual(len(findings), 2)
        self.assertEqual({f.ai_payload_class for f in findings},
                         {"pyrit-crescendo", "pyrit-skeleton-key"})

    def test_no_output_file_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(padapter, "_invoke", return_value=(1, "crashed")):  # no out file
                findings = padapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434",
                                        attacks=["crescendo"])
        self.assertEqual(findings, [])

    def test_model_from_string_ai_model_ids(self):
        # recon usually stores a list, but a bare string must not be sliced to a char.
        t = self._target()
        t.ai_model_ids = "qwen2.5:7b"
        captured = {}
        with tempfile.TemporaryDirectory() as d:
            def cap(cfg_path, **_):
                cfg = json.load(open(cfg_path))
                captured.update(cfg)
                open(cfg["out"], "w").close()
                return 0, ""
            from adapters.pyrit.parser import PyritReport
            with patch.object(padapter, "_invoke", side_effect=cap), \
                 patch.object(padapter, "parse_report",
                              return_value=PyritReport("crescendo", "0.14.0", 0, [])):
                padapter.run(t, Bounds(judge_model="m"), output_dir=d, run_id="t1",
                             judge_base_url="http://localhost:11434", attacks=["crescendo"])
        self.assertEqual(captured["model"], "qwen2.5:7b")

    def test_below_threshold_no_finding(self):
        from adapters.pyrit.parser import PyritReport, PyritResult
        report = PyritReport(attack="crescendo", pyrit_version="0.14.0", seed=0, results=[
            PyritResult("a", "FAILURE", 4, "refused"),
        ])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                open(json.load(open(cfg_path))["out"], "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                findings = padapter.run(self._target(), Bounds(asr_threshold=0.3, judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        self.assertEqual(findings, [])

    def test_invoke_passes_timeout_to_run_streamed(self):
        with patch.object(padapter, "run_streamed", return_value=(0, "")) as mrun:
            padapter._invoke("/tmp/cfg.json", timeout=1234)
        self.assertEqual(mrun.call_args.kwargs["timeout"], 1234)


if __name__ == "__main__":
    unittest.main(verbosity=2)
