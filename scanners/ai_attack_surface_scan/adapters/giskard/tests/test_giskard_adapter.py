"""Unit tests for the giskard adapter (base interpreter; giskard not required).

giskard_run.py imports giskard/pandas lazily (inside main), so its helpers are
testable here. The adapter test mocks the subprocess + parser.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from config import Bounds
from target_loader import Target

from adapters.giskard import adapter as gadapter
from adapters.giskard import giskard_run
from adapters.giskard.detectors import DEFAULT_DETECTORS, detector_meta
from adapters.giskard.parser import parse_report


class TestRunnerHelpers(unittest.TestCase):
    def test_family_inference(self):
        self.assertEqual(giskard_run._family("/v1/chat/completions", None), "openai-chat")
        self.assertEqual(giskard_run._family("/api/chat", None), "ollama-chat")
        self.assertEqual(giskard_run._family("/v1/messages", None), "anthropic")

    def test_body_shape(self):
        body, path = giskard_run._body_and_path("openai-chat", "m", "hello?")
        self.assertEqual(body["messages"][0]["content"], "hello?")
        self.assertEqual(path, ["choices", 0, "message", "content"])

    def test_call_target_sends_auth_and_extracts(self):
        cfg = {"baseurl": "http://h:8000", "path": "/v1/chat/completions",
               "interface_type": "llm-chat", "model": "m",
               "auth_header": "Authorization", "auth_scheme": "Bearer", "api_key": "sk-1"}
        call = giskard_run._make_call_target(cfg)
        captured = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps({"choices": [{"message": {"content": "answer"}}]}).encode()

        def fake_urlopen(req, timeout=0):
            captured["headers"] = req.headers
            captured["url"] = req.full_url
            return FakeResp()

        with patch.object(giskard_run.urllib.request, "urlopen", side_effect=fake_urlopen):
            out = call("what is 2+2?")
        self.assertEqual(out, "answer")
        # urllib title-cases header keys
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer sk-1")
        self.assertEqual(captured["url"], "http://h:8000/v1/chat/completions")

    def test_call_target_no_auth(self):
        cfg = {"baseurl": "http://h", "path": "/v1/chat/completions", "model": "m"}
        call = giskard_run._make_call_target(cfg)

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps({"choices": [{"message": {"content": "x"}}]}).encode()

        captured = {}
        with patch.object(giskard_run.urllib.request, "urlopen",
                          side_effect=lambda req, timeout=0: (captured.update(h=req.headers), FakeResp())[1]):
            call("q")
        self.assertNotIn("Authorization", captured["h"])


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "giskard_report.json")


class TestParserRealFixture(unittest.TestCase):
    def test_parses_captured_scan(self):
        r = parse_report(FIXTURE)
        self.assertEqual(r.giskard_version, "2.19.1")
        self.assertEqual(len(r.issues), 5)   # 5 prompt-injection issues captured
        # real detector_name maps to the right chip
        self.assertEqual(detector_meta(r.issues[0].detector), ("LLM01", "prompt-injection"))
        self.assertIn(r.issues[0].severity, ("major", "medium", "minor"))


class TestParser(unittest.TestCase):
    def _write(self, issues):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"giskard_version": "2.19.1", "detectors": ["llm_prompt_injection"], "issues": issues}, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_parses_issues(self):
        p = self._write([
            {"detector": "llm_prompt_injection", "description": "injection found", "severity": "major", "num_examples": 3},
            {"detector": "llm_information_disclosure", "description": "leak", "severity": "medium", "num_examples": 1},
        ])
        r = parse_report(p)
        self.assertEqual(r.giskard_version, "2.19.1")
        self.assertEqual(len(r.issues), 2)
        self.assertEqual(r.issues[0].detector, "llm_prompt_injection")
        self.assertEqual(r.issues[0].num_examples, 3)

    def test_empty_issues(self):
        self.assertEqual(parse_report(self._write([])).issues, [])


class TestDetectorMap(unittest.TestCase):
    def test_known(self):
        self.assertEqual(detector_meta("llm_prompt_injection"), ("LLM01", "prompt-injection"))
        self.assertEqual(detector_meta("llm_information_disclosure"), ("LLM02", "data-disclosure"))
        self.assertEqual(detector_meta("llm_faithfulness"), ("LLM09", "hallucination"))

    def test_extended_detectors_map(self):
        # detectors added in Tier-1 (real giskard 2.19.1 detector names)
        self.assertEqual(detector_meta("LLMHarmfulContentDetector"), ("safety", "toxicity"))
        self.assertEqual(detector_meta("LLMStereotypesDetector"), ("safety", "bias"))
        self.assertEqual(detector_meta("LLMOutputFormattingDetector"), ("LLM05", "insecure-output"))
        self.assertEqual(detector_meta("LLMBasicSycophancyDetector"), ("LLM09", "hallucination"))

    def test_extended_tag_map(self):
        from adapters.giskard.detectors import TAG_MAP
        for tag in ("harmfulness", "stereotypes", "sycophancy", "output_formatting"):
            self.assertIn(tag, TAG_MAP)

    def test_default_detectors_are_tags(self):
        # only=[...] filters by tags, so the default carries semantic tags.
        self.assertIn("prompt_injection", DEFAULT_DETECTORS)
        self.assertIn("information_disclosure", DEFAULT_DETECTORS)


class TestAdapterFindings(unittest.TestCase):
    def _target(self):
        return Target(baseurl="http://h:8000", path="/v1/chat/completions",
                      method="POST", ai_interface_type="llm-chat", ai_model_ids=["qwen"])

    def test_no_judge_returns_empty(self):
        self.assertEqual(
            gadapter.run(self._target(), Bounds(), output_dir="/tmp/x", run_id="t", judge_base_url=None),
            [])

    def _run_capturing_cfg(self, target_purpose):
        """Run the adapter with a no-op invoke, return the written config dict."""
        from adapters.giskard.parser import GiskardReport
        captured = {}
        empty = GiskardReport(giskard_version="2.19.1", detectors=[], issues=[])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                with open(cfg_path) as fh:
                    captured.update(json.load(fh))
                open(captured["out"], "w").close()
                return 0, ""
            with patch.object(gadapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(gadapter, "parse_report", return_value=empty):
                gadapter.run(self._target(), Bounds(judge_model="m"), output_dir=d, run_id="t1",
                             judge_base_url="http://localhost:11434", target_purpose=target_purpose)
        return captured

    def test_target_purpose_flows_to_model_description(self):
        # giskard generates its test set from the model description, so the shared
        # target_purpose must land in the config's "description".
        cfg = self._run_capturing_cfg("A bank support bot that issues refunds")
        self.assertEqual(cfg["description"], "A bank support bot that issues refunds")

    def test_blank_purpose_uses_generic_description(self):
        cfg = self._run_capturing_cfg("   ")
        self.assertEqual(cfg["description"], "A general-purpose LLM chat assistant.")

    def test_issue_becomes_finding(self):
        from adapters.giskard.parser import GiskardIssue, GiskardReport
        report = GiskardReport(giskard_version="2.19.1", detectors=["llm_prompt_injection"], issues=[
            GiskardIssue("llm_prompt_injection", "injection works", "major", 3),
        ])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                open(json.load(open(cfg_path))["out"], "w").close()
                return 0, ""
            with patch.object(gadapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(gadapter, "parse_report", return_value=report):
                findings = gadapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, "giskard")
        self.assertEqual(f.chip, "prompt-injection")
        self.assertEqual(f.ai_owasp_llm_id, "LLM01")
        self.assertEqual(f.ai_payload_class, "giskard-llm_prompt_injection")
        self.assertEqual(f.severity, "high")        # major -> high
        self.assertEqual(f.ai_trials, 3)
        self.assertEqual(f.ai_oracle_kind, "judge_llm")

    def test_aggregates_per_detector_worst_severity(self):
        from adapters.giskard.parser import GiskardIssue, GiskardReport
        # 3 issues from ONE detector (mixed severity) + 1 from another.
        report = GiskardReport(giskard_version="2.19.1",
                               detectors=["prompt_injection", "information_disclosure"], issues=[
            GiskardIssue("LLMPromptInjectionDetector", "a", "medium", 0),
            GiskardIssue("LLMPromptInjectionDetector", "b", "major", 0),    # worst
            GiskardIssue("LLMPromptInjectionDetector", "c", "minor", 0),
            GiskardIssue("LLMInfoDisclosureDetector", "d", "medium", 0),
        ])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, **_):
                open(json.load(open(cfg_path))["out"], "w").close()
                return 0, ""
            with patch.object(gadapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(gadapter, "parse_report", return_value=report):
                findings = gadapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        # one finding per detector (not per issue)
        self.assertEqual(len(findings), 2)
        by_pc = {f.ai_payload_class: f for f in findings}
        pi = by_pc["giskard-LLMPromptInjectionDetector"]
        self.assertEqual(pi.severity, "high")        # worst (major) wins, deterministic
        self.assertEqual(pi.ai_trials, 3)            # 3 issues -> trials
        self.assertEqual(by_pc["giskard-LLMInfoDisclosureDetector"].chip, "data-disclosure")

    def test_no_report_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(gadapter, "_invoke", return_value=(1, "crashed")):
                findings = gadapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        self.assertEqual(findings, [])

    def test_invoke_strips_openai_key(self):
        # Egress guard: the giskard subprocess env must not carry OPENAI_API_KEY.
        captured = {}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "leak"}), \
             patch.object(gadapter, "run_streamed") as mrun:
            mrun.return_value = (0, "")
            gadapter._invoke("/tmp/cfg.json")
            captured = mrun.call_args.kwargs["env"]
        self.assertNotIn("OPENAI_API_KEY", captured)

    def test_invoke_passes_timeout_to_run_streamed(self):
        with patch.object(gadapter, "run_streamed", return_value=(0, "")) as mrun:
            gadapter._invoke("/tmp/cfg.json", timeout=1234)
        self.assertEqual(mrun.call_args.kwargs["timeout"], 1234)


if __name__ == "__main__":
    unittest.main(verbosity=2)
