"""Unit tests for the garak adapter (Step 4).

Pure-Python: the parser/rest_config/owasp_map have no heavy deps, and the
adapter test mocks the garak subprocess + parser. Run from the spine root:

    cd ai_attack_surface_scan && python -m unittest \
        adapters.garak.tests.test_garak_adapter -v

The parser is anchored on a REAL captured garak 0.15.1 report
(tests/fixtures/garak_test_report.jsonl) plus synthetic eval rows for the ASR math.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from config import Bounds
from target_loader import Target

from adapters.garak import adapter as gadapter
from adapters.garak.owasp_map import PROBE_FAMILY_MAP, family_of, map_family
from adapters.garak.parser import FamilyResult, GarakReport, parse_report
from adapters.garak.rest_config import build_rest_config

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "garak_test_report.jsonl")


# --------------------------------------------------------------------------- #
# Parser — against the REAL captured artifact
# --------------------------------------------------------------------------- #

class TestParserRealFixture(unittest.TestCase):
    def test_parses_version_and_family(self):
        r = parse_report(FIXTURE)
        self.assertEqual(r.garak_version, "0.15.1")
        fams = {f.family: f for f in r.families}
        self.assertIn("test", fams)
        self.assertEqual(fams["test"].asr, 0.0)        # always.Pass -> 0 fails
        self.assertEqual(fams["test"].trials, 8)
        self.assertEqual(fams["test"].top_detector, "always.Pass")

    def test_attempt_entries_are_skipped(self):
        # 16 attempt rows in the fixture must not become families.
        r = parse_report(FIXTURE)
        self.assertEqual(len(r.families), 1)  # only the single eval -> one family


# --------------------------------------------------------------------------- #
# Parser — synthetic ASR math
# --------------------------------------------------------------------------- #

class TestParserAsrMath(unittest.TestCase):
    def _write(self, rows):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        self.addCleanup(os.unlink, path)
        return path

    def test_family_uses_worst_detector_and_groups(self):
        path = self._write([
            {"entry_type": "init", "garak_version": "0.15.1"},
            {"entry_type": "eval", "probe": "promptinject.A", "detector": "d1",
             "passed": 6, "fails": 4, "nones": 0, "total_evaluated": 10},
            {"entry_type": "eval", "probe": "promptinject.A", "detector": "d2",
             "passed": 9, "fails": 1, "nones": 0, "total_evaluated": 10},
            {"entry_type": "eval", "probe": "encoding.InjectBase64", "detector": "decode",
             "passed": 2, "fails": 8, "nones": 0, "total_evaluated": 10},
            {"entry_type": "attempt", "uuid": "x", "status": 2},  # skipped
        ])
        r = parse_report(path)
        fams = {f.family: f for f in r.families}
        self.assertEqual(set(fams), {"promptinject", "encoding"})
        # promptinject: worst detector is d1 (4/10), not d2 (1/10)
        self.assertAlmostEqual(fams["promptinject"].asr, 0.4)
        self.assertEqual(fams["promptinject"].top_detector, "d1")
        self.assertEqual(len(fams["promptinject"].detectors), 2)
        self.assertAlmostEqual(fams["encoding"].asr, 0.8)
        # families sorted by ASR desc
        self.assertEqual(r.families[0].family, "encoding")

    def test_zero_total_evaluated_is_zero_asr(self):
        path = self._write([
            {"entry_type": "eval", "probe": "dan.X", "detector": "d",
             "passed": 0, "fails": 0, "nones": 0, "total_evaluated": 0},
        ])
        r = parse_report(path)
        self.assertEqual(r.families[0].asr, 0.0)

    def test_seed_from_flat_dotted_key(self):
        path = self._write([
            {"entry_type": "start_run setup", "run.seed": 42},
            {"entry_type": "eval", "probe": "dan.X", "detector": "d",
             "passed": 1, "fails": 1, "nones": 0, "total_evaluated": 2},
        ])
        self.assertEqual(parse_report(path).seed, 42)


# --------------------------------------------------------------------------- #
# REST config builder
# --------------------------------------------------------------------------- #

class TestRestConfig(unittest.TestCase):
    def _cfg(self, path, iface="llm-chat", model="m"):
        t = Target(baseurl="http://h:8000", path=path, method="POST",
                   ai_interface_type=iface, ai_model_ids=[model])
        return build_rest_config(t, model=model)["rest"]["RestGenerator"]

    def test_openai_chat_shape(self):
        c = self._cfg("/v1/chat/completions")
        self.assertEqual(c["uri"], "http://h:8000/v1/chat/completions")
        self.assertEqual(c["response_json_field"], "$.choices[0].message.content")
        self.assertEqual(c["req_template_json_object"]["messages"][0]["content"], "$INPUT")
        self.assertTrue(c["response_json"])

    def test_ollama_chat_shape(self):
        c = self._cfg("/api/chat")
        self.assertEqual(c["response_json_field"], "$.message.content")
        self.assertFalse(c["req_template_json_object"]["stream"])

    def test_ollama_generate_shape(self):
        c = self._cfg("/api/generate")
        self.assertEqual(c["response_json_field"], "$.response")
        self.assertEqual(c["req_template_json_object"]["prompt"], "$INPUT")

    def test_anthropic_shape(self):
        c = self._cfg("/v1/messages")
        self.assertEqual(c["response_json_field"], "$.content[0].text")

    def test_response_is_token_capped(self):
        # Every family must bound the victim's reply so a runaway generation
        # can't blow past request_timeout and crash the run. OpenAI-compat APIs
        # use max_tokens; native Ollama uses options.num_predict.
        for path in ("/v1/chat/completions", "/v1/completions", "/v1/messages"):
            body = self._cfg(path)["req_template_json_object"]
            self.assertEqual(body.get("max_tokens"), 512, f"{path} missing max_tokens")
        for path in ("/api/chat", "/api/generate"):
            body = self._cfg(path)["req_template_json_object"]
            self.assertEqual(body.get("options", {}).get("num_predict"), 512,
                             f"{path} missing options.num_predict")

    def test_bearer_auth_header(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions")
        c = build_rest_config(t, model="m", auth_header="Authorization", auth_scheme="Bearer")["rest"]["RestGenerator"]
        self.assertEqual(c["headers"]["Authorization"], "Bearer $KEY")

    def test_custom_header_auth_no_scheme(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions")
        c = build_rest_config(t, model="m", auth_header="x-api-key", auth_scheme="")["rest"]["RestGenerator"]
        self.assertEqual(c["headers"]["x-api-key"], "$KEY")  # raw key, no scheme

    def test_no_auth_omits_header(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions")
        c = build_rest_config(t, model="m")["rest"]["RestGenerator"]
        self.assertEqual(list(c["headers"].keys()), ["Content-Type"])

    def test_nesting_is_rest_RestGenerator(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions")
        cfg = build_rest_config(t, model="m")
        self.assertIn("rest", cfg)
        self.assertIn("RestGenerator", cfg["rest"])

    def test_model_from_list(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions", ai_model_ids=["qwen2.5:7b"])
        c = build_rest_config(t)["rest"]["RestGenerator"]
        self.assertEqual(c["req_template_json_object"]["model"], "qwen2.5:7b")

    def test_model_id_as_bare_string_not_sliced(self):
        # Regression: a string ai_model_ids must not become its first character.
        t = Target(baseurl="http://h", path="/v1/chat/completions")
        t.ai_model_ids = "qwen"  # not a list
        c = build_rest_config(t)["rest"]["RestGenerator"]
        self.assertEqual(c["req_template_json_object"]["model"], "qwen")

    def test_model_falls_back_to_family_guess(self):
        t = Target(baseurl="http://h", path="/v1/chat/completions",
                   ai_model_ids=None, ai_model_family_guess="llama")
        c = build_rest_config(t)["rest"]["RestGenerator"]
        self.assertEqual(c["req_template_json_object"]["model"], "llama")


# --------------------------------------------------------------------------- #
# OWASP map
# --------------------------------------------------------------------------- #

class TestOwaspMap(unittest.TestCase):
    def test_family_of(self):
        self.assertEqual(family_of("promptinject.HijackHateHumans"), "promptinject")
        self.assertEqual(family_of("encoding.InjectBase64"), "encoding")

    def test_known_families(self):
        self.assertEqual(map_family("promptinject")[0], "LLM01")
        self.assertEqual(map_family("leakreplay")[0], "LLM02")
        self.assertEqual(map_family("dan")[1], "jailbreak")

    def test_unknown_family_defaults(self):
        self.assertEqual(map_family("totallynew"), ("LLM01", "prompt-injection", "classifier"))

    # Full garak 0.15.1 family catalog now selectable from the UI: every one must
    # be classified (else its findings fall back to the LLM01/prompt-injection
    # default). This list mirrors webapp/src/lib/aiAttackSurface.ts GARAK_CARD
    # (minus the no-op `test` smoke probe).
    UI_FAMILIES = {
        "promptinject", "dan", "encoding", "leakreplay",
        "latentinjection", "goodside", "agent_breaker",
        "doctor", "grandma", "dra", "fitd", "phrasing", "suffix", "tap",
        "goat", "glitch", "sata", "audio", "visual_jailbreak",
        "sysprompt_extraction", "apikey", "propile", "divergence",
        "smuggling", "realtoxicityprompts", "lmrc", "continuation",
        "donotanswer", "atkgen", "topic", "malwaregen", "exploitation",
        "av_spam_scanning", "fileformats", "ansiescape", "web_injection",
        "badchars", "packagehallucination", "misleading", "snowball",
    }

    def test_full_garak_catalog_is_mapped(self):
        self.assertEqual(len(self.UI_FAMILIES), 40)
        missing = self.UI_FAMILIES - set(PROBE_FAMILY_MAP)
        self.assertEqual(missing, set(), f"unmapped families: {sorted(missing)}")

    def test_all_map_entries_have_valid_shape(self):
        valid_chips = {
            "prompt-injection", "jailbreak", "system-prompt-leak",
            "data-disclosure", "encoding-bypass", "toxicity", "bias",
            "hallucination", "harmful-generation", "insecure-output",
            "supply-chain",
        }
        valid_oracles = {"classifier", "contains", "judge_llm"}
        for fam, entry in PROBE_FAMILY_MAP.items():
            self.assertEqual(len(entry), 3, f"{fam} entry not a 3-tuple")
            owasp, chip, oracle = entry
            self.assertRegex(owasp, r"^(LLM\d{2}|safety)$", f"{fam} owasp={owasp}")
            self.assertIn(chip, valid_chips, f"{fam} chip={chip}")
            self.assertIn(oracle, valid_oracles, f"{fam} oracle={oracle}")

    def test_new_family_mappings(self):
        self.assertEqual(map_family("sysprompt_extraction"),
                         ("LLM07", "system-prompt-leak", "contains"))
        self.assertEqual(map_family("packagehallucination")[1], "supply-chain")
        self.assertEqual(map_family("web_injection")[1], "insecure-output")
        self.assertEqual(map_family("malwaregen")[1], "harmful-generation")
        self.assertEqual(map_family("exploitation")[0], "LLM05")


# --------------------------------------------------------------------------- #
# Adapter — Finding construction (garak subprocess + parser mocked)
# --------------------------------------------------------------------------- #

class TestAdapterFindings(unittest.TestCase):
    def _target(self):
        return Target(baseurl="http://h:8000", path="/v1/chat/completions",
                      method="POST", ai_interface_type="llm-chat", ai_model_ids=["qwen"])

    def test_threshold_filters_and_maps(self):
        report = GarakReport(garak_version="0.15.1", families=[
            FamilyResult(family="encoding", asr=0.8, trials=10, hits=8,
                         top_probe="encoding.InjectBase64", top_detector="decode"),
            FamilyResult(family="promptinject", asr=0.1, trials=10, hits=1,
                         top_probe="promptinject.A", top_detector="d1"),
        ])
        with tempfile.TemporaryDirectory() as d, \
             patch.object(gadapter, "run_garak_scan",
                          return_value=(os.path.join(d, "r.report.jsonl"), 0, "")), \
             patch.object(gadapter, "parse_report", return_value=report):
            findings = gadapter.run(self._target(), Bounds(trials=10, asr_threshold=0.3),
                                    output_dir=d, run_id="t1")
        # Only encoding (0.8 >= 0.3); promptinject (0.1) filtered out.
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, "garak")
        self.assertEqual(f.chip, "encoding-bypass")
        self.assertEqual(f.ai_owasp_llm_id, "LLM01")
        self.assertEqual(f.ai_payload_class, "garak-encoding")
        self.assertEqual(f.ai_trials, 10)
        self.assertEqual(f.severity, "high")
        self.assertIn("garak/0.15.1", f.ai_probe_pack_version)

    def test_no_report_returns_empty(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(gadapter, "run_garak_scan", return_value=(None, 1, "boom")):
            findings = gadapter.run(self._target(), Bounds(), output_dir=d, run_id="t1")
        self.assertEqual(findings, [])

    def test_explicit_seed_zero_is_honored(self):
        # bounds.seed=0 must reach garak even when the env default seed is non-zero.
        captured = {}

        def fake_scan(*a, **k):
            captured.update(k)
            return (None, 1, "")
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, {"AI_ATTACK_GARAK_SEED": "99"}), \
             patch.object(gadapter, "run_garak_scan", side_effect=fake_scan):
            gadapter.run(self._target(), Bounds(seed=0), output_dir=d, run_id="t1")
        self.assertEqual(captured["seed"], 0)


class TestRunnerEgress(unittest.TestCase):
    """The garak subprocess must never inherit a hosted OPENAI_API_KEY."""
    def test_openai_key_stripped_and_judge_forced(self):
        from adapters.garak import runner
        captured = {}

        def fake_stream(cmd, env=None, **k):
            captured["env"] = env
            return (0, "")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-LEAK", "OPENAI_API_BASE": "https://api.openai.com/v1"}), \
             patch.object(runner, "run_streamed", side_effect=fake_stream):
            runner.run_garak_scan(config_path="/x.json", probes=["dan"], generations=1,
                                  seed=0, report_prefix="/tmp/none/x",
                                  judge_base_url="http://o:11434")
        env = captured["env"]
        self.assertEqual(env.get("OPENAI_API_KEY"), "ollama-local")
        self.assertEqual(env.get("OPENAI_API_BASE"), "http://o:11434/v1")
        self.assertNotIn("sk-LEAK", list(env.values()))

    def test_openai_key_stripped_even_with_no_judge(self):
        from adapters.garak import runner
        captured = {}

        def fake_stream(cmd, env=None, **k):
            captured["env"] = env
            return (0, "")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-LEAK"}), \
             patch.object(runner, "run_streamed", side_effect=fake_stream):
            runner.run_garak_scan(config_path="/x.json", probes=["dan"], generations=1,
                                  seed=0, report_prefix="/tmp/none/x", judge_base_url=None)
        self.assertNotIn("OPENAI_API_KEY", captured["env"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
