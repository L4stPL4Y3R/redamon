"""Unit tests for the garak subprocess runner (the previously-mocked layer).

Asserts the exact CLI we build (TOOL_API.md §1), the judge/key env wiring, the
report.jsonl location logic, and timeout handling. The streaming subprocess
helper (run_streamed) is mocked.
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from adapters.garak import runner
from adapters.garak.runner import _locate_report, run_garak_scan


class TestCommandConstruction(unittest.TestCase):
    def test_cmd_flags_and_env(self):
        with patch.object(runner, "run_streamed") as mrun:
            mrun.return_value = (0, "ok")
            report, rc, tail = run_garak_scan(
                config_path="/cfg.json", probes=["dan", "encoding"],
                generations=3, seed=7, report_prefix="/out/garak_run",
                judge_base_url="http://localhost:11434", api_key="secret")
        cmd = mrun.call_args.args[0]
        # cmd[0] is the garak venv interpreter (GARAK_PYTHON), "python" in dev.
        self.assertEqual(cmd[0], runner.GARAK_PYTHON)
        self.assertEqual(cmd[1:3], ["-m", "garak"])
        self.assertEqual(cmd[cmd.index("--model_type") + 1], "rest")
        self.assertEqual(cmd[cmd.index("--generator_option_file") + 1], "/cfg.json")
        self.assertEqual(cmd[cmd.index("--probes") + 1], "dan,encoding")
        self.assertEqual(cmd[cmd.index("--generations") + 1], "3")
        self.assertEqual(cmd[cmd.index("--seed") + 1], "7")
        self.assertEqual(cmd[cmd.index("--report_prefix") + 1], "/out/garak_run")
        env = mrun.call_args.kwargs["env"]
        self.assertEqual(env["REST_API_KEY"], "secret")
        self.assertTrue(env["OPENAI_API_BASE"].endswith("/v1"))
        self.assertEqual(rc, 0)

    def test_parallel_attempts_flows_to_cli(self):
        with patch.object(runner, "run_streamed") as mrun:
            mrun.return_value = (0, "")
            run_garak_scan("/c.json", ["dan"], 1, 0, "/out/g", parallel_attempts=2)
        cmd = mrun.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--parallel_attempts") + 1], "2")

    def test_timeout_flows_to_run_streamed(self):
        with patch.object(runner, "run_streamed") as mrun:
            mrun.return_value = (0, "")
            run_garak_scan("/c.json", ["dan"], 1, 0, "/out/g", timeout=1234)
        self.assertEqual(mrun.call_args.kwargs["timeout"], 1234)

    def test_no_key_no_rest_api_key_env(self):
        with patch.object(runner, "run_streamed") as mrun:
            mrun.return_value = (0, "")
            run_garak_scan("/c.json", ["dan"], 1, 0, "/out/g")
        env = mrun.call_args.kwargs["env"]
        self.assertNotIn("REST_API_KEY", env)
        self.assertNotIn("OPENAI_API_BASE", env)  # no judge_base_url given

    def test_timeout_returns_rc_minus_one(self):
        # run_streamed owns the timeout now; it returns (-1, "...TIMEOUT...").
        with patch.object(runner, "run_streamed", return_value=(-1, "TIMEOUT after 1s")):
            report, rc, tail = run_garak_scan("/c.json", ["dan"], 1, 0, "/out/g", timeout=1)
        self.assertEqual(rc, -1)
        self.assertIn("TIMEOUT", tail)

    def test_inactive_families_are_dropped_and_run_retries(self):
        # First call: garak aborts because doctor+donotanswer are inactive.
        # Second call: it must retry with ONLY the active families and succeed.
        inactive_msg = ("garak ... ❌ all probes in 'doctor,donotanswer' are marked "
                        "inactive; select one or more by name to continue")
        with patch.object(runner, "run_streamed",
                          side_effect=[(0, inactive_msg), (0, "ok")]) as mrun, \
             patch.object(runner, "_locate_report",
                          side_effect=[None, "/out/g.report.jsonl"]):
            report, rc, tail = run_garak_scan(
                "/c.json", ["promptinject", "dan", "doctor", "donotanswer", "lmrc"],
                1, 0, "/out/g")
        self.assertEqual(mrun.call_count, 2)
        # retry CLI must contain the active families and NOT the inactive ones
        retry_probes = mrun.call_args_list[1].args[0][
            mrun.call_args_list[1].args[0].index("--probes") + 1]
        self.assertEqual(retry_probes, "promptinject,dan,lmrc")
        self.assertEqual(report, "/out/g.report.jsonl")

    def test_all_inactive_does_not_loop_forever(self):
        # If EVERY selected family is inactive, drop them, don't retry endlessly.
        msg = "❌ all probes in 'doctor,donotanswer' are marked inactive"
        with patch.object(runner, "run_streamed", return_value=(0, msg)) as mrun, \
             patch.object(runner, "_locate_report", return_value=None):
            report, rc, tail = run_garak_scan(
                "/c.json", ["doctor", "donotanswer"], 1, 0, "/out/g")
        self.assertIsNone(report)
        self.assertEqual(mrun.call_count, 1)  # nothing left to retry with


class TestLocateReport(unittest.TestCase):
    def test_exact_path(self):
        with tempfile.TemporaryDirectory() as d:
            prefix = os.path.join(d, "garak_run")
            exact = prefix + ".report.jsonl"
            open(exact, "w").close()
            self.assertEqual(_locate_report(prefix), exact)

    def test_glob_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            other = os.path.join(d, "garak.abc123.report.jsonl")
            open(other, "w").close()
            # exact <prefix>.report.jsonl missing -> glob finds the other one
            self.assertEqual(_locate_report(os.path.join(d, "garak_run")), other)

    def test_none_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(_locate_report(os.path.join(d, "garak_run")))

    def test_run_returns_none_report_when_no_file(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(runner, "run_streamed") as mrun:
            mrun.return_value = (0, "")
            report, rc, tail = run_garak_scan("/c.json", ["dan"], 1, 0,
                                              os.path.join(d, "garak_run"))
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
