"""Unit tests for CypherFix github_grep (D1).

Uses the real ripgrep binary present in the agent image for the happy paths, and
a subprocess.run monkeypatch for the error/timeout branches.

Run: pytest tests/test_cypherfix_grep_tool.py
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_codefix.state import CodeFixState
from cypherfix_codefix.tools import grep_tool
from cypherfix_codefix.tools.grep_tool import github_grep


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@unittest.skipUnless(shutil.which("rg"), "ripgrep (rg) not installed")
class TestGithubGrepReal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = CodeFixState()
        self.state.repo_path = Path(self.tmp)
        (Path(self.tmp) / "a.py").write_text("import os\nDEF find_me = 1\n", encoding="utf-8")
        (Path(self.tmp) / "b.py").write_text("no match here\nfind_me again\n", encoding="utf-8")
        (Path(self.tmp) / "c.txt").write_text("find_me in text\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_files_with_matches_lists_paths_relative(self):
        out = run(github_grep(self.state, "find_me"))
        self.assertIn("a.py", out)
        self.assertIn("b.py", out)
        # relative, not the absolute container path
        self.assertNotIn(self.tmp, out)

    def test_content_mode_shows_line_numbers(self):
        out = run(github_grep(self.state, "find_me", output_mode="content"))
        self.assertRegex(out, r":\d+:")

    def test_count_mode_reports_counts(self):
        out = run(github_grep(self.state, "find_me", output_mode="count"))
        self.assertIn("a.py", out)

    def test_type_filter_restricts_to_python(self):
        out = run(github_grep(self.state, "find_me", type="py"))
        self.assertIn("a.py", out)
        self.assertNotIn("c.txt", out)

    def test_glob_filter_restricts_files(self):
        out = run(github_grep(self.state, "find_me", glob="*.txt"))
        self.assertIn("c.txt", out)
        self.assertNotIn("a.py", out)

    def test_case_insensitive_matches_mixed_case(self):
        out = run(github_grep(self.state, "def find_me", output_mode="content",
                              case_insensitive=True))
        self.assertIn("DEF find_me", out)

    def test_no_match_returns_friendly_message(self):
        out = run(github_grep(self.state, "zzz_never_present_zzz"))
        self.assertIn("No matches found", out)

    def test_head_limit_truncates_and_announces(self):
        for i in range(60):
            (Path(self.tmp) / f"f{i}.py").write_text("find_me\n", encoding="utf-8")
        out = run(github_grep(self.state, "find_me", head_limit=5))
        self.assertIn("truncated", out.lower())


class TestGithubGrepErrorBranches(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = CodeFixState()
        self.state.repo_path = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ripgrep_error_exit_reports_stderr(self):
        class _R:
            returncode = 2
            stdout = ""
            stderr = "rg: regex parse error"
        orig = grep_tool.subprocess.run
        grep_tool.subprocess.run = lambda *a, **k: _R()
        try:
            out = run(github_grep(self.state, "("))
        finally:
            grep_tool.subprocess.run = orig
        self.assertIn("ripgrep failed", out)
        self.assertIn("regex parse error", out)

    def test_timeout_returns_timeout_message(self):
        def _boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="rg", timeout=30)
        orig = grep_tool.subprocess.run
        grep_tool.subprocess.run = _boom
        try:
            out = run(github_grep(self.state, "x"))
        finally:
            grep_tool.subprocess.run = orig
        self.assertIn("timed out", out.lower())


if __name__ == "__main__":
    unittest.main()
