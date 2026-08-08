"""Unit tests for the CypherFix CodeFix filesystem tools (D1).

These tools have zero tests today. Their import surface is clean
(cypherfix_codefix/__init__.py empty, tools/__init__.py only defines
CODEFIX_TOOLS), so we import via the package path and need no langchain stubbing
- only pydantic + a temp repo. Fixture: a CodeFixState with repo_path = tmpdir.

Named as the guarantees they enforce (README rule 2).

Run: pytest tests/test_cypherfix_fs_tools.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_codefix.state import CodeFixState, DiffBlock
from cypherfix_codefix.tools.read_tool import github_read
from cypherfix_codefix.tools.write_tool import github_write
from cypherfix_codefix.tools.edit_tool import github_edit, _generate_diff_block
from cypherfix_codefix.tools.glob_tool import github_glob
from cypherfix_codefix.tools.list_dir_tool import github_list_dir


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class _FsBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = CodeFixState()
        self.state.repo_path = Path(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, content):
        p = Path(self.tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# github_read
# ---------------------------------------------------------------------------
class TestGithubRead(_FsBase):
    def test_read_returns_line_numbered_output(self):
        self._write("a.py", "first\nsecond\nthird\n")
        out = run(github_read(self.state, "a.py"))
        self.assertIn("1\tfirst", out)
        self.assertIn("2\tsecond", out)
        self.assertIn("3\tthird", out)

    def test_read_tracks_file_as_read(self):
        self._write("a.py", "x\n")
        self.assertNotIn("a.py", self.state.files_read)
        run(github_read(self.state, "a.py"))
        self.assertIn("a.py", self.state.files_read)

    def test_read_offset_and_limit_window(self):
        self._write("a.py", "\n".join(f"line{i}" for i in range(1, 21)) + "\n")
        out = run(github_read(self.state, "a.py", offset=5, limit=3))
        self.assertIn("5\tline5", out)
        self.assertIn("7\tline7", out)
        self.assertNotIn("line8", out)
        # header announces the window when not the whole file
        self.assertIn("showing lines 5-7", out)

    def test_read_missing_file_returns_error_not_raise(self):
        out = run(github_read(self.state, "nope.py"))
        self.assertIn("Error: File not found", out)

    def test_read_binary_file_reports_binary(self):
        (Path(self.tmp) / "b.bin").write_bytes(b"\xff\xfe\x00\x01\x80")
        out = run(github_read(self.state, "b.bin"))
        self.assertIn("binary file", out)

    def test_read_truncates_very_long_line(self):
        self._write("a.py", "x" * 5000 + "\n")
        out = run(github_read(self.state, "a.py"))
        self.assertIn("[LINE TRUNCATED]", out)


# ---------------------------------------------------------------------------
# github_write
# ---------------------------------------------------------------------------
class TestGithubWrite(_FsBase):
    def test_write_creates_file_and_tracks_modified(self):
        out = run(github_write(self.state, "sub/new.py", "hello\nworld\n"))
        self.assertTrue((Path(self.tmp) / "sub" / "new.py").exists())
        self.assertIn("sub/new.py", self.state.files_modified)
        self.assertIn("Successfully wrote", out)

    def test_write_overwrites_existing(self):
        self._write("x.py", "old")
        run(github_write(self.state, "x.py", "new-content"))
        self.assertEqual((Path(self.tmp) / "x.py").read_text(), "new-content")


# ---------------------------------------------------------------------------
# github_edit
# ---------------------------------------------------------------------------
class TestGithubEdit(_FsBase):
    def _prime(self, rel, content):
        self._write(rel, content)
        # edit requires a prior read
        run(github_read(self.state, rel))

    def test_edit_requires_read_before_edit(self):
        self._write("x.py", "abc")
        out = run(github_edit(self.state, "x.py", "abc", "xyz"))
        self.assertIn("must read", out.lower())
        # unchanged on disk
        self.assertEqual((Path(self.tmp) / "x.py").read_text(), "abc")

    def test_edit_rejects_missing_file(self):
        out = run(github_edit(self.state, "nope.py", "a", "b"))
        self.assertIn("File not found", out)

    def test_edit_rejects_non_unique_target_without_replace_all(self):
        self._prime("x.py", "dup\ndup\n")
        out = run(github_edit(self.state, "x.py", "dup", "new"))
        self.assertIn("found 2 times", out)
        # nothing written
        self.assertEqual((Path(self.tmp) / "x.py").read_text(), "dup\ndup\n")

    def test_edit_rejects_identical_old_and_new(self):
        self._prime("x.py", "same")
        out = run(github_edit(self.state, "x.py", "same", "same"))
        self.assertIn("identical", out)

    def test_edit_rejects_absent_old_string(self):
        self._prime("x.py", "abc")
        out = run(github_edit(self.state, "x.py", "zzz", "b"))
        self.assertIn("old_string not found", out)

    def test_edit_single_replacement_appends_diff_block(self):
        self._prime("x.py", "alpha beta gamma")
        out = run(github_edit(self.state, "x.py", "beta", "BETA"))
        self.assertEqual((Path(self.tmp) / "x.py").read_text(), "alpha BETA gamma")
        self.assertIn("x.py", self.state.files_modified)
        self.assertEqual(len(self.state.diff_blocks), 1)
        self.assertIsInstance(self.state.diff_blocks[0], DiffBlock)
        self.assertIn("Successfully replaced 1", out)

    def test_edit_replace_all_replaces_every_occurrence(self):
        self._prime("x.py", "dup\ndup\ndup\n")
        out = run(github_edit(self.state, "x.py", "dup", "new", replace_all=True))
        self.assertEqual((Path(self.tmp) / "x.py").read_text(), "new\nnew\nnew\n")
        self.assertIn("Successfully replaced 3", out)

    def test_edit_streams_diff_block_to_callback(self):
        self._prime("x.py", "alpha beta")
        cb = AsyncMock()
        self.state.streaming_callback = cb
        run(github_edit(self.state, "x.py", "beta", "BETA"))
        cb.on_diff_block.assert_awaited_once()

    def test_edit_sets_pending_approval_when_required(self):
        self._prime("x.py", "alpha beta")
        self.state.settings.require_approval = True
        run(github_edit(self.state, "x.py", "beta", "BETA"))
        self.assertTrue(self.state.pending_approval)
        self.assertEqual(self.state.pending_block_id, self.state.diff_blocks[0].block_id)


class TestGenerateDiffBlock(_FsBase):
    def test_diff_block_captures_line_range_and_language(self):
        content = "l1\nl2\ntarget\nl4\nl5\n"
        new_content = content.replace("target", "changed")
        block = _generate_diff_block(
            "pkg/mod.py", "target", "changed", content, new_content, self.state)
        self.assertEqual(block.language, "python")
        self.assertEqual(block.old_code, "target")
        self.assertEqual(block.new_code, "changed")
        self.assertEqual(block.start_line, 3)
        self.assertEqual(block.end_line, 3)
        self.assertEqual(block.status, "pending")

    def test_diff_block_language_defaults_to_text_for_unknown_ext(self):
        block = _generate_diff_block(
            "notes.xyz", "a", "b", "a\n", "b\n", self.state)
        self.assertEqual(block.language, "text")


# ---------------------------------------------------------------------------
# github_glob / github_list_dir
# ---------------------------------------------------------------------------
class TestGithubGlob(_FsBase):
    def test_glob_finds_matching_files_relative(self):
        self._write("a.py", "")
        self._write("sub/b.py", "")
        self._write("c.txt", "")
        out = run(github_glob(self.state, "**/*.py"))
        self.assertIn("a.py", out)
        self.assertIn(os.path.join("sub", "b.py"), out)
        self.assertNotIn("c.txt", out)

    def test_glob_no_match_message(self):
        out = run(github_glob(self.state, "*.rs"))
        self.assertIn("No files matching", out)

    def test_glob_missing_dir_returns_error(self):
        out = run(github_glob(self.state, "*.py", path="does_not_exist"))
        self.assertIn("Directory not found", out)


class TestGithubListDir(_FsBase):
    def test_list_dir_marks_directories(self):
        self._write("sub/inner.py", "")
        self._write("top.py", "")
        out = run(github_list_dir(self.state, "."))
        self.assertIn("dir  sub", out)
        self.assertIn("top.py", out)

    def test_list_dir_non_directory_returns_error(self):
        self._write("x.py", "")
        out = run(github_list_dir(self.state, "x.py"))
        self.assertIn("Not a directory", out)


if __name__ == "__main__":
    unittest.main()
