"""
Guards the gitleaks -> betterleaks migration in the agent's tool docs.

betterleaks is the drop-in gitleaks successor baked into kali-sandbox
(mcp/kali-sandbox/Dockerfile). The agent runs it via kali_shell, so the only
thing that steers it is the command string in the kali_shell tool description.
Two subtle failure modes make a naive command useless, and each has a named
regression test below:

  - F1 (findings discarded on success): betterleaks exits 1 whenever it finds
    secrets. kali_shell's _format_subprocess_result treats a non-zero return
    code as failure and drops stdout, so a scan that finds 50 secrets is
    reported to the agent as "[ERROR] failed: returncode=1" with no findings.
    `--exit-code 0` forces a 0 exit so the JSON survives.
  - F2 (findings never surface): `--report-format json` with no report path
    writes the findings nowhere the agent can read. `--report-path -` streams
    the JSON array to stdout.

Also guards that modern betterleaks/gitleaks uses `git`/`dir`, not the removed
`detect` subcommand.
"""
from __future__ import annotations

import os
import sys
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402


def _kali_shell_doc() -> str:
    entry = TOOL_REGISTRY["kali_shell"]
    desc = entry["description"] if isinstance(entry, dict) else entry
    if isinstance(desc, (tuple, list)):
        return "".join(desc)
    return str(desc)


def _secrets_line() -> str:
    """The single '- **Secrets:** ...' bullet, isolated so assertions about the
    betterleaks command cannot accidentally match some other tool's text."""
    doc = _kali_shell_doc()
    marker = "**Secrets:**"
    assert marker in doc, "kali_shell doc lost its Secrets bullet"
    start = doc.index(marker)
    # bullets are newline-delimited in the registry string
    end = doc.find("\n", start)
    return doc[start: end if end != -1 else len(doc)]


def _betterleaks_command() -> str:
    """The backtick-quoted `betterleaks git ...` command ONLY, not the prose that
    explains it. The prose mentions the same flags, so asserting against the whole
    bullet would pass even if the flags were removed from the actual command (a
    mutation test caught exactly this)."""
    line = _secrets_line()
    needle = "`betterleaks git"
    assert needle in line, "no backtick-quoted `betterleaks git` command in Secrets bullet"
    start = line.index(needle) + 1  # skip opening backtick
    end = line.find("`", start)
    assert end != -1, "unterminated backtick command span"
    return line[start:end]


class TestSecretsScannerIsBetterleaks(unittest.TestCase):
    def test_kali_shell_recommends_betterleaks(self):
        self.assertIn("betterleaks", _secrets_line(),
                      "kali_shell secrets guidance must name betterleaks")

    def test_uses_valid_git_subcommand_not_removed_detect(self):
        line = _secrets_line()
        self.assertIn("betterleaks git", line,
                      "must steer the agent to `betterleaks git <repo>`")
        self.assertNotIn("betterleaks detect", line,
                         "betterleaks (like modern gitleaks) has no `detect` subcommand")
        self.assertNotIn("gitleaks detect", line,
                         "obsolete gitleaks `detect` command must not be resurrected")


class TestBetterleaksCommandSurfacesFindings(unittest.TestCase):
    """Regression tests named after the bugs found in the hardening pass."""

    def test_F1_exit_code_zero_so_findings_are_not_discarded(self):
        # Without --exit-code 0, betterleaks exits 1 on findings and kali_shell
        # reports the successful scan as a failure, dropping every secret.
        # Asserted against the command span, not the prose (prose names the flag too).
        self.assertIn("--exit-code 0", _betterleaks_command(),
                      "F1 regression: betterleaks command must pass --exit-code 0 "
                      "or kali_shell discards stdout on the exit-1 (found-secrets) path")

    def test_F2_report_path_stdout_so_findings_reach_the_agent(self):
        # Without --report-path -, the JSON goes nowhere the agent can read.
        self.assertIn("--report-path -", _betterleaks_command(),
                      "F2 regression: betterleaks command must stream JSON to stdout "
                      "with --report-path - so the agent actually receives findings")

    def test_json_report_format_requested(self):
        self.assertIn("--report-format json", _betterleaks_command())


if __name__ == "__main__":
    unittest.main()
