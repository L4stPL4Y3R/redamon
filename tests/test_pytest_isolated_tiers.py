"""The gate must honour an in-file tier marker, not just the filename.

`pytest_isolated.py` picks FILES by name, which cannot see a single test inside a
unit-named file that has opted out with `@pytest.mark.integration`. The gate ran
such a test anyway - a wall-clock assertion in recon/tests/test_vhost_sni_stress.py
that its own comment says is not hermetic - so the unit gate failed intermittently
depending on how loaded the host was under the parallel run.
"""
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "tooling/scripts/pytest_isolated.py"

# Mirrors the tier auto-marking every section conftest.py performs, so the temp
# project behaves like a real section: unmarked tests land in the unit tier.
CONFTEST = """
_TIERS = {"unit", "integration", "live"}


def pytest_collection_modifyitems(config, items):
    for item in items:
        if _TIERS & {m.name for m in item.iter_markers()}:
            continue
        item.add_marker("unit")
"""

TEST_FILE = """
import pathlib
import pytest

OUT = pathlib.Path(__file__).parent


def test_plain_unit_test():
    (OUT / "plain.ran").write_text("yes")


@pytest.mark.integration
def test_opted_out_of_the_unit_tier():
    (OUT / "marked.ran").write_text("yes")
"""


class IsolatedRunnerTierTest(unittest.TestCase):
    def _run(self, tier):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "conftest.py").write_text(textwrap.dedent(CONFTEST))
            (d / "test_sample.py").write_text(textwrap.dedent(TEST_FILE))
            proc = subprocess.run(
                [sys.executable, str(RUNNER), tier, str(d)],
                capture_output=True, text=True, cwd=tmp, timeout=180,
            )
            return proc, (d / "plain.ran").exists(), (d / "marked.ran").exists()

    def test_unit_tier_skips_a_test_marked_integration(self):
        proc, plain_ran, marked_ran = self._run("unit")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(plain_ran, "the unmarked test must still run")
        self.assertFalse(marked_ran,
                         "a test marked integration must not run in the unit gate")

    def test_the_integration_tier_still_runs_it(self):
        """Opting out of the unit tier must not mean never running at all."""
        proc, plain_ran, marked_ran = self._run("all")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(marked_ran, "`all` covers unit+integration, so it must run")

    def test_every_tier_has_a_marker_expression(self):
        sys.path.insert(0, str(RUNNER.parent))
        try:
            import pytest_isolated
        finally:
            sys.path.pop(0)
        # The argparse choices and the expression table must not drift apart:
        # a missing key would raise KeyError mid-gate.
        self.assertEqual(set(pytest_isolated._MARKEXPR), {"unit", "integration", "live", "all"})
        self.assertEqual(pytest_isolated._MARKEXPR["all"], "unit or integration")


if __name__ == "__main__":
    unittest.main()
