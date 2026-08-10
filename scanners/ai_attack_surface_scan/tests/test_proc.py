"""Unit tests for proc.run_streamed (the live-streaming subprocess helper)."""
import io
import time
import unittest
from contextlib import redirect_stdout

from proc import run_streamed


class TestRunStreamed(unittest.TestCase):
    def test_streams_lines_and_returns_tail(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            # \r (tqdm-style redraw) must be treated as a line break too
            rc, tail = run_streamed(["sh", "-c", "printf 'alpha\\nbeta\\rgamma\\n'"],
                                    tag="t", throttle=0)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        for token in ("alpha", "beta", "gamma"):
            self.assertIn(token, out)      # streamed live
            self.assertIn(token, tail)     # captured in the tail
        self.assertIn("[t]", out)          # tagged

    def test_nonzero_exit_code_propagates(self):
        with redirect_stdout(io.StringIO()):
            rc, tail = run_streamed(["sh", "-c", "echo boom; exit 7"], tag="t", throttle=0)
        self.assertEqual(rc, 7)
        self.assertIn("boom", tail)

    def test_timeout_kills_and_returns_minus_one(self):
        start = time.monotonic()
        with redirect_stdout(io.StringIO()):
            rc, tail = run_streamed(["sh", "-c", "sleep 10"], timeout=1, tag="t")
        elapsed = time.monotonic() - start
        self.assertEqual(rc, -1)
        self.assertIn("TIMEOUT", tail)
        self.assertLess(elapsed, 5)        # enforced even though the child was silent

    def test_captured_tail_is_bounded(self):
        with redirect_stdout(io.StringIO()):
            rc, tail = run_streamed(["sh", "-c", "for i in $(seq 1 500); do echo line$i; done"],
                                    tag="t", throttle=0)
        self.assertEqual(rc, 0)
        # tail keeps only the last lines (bounded), so early lines are dropped
        self.assertIn("line500", tail)
        self.assertNotIn("line1\n", tail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
