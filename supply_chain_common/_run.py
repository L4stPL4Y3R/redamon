"""Internal subprocess helper shared by the runners.

Always shell=False with a list argv (S6). Strips ANSI. Never raises just
because a tool signalled 'findings present' via a non-zero exit code; the
caller decides what an acceptable exit set is and always parses JSON.
"""

import re
import subprocess

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

DEFAULT_TIMEOUT = 120


def strip_ansi(text):
    return _ANSI_RE.sub("", text or "")


def run_argv(argv, *, timeout=DEFAULT_TIMEOUT, env=None, cwd=None):
    """Run argv (a list) with a timeout. Returns a dict, never raises on a
    non-zero exit or timeout; those surface in the returned fields so the caller
    can still parse whatever stdout was produced.

    Returns: {stdout, stderr, exit_code, timed_out, error}
      - exit_code is None on timeout/spawn failure
      - error is a human string when the run itself failed, else None
    """
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list")
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": strip_ansi(exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout),
            "stderr": "",
            "exit_code": None,
            "timed_out": True,
            "error": "timeout after {}s".format(timeout),
        }
    except (FileNotFoundError, OSError) as exc:
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "timed_out": False,
            "error": "spawn failed: {}".format(exc),
        }
    return {
        "stdout": strip_ansi(proc.stdout),
        "stderr": strip_ansi(proc.stderr),
        "exit_code": proc.returncode,
        "timed_out": False,
        "error": None,
    }
