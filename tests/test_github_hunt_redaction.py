#!/usr/bin/env python3
"""I4 — github-hunt must not print harvested secret values to stdout.

Stubs PyGithub so the module imports on a bare host, builds a hunter via
__new__ (no network), and asserts _add_finding prints the banner + non-sensitive
metadata but NEVER the cleartext secret value/sample.

Run: python3 tests/test_github_hunt_redaction.py
"""
import io
import os
import sys
import types
import unittest.mock as mock
from contextlib import redirect_stdout

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Stub PyGithub (github + github.GithubException) so the import guard passes.
_gh = types.ModuleType("github")
_gh.Github = object
_gh.Auth = types.SimpleNamespace(Token=lambda *a, **k: None)
_ghe = types.ModuleType("github.GithubException")
_ghe.RateLimitExceededException = type("RateLimitExceededException", (Exception,), {})
_ghe.GithubException = type("GithubException", (Exception,), {})
_gh.GithubException = _ghe
sys.modules["github"] = _gh
sys.modules["github.GithubException"] = _ghe

sys.path.insert(0, os.path.join(REPO_ROOT, "scanners", "github_secret_hunt"))
import github_secret_hunt as ghh  # noqa: E402

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {desc}")
    else:
        FAIL += 1; print(f"  FAIL {desc}")


def main():
    h = ghh.GitHubSecretHunter.__new__(ghh.GitHubSecretHunter)
    h.findings = []
    h.stats = {"secrets_found": 0, "sensitive_files": 0, "high_entropy": 0}
    h._save_incremental = lambda: None

    SECRET = "AKIAIOSFODNN7EXAMPLE_supersecret"
    buf = io.StringIO()
    with redirect_stdout(buf):
        h._add_finding("SECRET", "victim/repo", "config/.env", "aws_access_key",
                       {"sample": SECRET, "value": SECRET, "line": 42})
    out = buf.getvalue()

    check("banner printed", "SECRET FOUND: aws_access_key" in out)
    check("repository metadata printed", "victim/repo" in out)
    check("non-sensitive detail (line) printed", "line: 42" in out)
    check("secret VALUE not in stdout", SECRET not in out)
    check("sample redacted", "[REDACTED]" in out)
    # on-disk finding dict STILL carries the value (tracker decision).
    check("finding dict retains the value (on-disk unchanged)",
          h.findings and h.findings[0]["details"].get("sample") == SECRET)

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
