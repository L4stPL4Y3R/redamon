"""Unit tests for the L1 GitHub clone input (supply_chain_scan/repo_clone.py).

The repository coordinate is operator-supplied and becomes a `git clone`
argument inside the scan container, so the charset gate and the credential
handling are security controls, not conveniences.

Run: python -m unittest tests.test_supply_chain_repo_clone
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from supply_chain_scan.repo_clone import (   # noqa: E402
    parse_repo, parse_repo_target, clone_repo, RepoCloneError, _validate_ref,
)

_GHE = "ghe.example.com"


class TestParseRepo(unittest.TestCase):
    def test_owner_repo_shorthand(self):
        self.assertEqual(parse_repo("DataDog/guarddog"), ("DataDog", "guarddog"))

    def test_https_url(self):
        self.assertEqual(parse_repo("https://github.com/DataDog/guarddog"),
                         ("DataDog", "guarddog"))

    def test_url_with_dot_git_and_trailing_slash(self):
        self.assertEqual(parse_repo("https://github.com/owner/repo.git"),
                         ("owner", "repo"))
        self.assertEqual(parse_repo("https://github.com/owner/repo/"),
                         ("owner", "repo"))

    def test_dots_and_dashes_in_repo_name_are_fine(self):
        self.assertEqual(parse_repo("my-org/my.repo_name-2"),
                         ("my-org", "my.repo_name-2"))

    # -- rejections ---------------------------------------------------------

    def test_rejects_non_github_host(self):
        """Only github.com. An arbitrary host would let the scan container be
        pointed at an internal git server (SSRF via the clone)."""
        for url in ("https://gitlab.com/o/r",
                    "https://github.com.evil.tld/o/r",
                    "https://internal.corp/o/r"):
            with self.assertRaises(RepoCloneError, msg=url):
                parse_repo(url)

    def test_rejects_plain_http(self):
        with self.assertRaises(RepoCloneError):
            parse_repo("http://github.com/o/r")

    def test_rejects_credentials_in_the_url(self):
        """A token pasted into the field must not be silently persisted."""
        with self.assertRaises(RepoCloneError):
            parse_repo("https://user:ghp_secret@github.com/o/r")

    def test_rejects_path_traversal(self):
        for value in ("../../etc/passwd", "owner/../../x", "owner/..",
                      "https://github.com/owner/../../x"):
            with self.assertRaises(RepoCloneError, msg=value):
                parse_repo(value)

    def test_rejects_shell_metacharacters(self):
        for value in ("owner/repo;whoami", "owner/`id`", "owner/repo$(id)",
                      "owner/repo|cat", "owner/re po"):
            with self.assertRaises(RepoCloneError, msg=value):
                parse_repo(value)

    def test_rejects_leading_dash_owner(self):
        """A leading '-' would be read by git as an option, not a path."""
        with self.assertRaises(RepoCloneError):
            parse_repo("-oProxyCommand=id/repo")

    def test_rejects_wrong_arity(self):
        for value in ("justowner", "a/b/c", "", "   "):
            with self.assertRaises(RepoCloneError, msg=repr(value)):
                parse_repo(value)

    def test_rejects_non_string_and_oversized(self):
        with self.assertRaises(RepoCloneError):
            parse_repo(None)
        with self.assertRaises(RepoCloneError):
            parse_repo("o/" + "r" * 400)

    def test_rejects_query_and_fragment(self):
        for value in ("https://github.com/o/r?x=1", "https://github.com/o/r#f"):
            with self.assertRaises(RepoCloneError, msg=value):
                parse_repo(value)


class TestValidateRef(unittest.TestCase):
    def test_accepts_ordinary_refs(self):
        for ref in ("main", "v1.2.3", "release/2026-01", "a" * 40):
            self.assertEqual(_validate_ref(ref), ref)

    def test_empty_means_default_branch(self):
        self.assertIsNone(_validate_ref(""))
        self.assertIsNone(_validate_ref(None))
        self.assertIsNone(_validate_ref("   "))

    def test_rejects_option_lookalike(self):
        with self.assertRaises(RepoCloneError):
            _validate_ref("--upload-pack=id")

    def test_rejects_git_revision_syntax(self):
        for ref in ("a..b", "main@{1}", "main.lock"):
            with self.assertRaises(RepoCloneError, msg=ref):
                _validate_ref(ref)

    def test_rejects_metacharacters(self):
        for ref in ("main;id", "main`id`", "main x"):
            with self.assertRaises(RepoCloneError, msg=ref):
                _validate_ref(ref)


class _FakeProc:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


class TestCloneArgvAndCredentials(unittest.TestCase):
    """The clone is never executed here; only what it would be asked to do."""

    def setUp(self):
        self.calls = []
        self.tmp = tempfile.mkdtemp(prefix="sc-clone-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _runner(self, returncode=0, stderr="", make_dest=True):
        def run(argv, env=None, capture_output=None, text=None, timeout=None):
            self.calls.append({"argv": argv, "env": env or {}})
            if make_dest and returncode == 0:
                os.makedirs(argv[-1], exist_ok=True)
                with open(os.path.join(argv[-1], "package-lock.json"), "w") as fh:
                    fh.write("{}")
            return _FakeProc(returncode, stderr)
        return run

    def test_url_is_rebuilt_from_validated_parts(self):
        dest = clone_repo("https://github.com/Owner/Repo.git",
                          dest_parent=self.tmp, runner=self._runner())
        argv = self.calls[0]["argv"]
        self.assertIn("https://github.com/Owner/Repo.git", argv)
        self.assertTrue(os.path.isdir(dest))

    def test_clone_is_shallow_and_submodule_free(self):
        clone_repo("o/r", dest_parent=self.tmp, runner=self._runner())
        argv = self.calls[0]["argv"]
        self.assertEqual(argv[argv.index("--depth") + 1], "1")
        self.assertIn("--single-branch", argv)
        self.assertIn("--recurse-submodules=no", argv)
        self.assertIn("--no-tags", argv)

    def test_token_never_appears_in_argv(self):
        """argv is world-readable via /proc to anything in the PID namespace."""
        clone_repo("o/r", token="ghp_supersecret", dest_parent=self.tmp,
                   runner=self._runner())
        argv = self.calls[0]["argv"]
        self.assertNotIn("ghp_supersecret", " ".join(argv))

    def test_token_never_appears_in_the_remote_url(self):
        """git writes the remote URL into .git/config, so a credentialed URL
        would be persisted to disk and shipped with the checkout."""
        clone_repo("o/r", token="ghp_supersecret", dest_parent=self.tmp,
                   runner=self._runner())
        url = [a for a in self.calls[0]["argv"] if a.startswith("https://")][0]
        self.assertNotIn("ghp_supersecret", url)
        self.assertNotIn("@", url.replace("https://", ""))

    def test_token_is_passed_through_askpass(self):
        clone_repo("o/r", token="ghp_supersecret", dest_parent=self.tmp,
                   runner=self._runner())
        env = self.calls[0]["env"]
        self.assertTrue(env.get("GIT_ASKPASS", "").endswith("askpass.sh"))
        self.assertEqual(env.get("SC_GIT_TOKEN"), "ghp_supersecret")

    def test_no_askpass_when_there_is_no_token(self):
        clone_repo("o/r", dest_parent=self.tmp, runner=self._runner())
        self.assertNotIn("GIT_ASKPASS", self.calls[0]["env"])

    def test_terminal_prompt_disabled(self):
        """Without this a private repo with no token blocks forever on a
        terminal read instead of failing the scan."""
        clone_repo("o/r", dest_parent=self.tmp, runner=self._runner())
        self.assertEqual(self.calls[0]["env"].get("GIT_TERMINAL_PROMPT"), "0")

    def test_lfs_smudge_disabled(self):
        clone_repo("o/r", dest_parent=self.tmp, runner=self._runner())
        self.assertEqual(self.calls[0]["env"].get("GIT_LFS_SKIP_SMUDGE"), "1")

    def test_ref_is_passed_as_branch(self):
        clone_repo("o/r", ref="release/2026-01", dest_parent=self.tmp,
                   runner=self._runner())
        argv = self.calls[0]["argv"]
        self.assertEqual(argv[argv.index("--branch") + 1], "release/2026-01")

    def test_hostile_ref_never_reaches_git(self):
        with self.assertRaises(RepoCloneError):
            clone_repo("o/r", ref="--upload-pack=id", dest_parent=self.tmp,
                       runner=self._runner())
        self.assertEqual(self.calls, [], "git must not be invoked at all")

    def test_askpass_helper_is_removed_before_the_analyzer_sees_the_tree(self):
        dest = clone_repo("o/r", token="t", dest_parent=self.tmp,
                          runner=self._runner())
        self.assertFalse(
            os.path.exists(os.path.join(os.path.dirname(dest), "askpass.sh")))

    def test_dot_git_is_stripped(self):
        def run(argv, env=None, **kw):
            self.calls.append({"argv": argv, "env": env or {}})
            os.makedirs(os.path.join(argv[-1], ".git"), exist_ok=True)
            return _FakeProc(0)
        dest = clone_repo("o/r", dest_parent=self.tmp, runner=run)
        self.assertFalse(os.path.exists(os.path.join(dest, ".git")),
                         ".git holds the object store and the remote config")

    def test_failure_is_an_error_not_an_empty_scan(self):
        """A clone that did not happen must never look like a repository with
        no dependencies."""
        with self.assertRaises(RepoCloneError) as ctx:
            clone_repo("o/r", dest_parent=self.tmp,
                       runner=self._runner(returncode=128, stderr="not found"))
        self.assertIn("not found", str(ctx.exception))

    def test_token_is_scrubbed_from_a_failure_message(self):
        with self.assertRaises(RepoCloneError) as ctx:
            clone_repo("o/r", token="ghp_leaky", dest_parent=self.tmp,
                       runner=self._runner(returncode=128,
                                           stderr="auth failed for ghp_leaky"))
        self.assertNotIn("ghp_leaky", str(ctx.exception))

    def test_scratch_is_removed_on_failure(self):
        before = set(os.listdir(self.tmp))
        with self.assertRaises(RepoCloneError):
            clone_repo("o/r", dest_parent=self.tmp,
                       runner=self._runner(returncode=1))
        self.assertEqual(set(os.listdir(self.tmp)), before,
                         "a failed clone must not leak its scratch directory")

    def test_oversized_repository_is_rejected(self):
        def run(argv, env=None, **kw):
            os.makedirs(argv[-1], exist_ok=True)
            with open(os.path.join(argv[-1], "big.bin"), "wb") as fh:
                fh.write(b"\0" * 4096)
            return _FakeProc(0)
        with self.assertRaises(RepoCloneError) as ctx:
            clone_repo("o/r", dest_parent=self.tmp, max_bytes=1024, runner=run)
        self.assertIn("limit", str(ctx.exception))

    def test_timeout_is_reported_not_swallowed(self):
        def run(argv, env=None, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        with self.assertRaises(RepoCloneError) as ctx:
            clone_repo("o/r", dest_parent=self.tmp, runner=run)
        self.assertIn("timed out", str(ctx.exception))


class TestEnterpriseHost(unittest.TestCase):
    """A GitHub Enterprise host is honoured, but ONLY when the operator's
    settings named it. This container re-checks the host because it must never
    trust a value that reached it over HTTP."""

    def setUp(self):
        self.calls = []
        self.tmp = tempfile.mkdtemp(prefix="sc-ghe-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _runner(self):
        def run(argv, env=None, capture_output=None, text=None, timeout=None):
            self.calls.append({"argv": argv, "env": env or {}})
            os.makedirs(argv[-1], exist_ok=True)
            with open(os.path.join(argv[-1], "package-lock.json"), "w") as fh:
                fh.write("{}")
            return _FakeProc(0)
        return run

    def test_default_host_is_github_com(self):
        self.assertEqual(parse_repo_target("o/r"), ("github.com", "o", "r"))
        self.assertEqual(parse_repo_target("https://github.com/o/r"),
                         ("github.com", "o", "r"))

    def test_allowed_enterprise_host_is_parsed(self):
        self.assertEqual(parse_repo_target("https://%s/o/r.git" % _GHE, [_GHE]),
                         (_GHE, "o", "r"))

    def test_enterprise_host_is_refused_when_not_configured(self):
        with self.assertRaises(RepoCloneError) as ctx:
            parse_repo_target("https://%s/o/r" % _GHE)
        self.assertIn("not an allowed GitHub host", str(ctx.exception))

    def test_a_different_host_is_refused_even_with_one_configured(self):
        with self.assertRaises(RepoCloneError):
            parse_repo_target("https://evil.example.com/o/r", [_GHE])

    def test_ssrf_shaped_hosts_cannot_be_allowlisted(self):
        for host in ("169.254.169.254", "localhost", "10.0.0.5"):
            with self.assertRaises(RepoCloneError, msg=host):
                parse_repo_target("https://%s/o/r" % host, [host])

    def test_a_port_is_refused(self):
        with self.assertRaises(RepoCloneError) as ctx:
            parse_repo_target("https://%s:8443/o/r" % _GHE, [_GHE])
        self.assertIn("port", str(ctx.exception))

    def test_a_malformed_authority_is_a_clean_refusal_not_a_traceback(self):
        # urlparse defers parsing the port, so `.port` raises ValueError here.
        with self.assertRaises(RepoCloneError):
            parse_repo_target("https://%s:notaport/o/r" % _GHE, [_GHE])

    def test_clone_url_is_rebuilt_on_the_enterprise_host(self):
        clone_repo("https://%s/Owner/Repo.git" % _GHE, dest_parent=self.tmp,
                   allowed_hosts=[_GHE], runner=self._runner())
        argv = self.calls[0]["argv"]
        self.assertIn("https://%s/Owner/Repo.git" % _GHE, argv)

    def test_clone_refuses_a_host_the_operator_did_not_configure(self):
        with self.assertRaises(RepoCloneError):
            clone_repo("https://%s/o/r" % _GHE, dest_parent=self.tmp,
                       runner=self._runner())
        self.assertEqual(self.calls, [], "git must not run for a disallowed host")

    def test_parse_repo_keeps_its_two_tuple_shape(self):
        self.assertEqual(parse_repo("https://%s/o/r" % _GHE, [_GHE]), ("o", "r"))


if __name__ == "__main__":
    unittest.main()
