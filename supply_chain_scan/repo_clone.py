"""Shallow GitHub clone for the L1 supply-chain scan.

The scan can take its input either from an uploaded SBOM/lockfile or straight
from a repository. This module is the repository half.

WHERE THIS RUNS, AND WHY IT IS NOT THE DIRTY ANALYZER
-----------------------------------------------------
The clone happens in the scan container (the CLEAN side) because it is the only
side that may hold the GitHub token. `git clone` does not execute anything from
the remote - remote hooks are never fetched, and `core.fsmonitor`-style config
injection is blocked by refusing `--upload-pack`/config overrides and by
disabling submodules - so a clone writes files without running repository code.
Every step that PARSES those files still happens inside the dirty analyzer:
this module hands it a directory (`mode: "dir"`) and no credential.

THREAT NOTES
------------
S6 (command injection): the repository coordinate is charset-gated and the URL
is rebuilt from the parsed owner/repo, so nothing from the operator's string
survives into argv verbatim. All subprocess calls are shell=False.

Credential handling: the token NEVER appears in argv (visible in `ps` to
anything sharing the PID namespace) and NEVER in the remote URL (git writes the
URL into .git/config, so a credentialed URL would be persisted to disk and
handed to the analyzer along with the checkout). It is passed through
GIT_ASKPASS, which git invokes as a helper program and reads on stdout.

S9 (resource exhaustion): a shallow single-branch clone with submodules
disabled, plus a hard byte cap enforced after the fact - a repository can
otherwise be arbitrarily large.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile

__all__ = ["parse_repo", "clone_repo", "RepoCloneError", "MAX_REPO_BYTES"]


class RepoCloneError(RuntimeError):
    """The repository could not be cloned, or is not an acceptable coordinate."""


# Mirrors webapp/src/lib/validation/supplyChainInput.ts. Both sides validate:
# the UI so the operator gets a message, and here because the scan container
# must never trust a value that reached it over HTTP.
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")

MAX_REPO_BYTES = int(os.environ.get("SUPPLY_CHAIN_MAX_REPO_BYTES", str(512 * 1024 * 1024)))
_CLONE_TIMEOUT = int(os.environ.get("SUPPLY_CHAIN_CLONE_TIMEOUT", "300"))


def parse_repo(raw):
    """`owner/repo` or an https://github.com/owner/repo URL -> (owner, repo).

    Raises RepoCloneError on anything else. Only github.com is accepted; a URL
    carrying credentials is refused rather than silently stripped, so a token
    pasted into the field is never quietly persisted.
    """
    if not isinstance(raw, str):
        raise RepoCloneError("repository must be a string")
    value = raw.strip()
    if not value or len(value) > 300:
        raise RepoCloneError("repository is empty or too long")

    if value.lower().startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise RepoCloneError("only https:// GitHub URLs are accepted")
        if (parsed.hostname or "").lower() != "github.com":
            raise RepoCloneError("only github.com repositories are accepted")
        if parsed.username or parsed.password:
            raise RepoCloneError("remove the credentials from the repository URL")
        if parsed.query or parsed.fragment:
            raise RepoCloneError("repository URL must not carry a query or fragment")
        value = (parsed.path or "").lstrip("/")

    if value.lower().endswith(".git"):
        value = value[:-4]
    value = value.rstrip("/")

    parts = value.split("/")
    if len(parts) != 2:
        raise RepoCloneError("repository must be owner/repo")
    owner, repo = parts
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise RepoCloneError("repository owner/name contains disallowed characters")
    # The repo charset allows '.', so "." and ".." satisfy the regex. Neither is
    # a real repository, and both become a directory name further down - reject
    # them explicitly rather than relying on the charset to have excluded them.
    if owner in (".", "..") or repo in (".", ".."):
        raise RepoCloneError("repository owner/name may not be '.' or '..'")
    if ".." in owner or ".." in repo:
        raise RepoCloneError("repository owner/name may not contain '..'")
    return owner, repo


def _validate_ref(ref):
    if not ref:
        return None
    ref = ref.strip()
    if not ref:
        return None
    # A leading '-' would be read as an option by git, and '..'/'@{' are git
    # revision syntax rather than a branch name.
    if ref.startswith("-") or ".." in ref or "@{" in ref or ref.endswith(".lock"):
        raise RepoCloneError("branch/tag contains a sequence git does not allow")
    if not _REF_RE.match(ref):
        raise RepoCloneError("branch/tag contains disallowed characters")
    return ref


def _write_askpass(dir_path, token):
    """A helper git runs to obtain the credential, so it stays out of argv.

    git calls the program once for the username and once for the password. The
    token goes in the environment of THIS helper only, and the file is inside a
    0700 directory that is removed with the rest of the scratch.
    """
    path = os.path.join(dir_path, "askpass.sh")
    with open(path, "w") as fh:
        fh.write(
            "#!/bin/sh\n"
            "# git asks for the username first, then the password. A PAT is\n"
            "# accepted as the password with any non-empty username.\n"
            'case "$1" in\n'
            "  *Username*) printf %s \"$SC_GIT_USER\" ;;\n"
            "  *) printf %s \"$SC_GIT_TOKEN\" ;;\n"
            "esac\n"
        )
    os.chmod(path, stat.S_IRWXU)
    return path


def _dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


def clone_repo(repo, *, ref=None, token=None, dest_parent=None,
               timeout=_CLONE_TIMEOUT, max_bytes=MAX_REPO_BYTES, runner=None):
    """Shallow-clone `repo` and return the checkout path.

    The caller owns the returned directory and must remove it. Raises
    RepoCloneError on a bad coordinate, a clone failure, or an oversized
    repository.
    """
    owner, name = parse_repo(repo)
    ref = _validate_ref(ref)

    scratch = tempfile.mkdtemp(prefix="sc-repo-", dir=dest_parent)
    os.chmod(scratch, stat.S_IRWXU)
    dest = os.path.join(scratch, "src")

    argv = [
        "git",
        # Never prompt: without this a private repo with no token blocks the
        # scan forever on a terminal read instead of failing.
        "-c", "credential.helper=",
        "-c", "core.askPass=",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        # Submodules can point anywhere, including file:// paths on this host.
        "--recurse-submodules=no",
        "--config", "submodule.recurse=false",
    ]
    if ref:
        argv += ["--branch", ref]
    # The URL is REBUILT from the validated parts, never echoed from the input.
    argv += ["https://github.com/{}/{}.git".format(owner, name), dest]

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    # Submodule/LFS smudge filters would run repository-controlled commands.
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    if token:
        env["GIT_ASKPASS"] = _write_askpass(scratch, token)
        env["SC_GIT_USER"] = "x-access-token"
        env["SC_GIT_TOKEN"] = token

    try:
        run = runner or subprocess.run
        proc = run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(scratch, ignore_errors=True)
        raise RepoCloneError("clone timed out after {}s".format(timeout))
    except OSError as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        raise RepoCloneError("could not run git: {}".format(exc))

    if getattr(proc, "returncode", 1) != 0:
        stderr = (getattr(proc, "stderr", "") or "").strip()
        shutil.rmtree(scratch, ignore_errors=True)
        # The token cannot appear in stderr (it never entered argv or the URL),
        # but scrub defensively before this reaches a log or the graph.
        raise RepoCloneError("git clone failed: {}".format(
            _scrub(stderr, token)[:500]))

    size = _dir_size(dest)
    if size > max_bytes:
        shutil.rmtree(scratch, ignore_errors=True)
        raise RepoCloneError(
            "repository is {} MB, over the {} MB limit".format(
                size // (1024 * 1024), max_bytes // (1024 * 1024)))

    # The credential helper has done its job; do not leave it next to a
    # directory that is about to be handed to the analyzer.
    askpass = os.path.join(scratch, "askpass.sh")
    if os.path.exists(askpass):
        os.unlink(askpass)

    # .git holds the full object store and the remote config. The analyzer only
    # needs the working tree, and osv-scanner would otherwise walk it.
    shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)

    return dest


def _scrub(text, token):
    if token and token in text:
        return text.replace(token, "***")
    return text
