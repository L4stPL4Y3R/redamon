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

__all__ = ["parse_repo", "parse_repo_target", "clone_repo", "RepoCloneError",
           "MAX_REPO_BYTES", "DEFAULT_HOST"]


class RepoCloneError(RuntimeError):
    """The repository could not be cloned, or is not an acceptable coordinate."""


# Mirrors webapp/src/lib/validation/supplyChainInput.ts. Both sides validate:
# the UI so the operator gets a message, and here because the scan container
# must never trust a value that reached it over HTTP.
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
# A dotted DNS name; the required dot also excludes `localhost`.
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

DEFAULT_HOST = "github.com"

MAX_REPO_BYTES = int(os.environ.get("SUPPLY_CHAIN_MAX_REPO_BYTES", str(2 * 1024 * 1024 * 1024)))
_CLONE_TIMEOUT = int(os.environ.get("SUPPLY_CHAIN_CLONE_TIMEOUT", "300"))


def _normalize_hosts(allowed_hosts):
    """The hosts a coordinate may name. github.com is always in, and a caller's
    extra host must still look like a DNS name - a bad value in the operator's
    settings must not widen this to an IP literal or `localhost`."""
    hosts = {DEFAULT_HOST}
    for host in (allowed_hosts or ()):
        if not isinstance(host, str):
            continue
        value = host.strip().lower()
        if value and not _IPV4_RE.match(value) and _HOST_RE.match(value):
            hosts.add(value)
    return hosts


def parse_repo_target(raw, allowed_hosts=None):
    """`owner/repo` or an https://<host>/owner/repo URL -> (host, owner, repo).

    Raises RepoCloneError on anything else. The host must be github.com or one
    the operator configured (a GitHub Enterprise server); anything else is
    refused HERE too, not only in the webapp, because this container must never
    trust a value that reached it over HTTP. A URL carrying credentials is
    refused rather than silently stripped, so a token pasted into the field is
    never quietly persisted.
    """
    hosts = _normalize_hosts(allowed_hosts)
    host = DEFAULT_HOST

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
        # A port would let an allowed hostname be pointed at another service.
        # .port/.hostname parse lazily and raise ValueError on a malformed
        # authority, which must surface as a clean refusal, not a traceback.
        try:
            port = parsed.port
            host = (parsed.hostname or "").lower()
        except ValueError:
            raise RepoCloneError("repository URL has a malformed host")
        if port:
            raise RepoCloneError("repository URL must not carry a port")
        if host not in hosts:
            raise RepoCloneError(
                "'{}' is not an allowed GitHub host".format(host or "(none)"))
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
    return host, owner, repo


def parse_repo(raw, allowed_hosts=None):
    """`parse_repo_target` without the host - the coordinate half only."""
    _host, owner, repo = parse_repo_target(raw, allowed_hosts)
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
               timeout=_CLONE_TIMEOUT, max_bytes=MAX_REPO_BYTES, runner=None,
               allowed_hosts=None):
    """Shallow-clone `repo` and return the checkout path.

    `repo` may be `owner/repo` (github.com) or a full https URL naming github.com
    or an allowed GitHub Enterprise host. The caller owns the returned directory
    and must remove it. Raises RepoCloneError on a bad coordinate, a disallowed
    host, a clone failure, or an oversized repository.
    """
    host, owner, name = parse_repo_target(repo, allowed_hosts)
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
    argv += ["https://{}/{}/{}.git".format(host, owner, name), dest]

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
