"""TruffleHog source registry — the single Python authority for argv construction.

Mirrors ``webapp/src/lib/trufflehogSources.ts`` (form rendering). The two must
agree field-for-field: the TS side renders the form and stores ``config``, this
side turns that same ``config`` into a TruffleHog command line. A field present
in one mirror and missing from the other is silently dropped at the boundary, so
add to both or neither.

Three rules the registry exists to enforce:

* **No secret is ever a field.** Credentials arrive as environment variables
  named exactly what TruffleHog documents for the flag, so the binary reads them
  itself and the flag is never emitted — the token stays out of both the
  operator-supplied ``config`` (which is exported verbatim into ``project.json``)
  and the container's process table. Only two flags have no upstream Envar and
  must go through argv: docker ``--registry-token`` and gcs
  ``--service-account`` (a path, not the key).
* **``--exclude-paths`` is two incompatible flags.** On git/github/gitlab/
  filesystem it takes a *path to a file* of newline-separated regexes; on docker
  it takes an *inline comma-separated list*. The type is per-source for that
  reason; a shared helper that assumes one form builds a broken command on the
  other with no error.
* **Every operator-supplied host is an egress decision.** ``egress_hosts()``
  enumerates them so the orchestrator can resolve and deny before spawning.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# Field / credential vocabulary
# ---------------------------------------------------------------------------

#: How a field is rendered and how it is turned into argv. The type is the UI
#: CONTROL, shared with the TS mirror; whether a field reaches TruffleHog at all
#: is the separate ``client`` flag below.
FIELD_TYPES = (
    "text", "multi", "csv", "pathfile", "toggle", "number", "select", "bytes",
    "textarea",
)


@dataclass(frozen=True)
class Field:
    """One operator-settable input on a source card."""

    key: str                    # config key, camelCase — matches the TS mirror
    type: str                   # the UI control; same value in the TS mirror
    flag: str = ""              # "" on a non-client field means positional
    required: bool = False
    forced: bool = False        # always emitted when the source is used
    label: str = ""
    #: Consumed by the runner itself and never passed to TruffleHog — the docker
    #: tag/architecture expansion, which is our work because `remote.Image()`
    #: resolves a single platform per reference and has no flag for it.
    client: bool = False

    def __post_init__(self) -> None:
        if self.type not in FIELD_TYPES:
            raise ValueError(f"unknown field type {self.type!r} for {self.key}")


@dataclass(frozen=True)
class Credential:
    """A secret the orchestrator injects as an env var, never as config.

    ``env`` is deliberately the env var name TruffleHog 3.96.0 itself documents
    for the flag (``$GITHUB_TOKEN``, ``$ELASTICSEARCH_API_KEY``, ...). With
    ``native_env`` set, the binary reads the value straight out of the
    environment and the flag is never emitted — which is how a token stays out
    of the container's process table entirely.
    """

    env: str                    # env var name inside the dirty container
    settings_key: str           # UserSettings column (camelCase) it is read from
    label: str                  # human name, used verbatim in the start-blocked alert
    flag: str = ""              # TruffleHog flag it feeds; "" = consumed by the runner
    optional_within_source: bool = False  # part of a multi-key source (elasticsearch)
    #: False for the two flags with no upstream Envar (docker --registry-token,
    #: gcs --service-account); those must be spliced into argv.
    native_env: bool = True


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    subcommand: str
    asset_label: str
    asset_kind: str
    fields: tuple[Field, ...] = ()
    credentials: tuple[Credential, ...] = ()
    #: Extra argv appended unconditionally (github-experimental needs its
    #: submodule flag or the command errors out).
    fixed_args: tuple[str, ...] = ()

    def field(self, key: str) -> Optional[Field]:
        for f in self.fields:
            if f.key == key:
                return f
        return None


# ---------------------------------------------------------------------------
# Credential definitions (5.2 / Appendix D). ``settings_key`` is the
# UserSettings column; the orchestrator resolves it and sets ``env``.
# ---------------------------------------------------------------------------

CRED_GITHUB = Credential("GITHUB_TOKEN", "trufflehogGithubToken", "TruffleHog GitHub Token", "--token")
CRED_GITLAB = Credential("GITLAB_TOKEN", "trufflehogGitlabToken", "TruffleHog GitLab Token", "--token")
CRED_DOCKER = Credential("DOCKER_TOKEN", "trufflehogDockerToken", "TruffleHog Docker Token", "--token")
CRED_HUGGINGFACE = Credential("HUGGINGFACE_TOKEN", "trufflehogHuggingfaceToken", "TruffleHog Hugging Face Token", "--token")
CRED_POSTMAN = Credential("POSTMAN_TOKEN", "trufflehogPostmanToken", "TruffleHog Postman Token", "--token")
CRED_CIRCLECI = Credential("CIRCLECI_TOKEN", "trufflehogCircleciToken", "TruffleHog CircleCI Token", "--token")
CRED_TRAVISCI = Credential("TRAVISCI_TOKEN", "trufflehogTravisciToken", "TruffleHog Travis CI Token", "--token")
CRED_AWS_KEY = Credential("AWS_ACCESS_KEY_ID", "trufflehogAwsAccessKeyId", "TruffleHog AWS Access Key ID", "--key")
CRED_AWS_SECRET = Credential("AWS_SECRET_ACCESS_KEY", "trufflehogAwsSecretKey", "TruffleHog AWS Secret Key", "--secret")
CRED_AWS_SESSION = Credential("AWS_SESSION_TOKEN", "trufflehogAwsSessionToken", "TruffleHog AWS Session Token", "--session-token", optional_within_source=True)
# --service-account takes a PATH, not the JSON itself, so the blob is written to
# the run dir and the path goes in argv (no upstream Envar for this flag).
CRED_GCP = Credential("GCP_SERVICE_ACCOUNT", "trufflehogGcpServiceAccount", "TruffleHog GCP Service Account", "--service-account", native_env=False)
CRED_JENKINS_USER = Credential("JENKINS_USERNAME", "trufflehogJenkinsUsername", "TruffleHog Jenkins Username", "--username", optional_within_source=True)
CRED_JENKINS_PASS = Credential("JENKINS_PASSWORD", "trufflehogJenkinsPassword", "TruffleHog Jenkins Password", "--password", optional_within_source=True)
CRED_ES_USER = Credential("ELASTICSEARCH_USERNAME", "trufflehogElasticUsername", "TruffleHog Elasticsearch Username", "--username", optional_within_source=True)
CRED_ES_PASS = Credential("ELASTICSEARCH_PASSWORD", "trufflehogElasticPassword", "TruffleHog Elasticsearch Password", "--password", optional_within_source=True)
CRED_ES_APIKEY = Credential("ELASTICSEARCH_API_KEY", "trufflehogElasticApiKey", "TruffleHog Elasticsearch API Key", "--api-key", optional_within_source=True)
CRED_ES_SVCTOKEN = Credential("ELASTICSEARCH_SERVICE_TOKEN", "trufflehogElasticServiceToken", "TruffleHog Elasticsearch Service Token", "--service-token", optional_within_source=True)
CRED_GIT_USER = Credential("GIT_USERNAME", "trufflehogGitUsername", "TruffleHog Git Username", optional_within_source=True)
CRED_GIT_TOKEN = Credential("GIT_TOKEN", "trufflehogGitToken", "TruffleHog Git Token", optional_within_source=True)

#: Every credential env var the feature can inject, for redaction sweeps.
ALL_CREDENTIALS: tuple[Credential, ...] = (
    CRED_GITHUB, CRED_GITLAB, CRED_DOCKER, CRED_HUGGINGFACE, CRED_POSTMAN,
    CRED_CIRCLECI, CRED_TRAVISCI, CRED_AWS_KEY, CRED_AWS_SECRET, CRED_AWS_SESSION,
    CRED_GCP, CRED_JENKINS_USER, CRED_JENKINS_PASS, CRED_ES_USER, CRED_ES_PASS,
    CRED_ES_APIKEY, CRED_ES_SVCTOKEN, CRED_GIT_USER, CRED_GIT_TOKEN,
)


# ---------------------------------------------------------------------------
# The registry (Appendix A)
# ---------------------------------------------------------------------------

SOURCES: dict[str, Source] = {
    "git": Source(
        id="git", label="Git repository", subcommand="git",
        asset_label="TrufflehogRepository", asset_kind="repository",
        credentials=(CRED_GIT_USER, CRED_GIT_TOKEN),
        fields=(
            Field("uri", "text", "", label="Repository URI"),
            # A folder name under scan_targets/git, composed into a file:// URI
            # server-side. Never the path itself.
            Field("localRepo", "text", "", label="Local repository"),
            Field("branch", "text", "--branch"),
            Field("sinceCommit", "text", "--since-commit"),
            Field("maxDepth", "number", "--max-depth"),
            Field("bare", "toggle", "--bare"),
            Field("includePaths", "pathfile", "--include-paths"),
            Field("excludePaths", "pathfile", "--exclude-paths"),
            Field("excludeGlobs", "csv", "--exclude-globs"),
        ),
    ),
    "github": Source(
        id="github", label="GitHub", subcommand="github",
        asset_label="TrufflehogRepository", asset_kind="repository",
        credentials=(CRED_GITHUB,),
        fields=(
            Field("endpoint", "text", "--endpoint"),
            Field("repos", "multi", "--repo"),
            Field("orgs", "multi", "--org"),
            Field("includeRepos", "multi", "--include-repos"),
            Field("excludeRepos", "multi", "--exclude-repos"),
            Field("includeForks", "toggle", "--include-forks"),
            Field("includeMembers", "toggle", "--include-members"),
            Field("includeWikis", "toggle", "--include-wikis"),
            Field("excludeArchived", "toggle", "--exclude-archived"),
            Field("ignoreGists", "toggle", "--ignore-gists"),
            Field("issueComments", "toggle", "--issue-comments"),
            Field("prComments", "toggle", "--pr-comments"),
            Field("gistComments", "toggle", "--gist-comments"),
            Field("commentsTimeframe", "number", "--comments-timeframe"),
            Field("includePaths", "pathfile", "--include-paths"),
            Field("excludePaths", "pathfile", "--exclude-paths"),
        ),
    ),
    "github_experimental": Source(
        id="github_experimental", label="GitHub deleted commits",
        subcommand="github-experimental",
        asset_label="TrufflehogRepository", asset_kind="repository",
        credentials=(CRED_GITHUB,),
        # --object-discovery is the only submodule; the command errors without it.
        fixed_args=("--object-discovery",),
        fields=(
            Field("repo", "text", "--repo", required=True),
            Field("collisionThreshold", "number", "--collision-threshold"),
            Field("deleteCachedData", "toggle", "--delete-cached-data"),
        ),
    ),
    "gitlab": Source(
        id="gitlab", label="GitLab", subcommand="gitlab",
        asset_label="TrufflehogRepository", asset_kind="repository",
        credentials=(CRED_GITLAB,),
        fields=(
            Field("endpoint", "text", "--endpoint"),
            Field("repos", "multi", "--repo"),
            Field("groupIds", "multi", "--group-id"),
            Field("includeRepos", "multi", "--include-repos"),
            Field("excludeRepos", "multi", "--exclude-repos"),
            Field("includePaths", "pathfile", "--include-paths"),
            Field("excludePaths", "pathfile", "--exclude-paths"),
        ),
    ),
    "docker": Source(
        id="docker", label="Docker registry", subcommand="docker",
        asset_label="TrufflehogImage", asset_kind="image",
        credentials=(CRED_DOCKER,),
        fields=(
            Field("images", "multi", "--image"),
            # File names under scan_targets/docker, composed into file:// image
            # refs server-side. Never the path itself.
            Field("localImages", "multi", "--image"),
            Field("namespace", "text", "--namespace"),
            # csv here, NOT pathfile — see the module docstring.
            Field("excludePaths", "csv", "--exclude-paths"),
            Field("maxImages", "number", client=True),
            Field("scanAllTags", "toggle", client=True),
            Field("scanAllArchitectures", "toggle", client=True),
            Field("includePrivate", "toggle", "--registry-token"),
        ),
    ),
    "huggingface": Source(
        id="huggingface", label="Hugging Face", subcommand="huggingface",
        asset_label="TrufflehogModel", asset_kind="model",
        credentials=(CRED_HUGGINGFACE,),
        fields=(
            Field("mode", "select", client=True),   # "assets" | "sweep"
            Field("endpoint", "text", "--endpoint"),
            Field("models", "multi", "--model"),
            Field("spaces", "multi", "--space"),
            Field("datasets", "multi", "--dataset"),
            Field("buckets", "multi", "--bucket"),
            Field("orgs", "multi", "--org"),
            Field("users", "multi", "--user"),
            Field("skipAllModels", "toggle", "--skip-all-models"),
            Field("skipAllSpaces", "toggle", "--skip-all-spaces"),
            Field("skipAllDatasets", "toggle", "--skip-all-datasets"),
            Field("skipAllBuckets", "toggle", "--skip-all-buckets"),
            Field("includeModels", "multi", "--include-models"),
            Field("includeSpaces", "multi", "--include-spaces"),
            Field("includeDatasets", "multi", "--include-datasets"),
            Field("includeBuckets", "multi", "--include-buckets"),
            Field("ignoreModels", "multi", "--ignore-models"),
            Field("ignoreSpaces", "multi", "--ignore-spaces"),
            Field("ignoreDatasets", "multi", "--ignore-datasets"),
            Field("ignoreBuckets", "multi", "--ignore-buckets"),
            Field("includeDiscussions", "toggle", "--include-discussions"),
            Field("includePrs", "toggle", "--include-prs"),
        ),
    ),
    "s3": Source(
        id="s3", label="AWS S3", subcommand="s3",
        asset_label="TrufflehogBucket", asset_kind="bucket",
        credentials=(CRED_AWS_KEY, CRED_AWS_SECRET, CRED_AWS_SESSION),
        fields=(
            Field("buckets", "multi", "--bucket"),
            Field("ignoreBuckets", "multi", "--ignore-bucket"),
            Field("roleArns", "multi", "--role-arn"),
            Field("cloudEnvironment", "toggle", "--cloud-environment"),
            Field("maxObjectSize", "bytes", "--max-object-size"),
        ),
    ),
    "gcs": Source(
        id="gcs", label="Google Cloud Storage", subcommand="gcs",
        asset_label="TrufflehogBucket", asset_kind="bucket",
        credentials=(CRED_GCP,),
        fields=(
            Field("projectId", "text", "--project-id"),
            Field("withoutAuth", "toggle", "--without-auth"),
            Field("cloudEnvironment", "toggle", "--cloud-environment"),
            Field("includeBuckets", "multi", "--include-buckets"),
            Field("excludeBuckets", "multi", "--exclude-buckets"),
            Field("includeObjects", "multi", "--include-objects"),
            Field("excludeObjects", "multi", "--exclude-objects"),
            Field("maxObjectSize", "bytes", "--max-object-size"),
        ),
    ),
    "filesystem": Source(
        id="filesystem", label="Filesystem", subcommand="filesystem",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        fields=(
            # No target field on purpose. This source always scans
            # SCAN_TARGET_DIRS["filesystem"], so there is no path to type and
            # nothing to validate — a typed path plus a credential-bearing
            # container is a file disclosure primitive (A.10).
            Field("includePaths", "pathfile", "--include-paths"),
            Field("excludePaths", "pathfile", "--exclude-paths"),
            Field("maxSymlinkDepth", "number", "--max-symlink-depth"),
        ),
    ),
    "jenkins": Source(
        id="jenkins", label="Jenkins", subcommand="jenkins",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        credentials=(CRED_JENKINS_USER, CRED_JENKINS_PASS),
        fields=(
            Field("url", "text", "--url", required=True),
            Field("insecureSkipVerifyTls", "toggle", "--insecure-skip-verify-tls"),
        ),
    ),
    "elasticsearch": Source(
        id="elasticsearch", label="Elasticsearch", subcommand="elasticsearch",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        credentials=(CRED_ES_USER, CRED_ES_PASS, CRED_ES_APIKEY, CRED_ES_SVCTOKEN),
        fields=(
            Field("nodes", "multi", "--nodes"),
            Field("cloudId", "text", "--cloud-id"),
            Field("indexPattern", "text", "--index-pattern"),
            Field("queryJson", "textarea", "--query-json"),
            Field("sinceTimestamp", "text", "--since-timestamp"),
            # --best-effort-scan is deliberately absent: it scans continuously, so
            # the run never reaches `completed` and never releases its memory
            # reservation (A.12).
        ),
    ),
    "postman": Source(
        id="postman", label="Postman", subcommand="postman",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        credentials=(CRED_POSTMAN,),
        fields=(
            Field("workspaceIds", "multi", "--workspace-id"),
            Field("collectionIds", "multi", "--collection-id"),
            Field("environments", "multi", "--environment"),
            Field("includeCollectionIds", "multi", "--include-collection-id"),
            Field("excludeCollectionIds", "multi", "--exclude-collection-id"),
            Field("includeEnvironments", "multi", "--include-environments"),
            Field("excludeEnvironments", "multi", "--exclude-environments"),
        ),
    ),
    "circleci": Source(
        id="circleci", label="CircleCI", subcommand="circleci",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        credentials=(CRED_CIRCLECI,),
    ),
    "travisci": Source(
        id="travisci", label="Travis CI", subcommand="travisci",
        asset_label="TrufflehogEndpoint", asset_kind="endpoint",
        credentials=(CRED_TRAVISCI,),
    ),
}

#: Sources that reach the network with an operator-typed host (12.4).
SOURCE_IDS: tuple[str, ...] = tuple(SOURCES)

#: Allowlisted filesystem scan roots (A.10). Keyed by the UI value; the value is
#: the container-side mount the orchestrator attaches read-only.
# The one place a source may read from disk. Mounted read-only by the
# orchestrator from scanners/scan_targets/; see that folder's README.
#
# A local path is never operator-typed. The scan container carries this source's
# credential in /work/job.json, so a free-text file:// target would read that
# token and report it back as a finding — defeating the point of giving the
# container exactly one secret. The operator names a folder or a file, the
# server composes the path, and SCAN_TARGET_NAME_RE keeps it to one segment.
SCAN_TARGETS_MOUNT = "/scan-targets"

SCAN_TARGET_DIRS: dict[str, str] = {
    "filesystem": f"{SCAN_TARGETS_MOUNT}/filesystem",
    "git": f"{SCAN_TARGETS_MOUNT}/git",
    "docker": f"{SCAN_TARGETS_MOUNT}/docker",
}

# One path segment: no separator, no traversal, no leading dot-dot. Anchored, so
# a newline cannot smuggle a second line past it.
SCAN_TARGET_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def is_valid_scan_target_name(name: str) -> bool:
    """True if `name` may be composed into a /scan-targets path."""
    name = (name or "").strip()
    if not name or name == "." or ".." in name:
        return False
    return bool(SCAN_TARGET_NAME_RE.match(name))


def scan_target_path(source_id: str, name: str) -> str:
    """Container-side path for a named fixture, or '' if the name is not safe."""
    base = SCAN_TARGET_DIRS.get(source_id, "")
    if not base or not is_valid_scan_target_name(name):
        return ""
    return f"{base}/{name.strip()}"


def get_source(source_id: str) -> Source:
    """Look up a source, normalising the dash spelling the CLI uses."""
    key = (source_id or "").strip().lower().replace("-", "_")
    if key not in SOURCES:
        raise KeyError(f"unknown trufflehog source: {source_id!r}")
    return SOURCES[key]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

#: A bare registry reference: no scheme, no shell metacharacters, no leading
#: dash (which argv would read as an option).
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*(:[A-Za-z0-9._\-]+)?(@sha256:[a-f0-9]{64})?$")
_SHELL_META = set(";|&$`\n\r<>()*?[]{}!\\'\" \t")


def as_list(value) -> list[str]:
    """Normalise a multi/csv field to a list of non-empty strings."""
    return _as_list(value)


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [p.strip() for p in value.split(",") if p.strip()]
    if isinstance(value, (list, tuple)):
        return [str(p).strip() for p in value if str(p).strip()]
    return [str(value).strip()]


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def _is_safe_argv_token(value: str) -> bool:
    """Reject anything that could be read as an option or a shell construct.

    argv is passed to Popen as a list so there is no shell, but a value starting
    with ``-`` still becomes an *option* to TruffleHog — that is the injection
    that matters here (12.6).
    """
    if not value or value.startswith("-"):
        return False
    return not (_SHELL_META & set(value))


def validate_config(source_id: str, config: dict) -> list[str]:
    """Return human-readable errors for a source config. Empty list = valid.

    Fails closed by design: the orchestrator refuses the start on any error, so a
    cross-field contradiction can never reach argv (where TruffleHog would either
    error opaquely or, worse, silently scan the wrong thing).
    """
    src = get_source(source_id)
    cfg = config or {}
    errors: list[str] = []

    for f in src.fields:
        if f.required and not _text(cfg.get(f.key)) and not _as_list(cfg.get(f.key)):
            errors.append(f"{src.label}: '{f.key}' is required")

    if src.id == "github":
        if not _as_list(cfg.get("repos")) and not _as_list(cfg.get("orgs")):
            errors.append("GitHub: set at least one repository or organization")
        org_only = ("includeRepos", "excludeRepos", "includeMembers")
        if not _as_list(cfg.get("orgs")):
            for key in org_only:
                if _as_list(cfg.get(key)) or _as_bool(cfg.get(key)):
                    errors.append(f"GitHub: '{key}' only applies to organization scans")

    if src.id == "gitlab":
        # Empty repos + groups is legal (it scans every project the token can
        # reach). But a repo that IS given must be a full http(s) URL: verified
        # against the pinned binary, which answers `org/repo` with
        # "Gitlab requires http/https repo urls" at INFO level and then scans
        # nothing for it — a silent miss, not a failure. GitHub accepts the
        # shorthand, so an operator will reasonably try it here too.
        for repo in _as_list(cfg.get("repos")):
            if not repo.startswith(("http://", "https://")):
                errors.append(
                    f"GitLab: '{repo}' must be a full URL, e.g. "
                    f"https://gitlab.com/{repo.strip('/')}.git")


    if src.id == "docker":
        images = _as_list(cfg.get("images"))
        if not images and not _text(cfg.get("namespace")):
            errors.append("Docker: set at least one image or a namespace")
        for image in images:
            if "://" in image:
                errors.append(
                    f"Docker: '{image}' must be a bare registry reference "
                    "(docker:// needs the Docker socket, file:// reads the container filesystem)"
                )
            elif not _IMAGE_RE.match(image):
                errors.append(f"Docker: '{image}' is not a valid image reference")
        ns = _text(cfg.get("namespace"))
        if ns and not _is_safe_argv_token(ns):
            errors.append(f"Docker: namespace '{ns}' contains invalid characters")

    if src.id == "huggingface":
        mode = _text(cfg.get("mode")) or "assets"
        if mode == "assets":
            if not any(_as_list(cfg.get(k)) for k in ("models", "spaces", "datasets", "buckets")):
                errors.append("Hugging Face: set at least one model, space, dataset or bucket")
        else:
            if not _as_list(cfg.get("orgs")) and not _as_list(cfg.get("users")):
                errors.append("Hugging Face: sweep mode needs an organization or a user")

    if src.id == "s3":
        if _as_list(cfg.get("buckets")) and _as_list(cfg.get("ignoreBuckets")):
            errors.append("S3: 'Buckets' and 'Ignore buckets' are mutually exclusive")

    if src.id == "gcs":
        if _text(cfg.get("projectId")) and _as_bool(cfg.get("withoutAuth")):
            errors.append("GCS: 'Project ID' cannot be combined with 'Without auth'")
        if not _text(cfg.get("projectId")) and not _as_bool(cfg.get("withoutAuth")):
            errors.append("GCS: set a Project ID or enable 'Without auth'")

    # The filesystem source takes no target, so there is nothing to validate.

    if src.id == "git":
        uri = _text(cfg.get("uri"))
        local = _text(cfg.get("localRepo"))
        if not uri and not local:
            errors.append(
                "Git: set a Repository URI, or a Local repository placed in "
                "scanners/scan_targets/git/"
            )
        if uri and local:
            errors.append(
                "Git: 'Repository URI' and 'Local repository' are mutually "
                "exclusive — a run scans one repository"
            )
        if local and not is_valid_scan_target_name(local):
            errors.append(
                f"Git: '{local}' is not a valid local repository name. Use the "
                "folder name only, as it appears in scanners/scan_targets/git/ "
                "(letters, digits, dot, dash, underscore; no slashes)"
            )

    if src.id == "docker":
        for name in _as_list(cfg.get("localImages")):
            if not is_valid_scan_target_name(name):
                errors.append(
                    f"Docker: '{name}' is not a valid local image name. Use the "
                    "file name only, as it appears in "
                    "scanners/scan_targets/docker/ (no slashes)"
                )

    if src.id == "elasticsearch":
        cloud_id = _text(cfg.get("cloudId"))
        if not _as_list(cfg.get("nodes")) and not cloud_id:
            errors.append("Elasticsearch: set at least one node or a Cloud ID")
        if cloud_id and not decode_cloud_id_host(cloud_id):
            # Fail closed: an undecodable cloud id presents no host to resolve,
            # so it would slip past the egress guard while still reaching
            # whatever Elastic makes of it.
            errors.append(
                "Elasticsearch: Cloud ID is not in the expected "
                "'<name>:<base64>' form, so its host cannot be checked")

    if src.id == "postman":
        if not any(_as_list(cfg.get(k)) for k in ("workspaceIds", "collectionIds", "environments")):
            errors.append("Postman: set at least one workspace, collection or environment")

    if src.id == "git":
        uri = _text(cfg.get("uri"))
        if uri:
            scheme = urlsplit(uri).scheme
            if scheme not in ("https", "http", "ssh", "git", "file"):
                errors.append(f"Git: '{uri}' must be an https://, ssh:// or file:// URI")
            if any(c in uri for c in ";|&`\n\r"):
                errors.append("Git: repository URI contains invalid characters")

    if src.id == "jenkins":
        url = _text(cfg.get("url"))
        if url and urlsplit(url).scheme not in ("http", "https"):
            errors.append("Jenkins: URL must be http:// or https://")

    return errors


# ---------------------------------------------------------------------------
# Credential gate (5.2a)
# ---------------------------------------------------------------------------

def credential_required(source_id: str, config: dict) -> bool:
    """Whether a credential is mandatory for this source *with this config*.

    Not static per source: a single public docker image scans anonymously, a
    namespace scan does not (10 anonymous pulls/hour per IP).
    """
    src = get_source(source_id)
    cfg = config or {}
    if src.id in ("github", "github_experimental", "gitlab", "postman", "circleci", "travisci"):
        return True
    if src.id == "docker":
        return bool(_text(cfg.get("namespace"))) or _as_bool(cfg.get("includePrivate"))
    if src.id == "s3":
        return not _as_bool(cfg.get("cloudEnvironment"))
    if src.id == "gcs":
        return not (_as_bool(cfg.get("withoutAuth")) or _as_bool(cfg.get("cloudEnvironment")))
    if src.id == "git":
        uri = _text(cfg.get("uri"))
        # Best effort: we cannot tell public from private without trying.
        return uri.startswith("ssh://")
    return False


def required_credentials(source_id: str, config: dict) -> tuple[Credential, ...]:
    """The credentials that must be non-empty before the scan may start.

    Elasticsearch and Jenkins return () because unauthenticated access is itself
    a finding; S3 returns key+secret but not the optional session token.
    """
    if not credential_required(source_id, config):
        return ()
    src = get_source(source_id)
    return tuple(c for c in src.credentials if not c.optional_within_source)


def missing_credentials(source_id: str, config: dict, secrets: dict) -> tuple[Credential, ...]:
    """Which mandatory credentials are absent from ``secrets``.

    ``secrets`` is keyed by ``Credential.settings_key`` (the UserSettings column),
    which is what both the webapp gate and the orchestrator start path have.
    """
    secrets = secrets or {}
    return tuple(
        c for c in required_credentials(source_id, config)
        if not str(secrets.get(c.settings_key) or "").strip()
    )


# ---------------------------------------------------------------------------
# Egress targets (12.4)
# ---------------------------------------------------------------------------

def egress_hosts(source_id: str, config: dict) -> list[str]:
    """Every operator-supplied host this source will reach.

    The orchestrator resolves each and refuses the start on an internal IP, so a
    source cannot be pointed at 169.254.169.254 or the loopback Neo4j.
    """
    src = get_source(source_id)
    cfg = config or {}
    hosts: list[str] = []

    def add_url(value: str) -> None:
        value = _text(value)
        if not value:
            return
        parsed = urlsplit(value if "://" in value else f"//{value}", scheme="https")
        if parsed.hostname:
            hosts.append(parsed.hostname)

    if src.id == "git":
        add_url(cfg.get("uri"))
    elif src.id in ("github", "gitlab", "huggingface"):
        add_url(cfg.get("endpoint"))
    elif src.id == "jenkins":
        add_url(cfg.get("url"))
    elif src.id == "elasticsearch":
        for node in _as_list(cfg.get("nodes")):
            add_url(node)
        # A Cloud ID hides its host in base64, so a config with only a cloud id
        # would present NO host to resolve and skip the guard entirely — while
        # still reaching whatever it decodes to.
        add_url(decode_cloud_id_host(cfg.get("cloudId")))
    elif src.id == "docker":
        # A namespace or image may carry a registry host: ghcr.io/acme/app. Only
        # the first segment of a multi-segment reference can be one — in a bare
        # `nginx:1.25` the colon introduces a TAG, not a port.
        for ref in _as_list(cfg.get("images")) + [_text(cfg.get("namespace"))]:
            if not ref or "/" not in ref:
                continue
            head = ref.split("/")[0]
            if ("." in head or ":" in head) and "@" not in head:
                hosts.append(head.split(":")[0])

    seen: list[str] = []
    for h in hosts:
        h = h.strip().strip(".").lower()
        if h and h not in seen:
            seen.append(h)
    return seen


def decode_cloud_id_host(cloud_id) -> str:
    """The host inside an Elastic Cloud ID, or "" if it does not decode.

    Format is ``<cluster_name>:<base64 of "host$es_uuid$kibana_uuid">``. The host
    is not visible in the raw value, so the egress guard has to decode it or an
    operator could point Elasticsearch at an internal address with nothing to
    resolve. Returns "" rather than raising: a value that does not decode is not
    a host, and `validate_config` is what rejects a malformed one.
    """
    raw = _text(cloud_id)
    if not raw or ":" not in raw:
        return ""
    encoded = raw.split(":", 1)[1].strip()
    if not encoded:
        return ""
    try:
        # Elastic omits padding; restore it before decoding.
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return ""
    host = decoded.split("$", 1)[0].strip()
    # The host segment may carry a port; add_url handles that, but strip any
    # stray scheme so the caller sees a bare host[:port].
    return host


def describe_target(source_id: str, config: dict) -> str:
    """A short human descriptor of what this run scans; stored on TrufflehogScan
    and logged in the audit row (12.9). Never includes a credential."""
    src = get_source(source_id)
    cfg = config or {}
    if src.id == "git":
        local = _text(cfg.get("localRepo"))
        if local:
            return f"local:{local}"
        return _redact_uri(_text(cfg.get("uri")))
    if src.id == "github":
        return ", ".join(_as_list(cfg.get("orgs")) + _as_list(cfg.get("repos")))
    if src.id == "github_experimental":
        return _text(cfg.get("repo"))
    if src.id == "gitlab":
        parts = _as_list(cfg.get("repos")) + [f"group:{g}" for g in _as_list(cfg.get("groupIds"))]
        return ", ".join(parts) or _text(cfg.get("endpoint")) or "gitlab.com (all visible)"
    if src.id == "docker":
        local = [f"local:{n}" for n in _as_list(cfg.get("localImages"))]
        return (", ".join(_as_list(cfg.get("images")) + local)
                or _text(cfg.get("namespace")))
    if src.id == "huggingface":
        parts = (_as_list(cfg.get("orgs")) + _as_list(cfg.get("users"))
                 + _as_list(cfg.get("models")) + _as_list(cfg.get("spaces"))
                 + _as_list(cfg.get("datasets")) + _as_list(cfg.get("buckets")))
        return ", ".join(parts)
    if src.id == "s3":
        return ", ".join(_as_list(cfg.get("buckets"))) or "all reachable buckets"
    if src.id == "gcs":
        return _text(cfg.get("projectId")) or "public buckets"
    if src.id == "filesystem":
        # No target field: the descriptor names the fixed folder so an audit row
        # still says what was scanned.
        return "scan_targets/filesystem"
    if src.id == "jenkins":
        return _text(cfg.get("url"))
    if src.id == "elasticsearch":
        return ", ".join(_as_list(cfg.get("nodes"))) or _text(cfg.get("cloudId"))
    if src.id == "postman":
        parts = (_as_list(cfg.get("workspaceIds")) + _as_list(cfg.get("collectionIds"))
                 + _as_list(cfg.get("environments")))
        return ", ".join(parts)
    return src.label


def _redact_uri(uri: str) -> str:
    """Strip userinfo from a URI so a composed https://user:token@host never
    reaches a log line, a graph property or the audit row."""
    if not uri or "@" not in uri:
        return uri
    try:
        parts = urlsplit(uri)
    except ValueError:
        return uri
    if not parts.netloc or "@" not in parts.netloc:
        return uri
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


# ---------------------------------------------------------------------------
# Shared options (A.1)
# ---------------------------------------------------------------------------

#: The `--results` statuses the UI offers. `filtered_unverified` exists in 3.96.0
#: but is not in the upstream-documented default set.
RESULT_TYPES = ("verified", "unverified", "unknown", "filtered_unverified")
DEFAULT_RESULT_TYPES = ("verified", "unverified", "unknown")

_COMMON_FLAG_SPEC: tuple[tuple[str, str, str], ...] = (
    # (config key, flag, type)
    ("concurrency", "--concurrency", "number"),
    ("includeDetectors", "--include-detectors", "csv"),
    ("excludeDetectors", "--exclude-detectors", "csv"),
    ("filterEntropy", "--filter-entropy", "number"),
    ("detectorTimeout", "--detector-timeout", "text"),
    ("maxDecodeDepth", "--max-decode-depth", "number"),
    ("forceSkipBinaries", "--force-skip-binaries", "toggle"),
    ("forceSkipArchives", "--force-skip-archives", "toggle"),
    ("archiveMaxSize", "--archive-max-size", "bytes"),
    ("archiveMaxDepth", "--archive-max-depth", "number"),
    ("archiveTimeout", "--archive-timeout", "text"),
    ("allowVerificationOverlap", "--allow-verification-overlap", "toggle"),
    ("dropUnverifiedJwtResults", "--drop-unverified-jwt-results", "toggle"),
)


def build_common_flags(common: dict) -> list[str]:
    """Shared (per-project) TruffleHog flags, from the A.1 option set.

    ``skipVerification`` and ``resultTypes`` are deliberately not independent:
    ``--results=verified`` together with ``--no-verification`` asks TruffleHog to
    report only verified results while forbidding it to verify, which returns
    zero findings with no error. When verification is off we emit only
    ``--no-verification`` and drop the result filter entirely.
    """
    common = common or {}
    # --no-update is NOT optional. TruffleHog self-updates on startup, which
    # (a) fails outright on the read-only root filesystem the scan container
    # runs with — "cannot move binary", exit 1, zero findings — and (b) would
    # silently replace the version the Dockerfile deliberately pins and
    # checksum-verifies.
    # --fail-on-scan-errors is NOT optional either. TruffleHog exits 0 even when
    # the scan wholly failed — a nonexistent path, an unreachable host, a
    # rejected token all still exit 0 (verified against the pinned binary). The
    # runner maps "exit 0 and no findings" to `completed`, so without this a scan
    # that never reached its target would be reported as a clean result: the
    # operator reads "0 findings" as "no secrets here".
    flags = ["--json", "--no-update", "--fail-on-scan-errors"]

    skip_verification = _as_bool(common.get("skipVerification"))
    if skip_verification:
        flags.append("--no-verification")
    else:
        results = [r for r in _as_list(common.get("resultTypes")) if r in RESULT_TYPES]
        if results and set(results) != set(DEFAULT_RESULT_TYPES):
            flags.append(f"--results={','.join(results)}")

    for key, flag, ftype in _COMMON_FLAG_SPEC:
        value = common.get(key)
        if ftype == "toggle":
            if _as_bool(value):
                flags.append(flag)
            continue
        if ftype == "number":
            if value in (None, "", 0):
                continue
            flags.append(f"{flag}={value}")
            continue
        if ftype == "csv":
            items = _as_list(value)
            if items:
                flags.append(f"{flag}={','.join(items)}")
            continue
        text = _text(value)
        if text:
            flags.append(f"{flag}={text}")

    return flags


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------

def _pathfile(workdir: Path, source_id: str, key: str, content: str) -> str:
    """Materialise a newline-separated regex list into a file TruffleHog reads."""
    workdir.mkdir(parents=True, exist_ok=True)
    path = workdir / f"{source_id}_{key}.txt"
    lines = [ln.strip() for ln in str(content).splitlines() if ln.strip()]
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def build_source_args(
    source_id: str,
    config: dict,
    workdir: Path,
    env: Optional[dict] = None,
) -> list[str]:
    """Source-specific argv (subcommand + its flags), credentials included.

    ``env`` defaults to ``os.environ``; every credential is read from there so no
    token has to live in ``config``.
    """
    src = get_source(source_id)
    cfg = config or {}
    env = os.environ if env is None else env
    args: list[str] = [src.subcommand]

    positional: list[str] = []

    for f in src.fields:
        if f.client:
            continue
        raw = cfg.get(f.key)

        if f.type == "toggle":
            if not _as_bool(raw):
                continue
            if f.key == "includePrivate":
                # --registry-token carries the credential, not a bare switch.
                token = _text(env.get(CRED_DOCKER.env, ""))
                if token:
                    args.append(f"--registry-token={token}")
                continue
            args.append(f.flag)
            continue

        if f.type == "multi":
            for item in _as_list(raw):
                if f.key == "localImages":
                    path = scan_target_path(src.id, item)
                    # A name that fails validation is DROPPED, not passed
                    # through: validate() already refused the start, and a
                    # fallthrough here would hand the binary a typed path.
                    if path:
                        args.append(f"{f.flag}=file://{path}")
                    continue
                args.append(f"{f.flag}={item}")
            continue

        if f.type == "csv":
            items = _as_list(raw)
            if items:
                args.append(f"{f.flag}={','.join(items)}")
            continue

        if f.type == "pathfile":
            content = _text(raw)
            if content:
                args.append(f"{f.flag}={_pathfile(workdir, src.id, f.key, content)}")
            continue

        value = _text(raw)
        if not value:
            continue
        if not f.flag:
            positional.append(_resolve_positional(src, f, value, env))
            continue
        args.append(f"{f.flag}={value}")

    # The filesystem source has no target field; its root is fixed.
    if src.id == "filesystem":
        positional.append(SCAN_TARGET_DIRS["filesystem"])

    args.extend(src.fixed_args)
    args.extend(_credential_args(src, cfg, env))
    args.extend(positional)
    return args


def _resolve_positional(src: Source, f: Field, value: str, env) -> str:
    """Positional arguments: the git URI (which carries its own credential) and
    the filesystem scan root (which resolves through the allowlist)."""
    if src.id == "git" and f.key == "uri":
        return _compose_git_uri(value, env)
    if src.id == "git" and f.key == "localRepo":
        # Composed, never typed. An invalid name yields "", which validate()
        # has already refused; returning the raw value would be the file
        # disclosure this design exists to prevent.
        return f"file://{scan_target_path(src.id, value)}"
    return value


def _compose_git_uri(uri: str, env) -> str:
    """The git source has no --token; auth rides in the URI.

    Only http(s) URIs get userinfo spliced in, and only when both halves are set.
    The composed URI is never written back to config — it exists for the length of
    one argv (and is redacted from every log line by ``redact``).
    """
    user = _text(env.get(CRED_GIT_USER.env, ""))
    token = _text(env.get(CRED_GIT_TOKEN.env, ""))
    if not token:
        return uri
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https") or not parts.netloc or "@" in parts.netloc:
        return uri
    userinfo = f"{user}:{token}" if user else token
    return urlunsplit((parts.scheme, f"{userinfo}@{parts.netloc}", parts.path,
                       parts.query, parts.fragment))


def _credential_args(src: Source, cfg: dict, env) -> list[str]:
    """Credential flags that must be spliced into argv.

    Almost always empty: TruffleHog 3.96.0 documents an Envar for every
    credential flag (``$GITHUB_TOKEN``, ``$AWS_SECRET_ACCESS_KEY``,
    ``$ELASTICSEARCH_API_KEY``, ...), so the container inherits the value and the
    binary picks it up — no token in the process table, which is what the old
    ``--token=<secret>`` argv did expose. The two exceptions carry
    ``native_env=False``: gcs ``--service-account`` (a path, written by
    ``gcp_service_account_path``) and docker ``--registry-token`` (emitted by the
    ``includePrivate`` toggle, the one flag upstream gives no Envar).
    """
    args: list[str] = []
    for cred in src.credentials:
        if cred.native_env or not cred.flag:
            continue
        if cred is CRED_GCP:
            continue  # resolved by gcp_service_account_path (writes the file first)
        value = _text(env.get(cred.env, ""))
        if value:
            args.append(f"{cred.flag}={value}")
    return args


def gcp_service_account_path(workdir: Path, env: Optional[dict] = None) -> Optional[str]:
    """Write the GCP service-account JSON to the run dir and return its path.

    ``--service-account`` takes a file, not a string, so the blob has to land on
    disk. It goes in the per-run dir (tmpfs in the dirty container), never a
    second mounted volume.
    """
    env = os.environ if env is None else env
    blob = _text(env.get(CRED_GCP.env, ""))
    if not blob:
        return None
    workdir.mkdir(parents=True, exist_ok=True)
    path = workdir / "gcp_service_account.json"
    path.write_text(blob)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return str(path)


def build_command(
    source_id: str,
    config: dict,
    common: dict,
    workdir: Path,
    env: Optional[dict] = None,
    binary: str = "trufflehog",
) -> list[str]:
    """The full argv for one TruffleHog invocation."""
    env = os.environ if env is None else env
    args = [binary] + build_source_args(source_id, config, workdir, env)
    if source_id.replace("-", "_") == "gcs":
        sa_path = gcp_service_account_path(workdir, env)
        if sa_path:
            args.append(f"--service-account={sa_path}")
    return args + build_common_flags(common)


# ---------------------------------------------------------------------------
# Log redaction
# ---------------------------------------------------------------------------

def redact(text: str, env: Optional[dict] = None) -> str:
    """Remove every credential value (and any URI userinfo) from a log line.

    Applied to *both* stdout and the command echo. Value-based rather than
    flag-based: a token can appear inside a composed clone URL where no flag name
    precedes it, which a `--token=` prefix match would miss.
    """
    if not text:
        return text
    env = os.environ if env is None else env
    out = text
    for cred in ALL_CREDENTIALS:
        value = _text(env.get(cred.env, ""))
        # 4 chars, not 6: a short credential is still a credential. The floor
        # exists only so a 1-2 char value cannot blank out unrelated text.
        if len(value) >= 4:
            out = out.replace(value, "***")
    # Any remaining userinfo in a URL (e.g. a token shorter than the threshold).
    out = re.sub(r"(https?://)[^/\s:@]+(:[^/\s@]*)?@", r"\1***@", out)
    return out


def safe_command(cmd: list[str], env: Optional[dict] = None) -> str:
    """A shell-quoted, credential-free rendering of an argv for logging."""
    return redact(" ".join(shlex.quote(c) for c in cmd), env)
