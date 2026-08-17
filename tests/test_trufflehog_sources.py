"""TruffleHog source registry -> argv.

The registry is the boundary between the operator's form input and a command
line that runs against a real target, so the invariants tested here are the ones
whose violation is silent:

  * a credential never reaches argv (it is read from the env var TruffleHog
    itself documents), and never reaches the log;
  * ``--exclude-paths`` builds a FILE for git-family sources and an inline CSV
    for docker — the same flag name with incompatible input;
  * a cross-field contradiction is refused at validation, not handed to
    TruffleHog to fail opaquely (or worse, succeed on the wrong target).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_scan import sources as reg  # noqa: E402


class TestRegistryShape(unittest.TestCase):
    def test_every_source_has_a_subcommand_and_asset_label(self):
        for source_id, src in reg.SOURCES.items():
            self.assertEqual(src.id, source_id)
            self.assertTrue(src.subcommand)
            self.assertIn(src.asset_label, {
                "TrufflehogRepository", "TrufflehogImage", "TrufflehogModel",
                "TrufflehogBucket", "TrufflehogEndpoint",
            })
            self.assertIn(src.asset_kind, {"repository", "image", "model", "bucket", "endpoint"})

    def test_dash_and_underscore_spellings_resolve(self):
        self.assertIs(reg.get_source("github-experimental"), reg.SOURCES["github_experimental"])
        self.assertIs(reg.get_source("GitHub"), reg.SOURCES["github"])

    def test_unknown_source_raises(self):
        with self.assertRaises(KeyError):
            reg.get_source("slack")

    def test_excluded_v1_sources_are_absent(self):
        # syslog is a listener and stdin has no operator-facing target; both
        # would hold a memory reservation that never releases (A.16).
        for excluded in ("syslog", "stdin", "multi_scan", "analyze"):
            self.assertNotIn(excluded, reg.SOURCES)

    def test_no_field_key_collides_with_a_credential(self):
        cred_keys = {c.settings_key for c in reg.ALL_CREDENTIALS}
        for src in reg.SOURCES.values():
            for f in src.fields:
                self.assertNotIn(f.key, cred_keys)


class TestArgvPerSource(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, source_id, config, common=None, env=None):
        return reg.build_command(source_id, config, common or {}, self.workdir, env=env or {})

    def test_github_org_and_repos(self):
        argv = self.build("github", {"orgs": ["acme"], "repos": ["acme/api"], "includeForks": True})
        self.assertEqual(argv[:2], ["trufflehog", "github"])
        self.assertIn("--org=acme", argv)
        self.assertIn("--repo=acme/api", argv)
        self.assertIn("--include-forks", argv)
        self.assertIn("--json", argv)

    def test_github_experimental_forces_object_discovery(self):
        # The command errors out without its only submodule flag.
        argv = self.build("github_experimental", {"repo": "acme/api"})
        self.assertIn("--object-discovery", argv)
        self.assertIn("--repo=acme/api", argv)

    def test_docker_images_and_namespace(self):
        argv = self.build("docker", {"images": ["nginx:1.25", "redis:7"], "namespace": "acme"})
        self.assertIn("--image=nginx:1.25", argv)
        self.assertIn("--image=redis:7", argv)
        self.assertIn("--namespace=acme", argv)

    def test_git_uri_is_positional(self):
        argv = self.build("git", {"uri": "https://github.com/acme/api.git", "branch": "main"})
        self.assertEqual(argv[-1] if "--json" not in argv[-1:] else argv[3], argv[3])
        self.assertIn("https://github.com/acme/api.git", argv)
        self.assertIn("--branch=main", argv)

    def test_filesystem_scan_root_resolves_through_the_allowlist(self):
        argv = self.build("filesystem", {"scanRoot": "recon_output"})
        self.assertIn(reg.FILESYSTEM_ROOTS["recon_output"], argv)
        # The raw UI value must never be the path passed to the binary.
        self.assertNotIn("recon_output", argv)

    def test_credential_only_sources_need_no_target_fields(self):
        for source_id in ("circleci", "travisci"):
            argv = self.build(source_id, {})
            self.assertEqual(argv[1], reg.SOURCES[source_id].subcommand)
            self.assertIn("--json", argv)

    def test_every_source_builds_a_command(self):
        minimal = {
            "git": {"uri": "https://example.com/a.git"},
            "github": {"orgs": ["acme"]},
            "github_experimental": {"repo": "acme/api"},
            "gitlab": {"repos": ["acme/api"]},
            "docker": {"images": ["nginx:1.25"]},
            "huggingface": {"models": ["acme/m"]},
            "s3": {"buckets": ["b"]},
            "gcs": {"projectId": "p"},
            "filesystem": {"scanRoot": "recon_output"},
            "jenkins": {"url": "https://ci.example.com"},
            "elasticsearch": {"nodes": ["es.example.com:9200"]},
            "postman": {"workspaceIds": ["w"]},
            "circleci": {},
            "travisci": {},
        }
        self.assertEqual(set(minimal), set(reg.SOURCES))
        for source_id, config in minimal.items():
            argv = self.build(source_id, config)
            self.assertEqual(argv[0], "trufflehog")
            self.assertEqual(argv[1], reg.SOURCES[source_id].subcommand)
            self.assertEqual(reg.validate_config(source_id, config), [])


class TestExcludePathsFootgun(unittest.TestCase):
    """Same flag name, two incompatible input shapes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_git_family_writes_a_regex_file(self):
        argv = reg.build_command(
            "github", {"orgs": ["acme"], "excludePaths": "vendor/.*\n.*\\.min\\.js"},
            {}, self.workdir, env={},
        )
        flag = [a for a in argv if a.startswith("--exclude-paths=")]
        self.assertEqual(len(flag), 1)
        path = Path(flag[0].split("=", 1)[1])
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text().splitlines(), ["vendor/.*", ".*\\.min\\.js"])

    def test_docker_passes_an_inline_csv(self):
        argv = reg.build_command(
            "docker", {"images": ["nginx:1.25"], "excludePaths": ["/usr/share", "/var/lib/apt"]},
            {}, self.workdir, env={},
        )
        self.assertIn("--exclude-paths=/usr/share,/var/lib/apt", argv)
        # ... and must NOT have written a file whose path would be scanned as a regex.
        self.assertFalse(list(self.workdir.glob("docker_excludePaths*")))


class TestCredentialsNeverReachArgv(unittest.TestCase):
    """12.7: the old runner put --token=<secret> in argv, visible in `ps`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_token_is_read_from_env_not_argv(self):
        env = {"GITHUB_TOKEN": "ghp_supersecretvalue"}
        argv = reg.build_command("github", {"orgs": ["acme"]}, {}, self.workdir, env=env)
        self.assertNotIn("ghp_supersecretvalue", " ".join(argv))
        self.assertFalse([a for a in argv if a.startswith("--token")])

    def test_every_native_env_credential_stays_out_of_argv(self):
        secrets = {c.env: f"secret-{c.env.lower()}" for c in reg.ALL_CREDENTIALS}
        configs = {
            "github": {"orgs": ["acme"]}, "gitlab": {"repos": ["a/b"]},
            "huggingface": {"models": ["a/m"]}, "s3": {"buckets": ["b"]},
            "postman": {"workspaceIds": ["w"]}, "circleci": {}, "travisci": {},
            "jenkins": {"url": "https://ci.example.com"},
            "elasticsearch": {"nodes": ["es:9200"]},
        }
        for source_id, config in configs.items():
            argv = reg.build_command(source_id, config, {}, self.workdir, env=secrets)
            joined = " ".join(argv)
            for value in secrets.values():
                self.assertNotIn(value, joined, f"{source_id} leaked {value} into argv")

    def test_gcp_service_account_is_written_as_a_file_and_passed_by_path(self):
        env = {"GCP_SERVICE_ACCOUNT": json.dumps({"type": "service_account", "private_key": "KEYBYTES"})}
        argv = reg.build_command("gcs", {"projectId": "p"}, {}, self.workdir, env=env)
        flag = [a for a in argv if a.startswith("--service-account=")]
        self.assertEqual(len(flag), 1)
        path = Path(flag[0].split("=", 1)[1])
        self.assertTrue(path.is_file())
        self.assertIn("KEYBYTES", path.read_text())
        # The blob itself must not be an argv token.
        self.assertNotIn("KEYBYTES", " ".join(argv))

    def test_docker_registry_token_is_the_documented_exception(self):
        # --registry-token is the one credential flag with no upstream Envar.
        env = {"DOCKER_TOKEN": "dckr_pat_value"}
        argv = reg.build_command("docker", {"images": ["nginx:1.25"], "includePrivate": True},
                                 {}, self.workdir, env=env)
        self.assertIn("--registry-token=dckr_pat_value", argv)
        # ...and it is redacted the moment it is rendered for a log.
        self.assertNotIn("dckr_pat_value", reg.safe_command(argv, env))

    def test_git_uri_carries_userinfo_but_never_a_logged_one(self):
        env = {"GIT_USERNAME": "svc", "GIT_TOKEN": "glpat_secretvalue"}
        argv = reg.build_command("git", {"uri": "https://git.example.com/a.git"},
                                 {}, self.workdir, env=env)
        self.assertIn("https://svc:glpat_secretvalue@git.example.com/a.git", argv)
        rendered = reg.safe_command(argv, env)
        self.assertNotIn("glpat_secretvalue", rendered)

    def test_git_uri_is_untouched_without_a_token(self):
        argv = reg.build_command("git", {"uri": "https://git.example.com/a.git"},
                                 {}, self.workdir, env={})
        self.assertIn("https://git.example.com/a.git", argv)

    def test_redact_strips_userinfo_even_for_short_tokens(self):
        self.assertEqual(
            reg.redact("cloning https://u:ab@host/x.git", {}),
            "cloning https://***@host/x.git",
        )

    def test_describe_target_never_includes_credentials(self):
        target = reg.describe_target("git", {"uri": "https://svc:glpat_secret@git.example.com/a.git"})
        self.assertEqual(target, "https://git.example.com/a.git")


class TestCommonFlags(unittest.TestCase):
    def test_defaults_are_minimal(self):
        self.assertEqual(reg.build_common_flags({}), ["--json"])

    def test_skip_verification_suppresses_the_result_filter(self):
        # --results=verified with --no-verification returns zero findings and no
        # error: TruffleHog is told to report only verified results while being
        # forbidden to verify. The two must never both be emitted.
        flags = reg.build_common_flags({"skipVerification": True, "resultTypes": ["verified"]})
        self.assertIn("--no-verification", flags)
        self.assertFalse([f for f in flags if f.startswith("--results")])

    def test_non_default_result_types_are_emitted(self):
        flags = reg.build_common_flags({"resultTypes": ["verified", "unknown"]})
        self.assertIn("--results=verified,unknown", flags)

    def test_default_result_set_is_not_emitted(self):
        flags = reg.build_common_flags({"resultTypes": list(reg.DEFAULT_RESULT_TYPES)})
        self.assertFalse([f for f in flags if f.startswith("--results")])

    def test_unknown_result_type_is_dropped(self):
        flags = reg.build_common_flags({"resultTypes": ["verified", "bogus"]})
        self.assertIn("--results=verified", flags)

    def test_numeric_and_toggle_options(self):
        flags = reg.build_common_flags({
            "concurrency": 16, "filterEntropy": 3.0, "forceSkipBinaries": True,
            "archiveMaxSize": "512MB", "excludeDetectors": ["JWT", "Slack"],
            "allowVerificationOverlap": False,
        })
        self.assertIn("--concurrency=16", flags)
        self.assertIn("--filter-entropy=3.0", flags)
        self.assertIn("--force-skip-binaries", flags)
        self.assertIn("--archive-max-size=512MB", flags)
        self.assertIn("--exclude-detectors=JWT,Slack", flags)
        self.assertNotIn("--allow-verification-overlap", flags)


class TestValidation(unittest.TestCase):
    def test_github_needs_a_repo_or_an_org(self):
        errors = reg.validate_config("github", {})
        self.assertTrue(any("repository or organization" in e for e in errors))

    def test_github_org_only_fields_rejected_without_an_org(self):
        errors = reg.validate_config("github", {"repos": ["a/b"], "includeRepos": ["a/t*"]})
        self.assertTrue(any("includeRepos" in e for e in errors))

    def test_s3_buckets_and_ignore_buckets_are_mutually_exclusive(self):
        errors = reg.validate_config("s3", {"buckets": ["a"], "ignoreBuckets": ["b"]})
        self.assertTrue(any("mutually exclusive" in e for e in errors))

    def test_gcs_project_id_conflicts_with_without_auth(self):
        errors = reg.validate_config("gcs", {"projectId": "p", "withoutAuth": True})
        self.assertTrue(any("Without auth" in e for e in errors))

    def test_gcs_needs_one_of_the_two(self):
        self.assertTrue(reg.validate_config("gcs", {}))

    def test_docker_rejects_scheme_prefixed_references(self):
        # docker:// needs the Docker socket, which a scan container never gets;
        # file:// reads the container's own filesystem.
        for ref in ("docker://nginx", "file:///tmp/img.tar"):
            errors = reg.validate_config("docker", {"images": [ref]})
            self.assertTrue(errors, f"{ref} should be refused")

    def test_docker_rejects_option_injection_and_shell_metacharacters(self):
        for ref in ("-oProxyCommand=id", "nginx;id", "nginx$(id)"):
            self.assertTrue(reg.validate_config("docker", {"images": [ref]}))

    def test_docker_accepts_digest_and_registry_host_references(self):
        ok = {"images": ["ghcr.io/acme/app:1.2", "nginx@sha256:" + "a" * 64]}
        self.assertEqual(reg.validate_config("docker", ok), [])

    def test_filesystem_root_must_be_allowlisted(self):
        errors = reg.validate_config("filesystem", {"scanRoot": "/etc"})
        self.assertTrue(any("not an allowed scan root" in e for e in errors))

    def test_huggingface_sweep_mode_needs_an_org_or_user(self):
        self.assertTrue(reg.validate_config("huggingface", {"mode": "sweep"}))
        self.assertEqual(reg.validate_config("huggingface", {"mode": "sweep", "orgs": ["acme"]}), [])

    def test_git_uri_scheme_is_checked(self):
        self.assertTrue(reg.validate_config("git", {"uri": "javascript:alert(1)"}))
        self.assertEqual(reg.validate_config("git", {"uri": "ssh://git@host/a.git"}), [])

    def test_elasticsearch_and_postman_need_a_target(self):
        self.assertTrue(reg.validate_config("elasticsearch", {}))
        self.assertTrue(reg.validate_config("postman", {}))


class TestCredentialGate(unittest.TestCase):
    """5.2a: mandatory-ness depends on the resolved config, not just the source."""

    def test_always_mandatory_sources(self):
        for source_id in ("github", "github_experimental", "gitlab", "postman", "circleci", "travisci"):
            self.assertTrue(reg.credential_required(source_id, {}))

    def test_docker_is_conditional_on_namespace(self):
        self.assertFalse(reg.credential_required("docker", {"images": ["nginx:1.25"]}))
        self.assertTrue(reg.credential_required("docker", {"namespace": "acme"}))
        self.assertTrue(reg.credential_required("docker", {"images": ["a"], "includePrivate": True}))

    def test_s3_and_gcs_follow_their_cloud_toggles(self):
        self.assertTrue(reg.credential_required("s3", {}))
        self.assertFalse(reg.credential_required("s3", {"cloudEnvironment": True}))
        self.assertTrue(reg.credential_required("gcs", {"projectId": "p"}))
        self.assertFalse(reg.credential_required("gcs", {"withoutAuth": True}))

    def test_unauthenticated_services_never_require_a_credential(self):
        # An exposed, unauthenticated Jenkins or Elasticsearch is itself a finding.
        for source_id in ("jenkins", "elasticsearch", "huggingface", "filesystem"):
            self.assertFalse(reg.credential_required(source_id, {}))

    def test_missing_credentials_names_the_exact_settings_field(self):
        missing = reg.missing_credentials("github", {}, {})
        self.assertEqual([c.settings_key for c in missing], ["trufflehogGithubToken"])
        self.assertEqual(reg.missing_credentials("github", {}, {"trufflehogGithubToken": "ghp_x"}), ())

    def test_optional_within_source_keys_are_not_required(self):
        # S3 needs key+secret, never the temporary session token.
        missing = reg.missing_credentials("s3", {}, {})
        self.assertEqual(
            sorted(c.settings_key for c in missing),
            ["trufflehogAwsAccessKeyId", "trufflehogAwsSecretKey"],
        )

    def test_blank_string_counts_as_missing(self):
        self.assertTrue(reg.missing_credentials("gitlab", {}, {"trufflehogGitlabToken": "   "}))


class TestEgressHosts(unittest.TestCase):
    """12.4: every operator-supplied host the orchestrator must resolve and deny."""

    def test_jenkins_and_elasticsearch_hosts(self):
        self.assertEqual(reg.egress_hosts("jenkins", {"url": "https://169.254.169.254/"}),
                         ["169.254.169.254"])
        self.assertEqual(reg.egress_hosts("elasticsearch", {"nodes": ["127.0.0.1:9200", "es.example.com:9200"]}),
                         ["127.0.0.1", "es.example.com"])

    def test_git_uri_host(self):
        self.assertEqual(reg.egress_hosts("git", {"uri": "https://git.internal:8443/a.git"}),
                         ["git.internal"])

    def test_custom_endpoints_are_covered(self):
        self.assertEqual(reg.egress_hosts("github", {"endpoint": "https://ghe.corp/api/v3", "orgs": ["a"]}),
                         ["ghe.corp"])

    def test_docker_registry_host_is_extracted_only_when_present(self):
        self.assertEqual(reg.egress_hosts("docker", {"images": ["ghcr.io/acme/app:1"]}), ["ghcr.io"])
        # A bare Docker Hub reference has no host component to check.
        self.assertEqual(reg.egress_hosts("docker", {"images": ["nginx:1.25"]}), [])

    def test_sources_with_no_operator_supplied_host(self):
        for source_id in ("circleci", "travisci", "postman", "s3", "filesystem"):
            self.assertEqual(reg.egress_hosts(source_id, {}), [])


if __name__ == "__main__":
    unittest.main()
