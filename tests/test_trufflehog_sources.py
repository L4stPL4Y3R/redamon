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
                "MultiscannerRepository", "MultiscannerImage", "MultiscannerModel",
                "MultiscannerBucket", "MultiscannerEndpoint",
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

    def test_github_experimental_optional_fields(self):
        # Both are hard to observe from a live scan - a raised threshold only
        # bites when short SHAs actually collide, and the cache flag is disk
        # hygiene - so the argv shape is pinned here instead.
        argv = self.build("github_experimental", {
            "repo": "acme/api", "collisionThreshold": 8, "deleteCachedData": True})
        self.assertIn("--collision-threshold=8", argv)
        self.assertIn("--delete-cached-data", argv)

    def test_github_experimental_omits_the_optional_fields_when_unset(self):
        # The off direction. A number field that emitted --collision-threshold=
        # with an empty value would make the binary reject the whole command.
        argv = self.build("github_experimental", {"repo": "acme/api"})
        self.assertFalse([a for a in argv if a.startswith("--collision-threshold")])
        self.assertNotIn("--delete-cached-data", argv)

    def test_docker_images_and_namespace(self):
        argv = self.build("docker", {"images": ["nginx:1.25", "redis:7"], "namespace": "acme"})
        self.assertIn("--image=nginx:1.25", argv)
        self.assertIn("--image=redis:7", argv)
        self.assertIn("--namespace=acme", argv)

    def test_git_uri_is_positional(self):
        argv = self.build("git", {"uri": "https://github.com/acme/api.git", "branch": "main"})
        self.assertIn("--branch=main", argv)
        # A bare token, not a --flag=, and after the subcommand.
        positionals = [a for a in argv[2:] if not a.startswith("-")]
        self.assertEqual(positionals, ["https://github.com/acme/api.git"])

    def test_filesystem_always_scans_the_fixed_target_folder(self):
        """It takes no target field, so there is no path to type."""
        argv = self.build("filesystem", {})
        self.assertIn(reg.SCAN_TARGET_DIRS["filesystem"], argv)
        self.assertEqual([], reg.validate_config("filesystem", {}))

    def test_a_local_git_repo_is_composed_never_typed(self):
        argv = self.build("git", {"localRepo": "myrepo.git"})
        self.assertIn("file:///scan-targets/git/myrepo.git", argv)

    def test_a_traversing_local_name_never_reaches_argv(self):
        """The scan container holds this source's credential in /work/job.json.
        A composed path is the whole reason a free-text file:// target - which
        would read that token back out as a finding - is not offered."""
        for bad in ("../work/job.json", "/work/job.json", "a/b", "..", "."):
            self.assertFalse(reg.is_valid_scan_target_name(bad), bad)
            self.assertEqual("", reg.scan_target_path("git", bad), bad)
            self.assertNotEqual([], reg.validate_config("git", {"localRepo": bad}), bad)
            argv = self.build("git", {"localRepo": bad})
            self.assertNotIn("job.json", " ".join(argv), bad)

    def test_a_local_docker_tarball_is_composed_never_typed(self):
        argv = self.build("docker", {"localImages": ["img.tar"]})
        self.assertIn("--image=file:///scan-targets/docker/img.tar", argv)
        self.assertNotIn("--image=file:///scan-targets/docker/../x",
                         self.build("docker", {"localImages": ["../x"]}))

    def test_git_takes_one_target_or_the_other(self):
        both = reg.validate_config("git", {"uri": "https://x/y.git", "localRepo": "z"})
        self.assertNotEqual([], both)
        self.assertEqual([], reg.validate_config("git", {"localRepo": "z"}))
        self.assertEqual([], reg.validate_config("git", {"uri": "https://x/y.git"}))
        self.assertNotEqual([], reg.validate_config("git", {}))

    def test_a_local_target_presents_no_host_to_the_egress_guard(self):
        """file:// has no host, so the guard is a natural no-op rather than
        something a local fixture has to be excused from."""
        self.assertEqual([], reg.egress_hosts("git", {"localRepo": "myrepo.git"}))

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
            "gitlab": {"repos": ["https://gitlab.com/acme/api.git"]},
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
        self.assertEqual(reg.build_common_flags({}),
                         ["--json", "--no-update", "--fail-on-scan-errors"])

    def test_scan_errors_are_made_fatal(self):
        # Verified against the pinned binary: without this flag trufflehog exits
        # 0 for a nonexistent path, an unreachable host and a rejected token
        # alike, so a scan that never reached its target would be recorded as
        # `completed` with 0 findings — read by the operator as "no secrets".
        for common in ({}, {"skipVerification": True}, {"concurrency": 4}):
            self.assertIn("--fail-on-scan-errors", reg.build_common_flags(common))

    def test_the_self_updater_is_always_disabled(self):
        # TruffleHog self-updates on startup. On the scan container's read-only
        # root that fails with "cannot move binary" and exit 1 — a scan that
        # reports zero findings for a reason that has nothing to do with the
        # target. It would also replace the pinned, checksum-verified binary.
        for common in ({}, {"skipVerification": True}, {"concurrency": 4}):
            self.assertIn("--no-update", reg.build_common_flags(common))

    def test_every_built_command_disables_the_updater(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            argv = reg.build_command("github", {"orgs": ["a"]}, {}, Path(tmp), env={})
        self.assertIn("--no-update", argv)

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

    def test_filesystem_has_no_target_to_get_wrong(self):
        """The root is fixed, so a stray key cannot redirect the scan."""
        self.assertEqual(reg.validate_config("filesystem", {}), [])
        self.assertEqual(reg.validate_config("filesystem", {"scanRoot": "/etc"}), [])
        argv = reg.build_source_args("filesystem", {"scanRoot": "/etc"}, Path("/tmp"), env={})
        self.assertIn(reg.SCAN_TARGET_DIRS["filesystem"], argv)
        self.assertNotIn("/etc", argv)

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


class TestF2ElasticCloudIdEgress(unittest.TestCase):
    """F2: a Cloud ID hides its host in base64, so a config carrying only a cloud
    id presented NO host to the resolved-IP guard and reached whatever it decoded
    to — including an RFC1918 address, which the bridge network can route."""

    def cloud_id(self, host: str, name: str = "prod") -> str:
        import base64
        return f"{name}:" + base64.b64encode(f"{host}$es_uuid$kb_uuid".encode()).decode()

    def test_f2_the_cloud_id_host_reaches_the_egress_guard(self):
        cid = self.cloud_id("10.0.0.5:9243")
        self.assertEqual(reg.egress_hosts("elasticsearch", {"cloudId": cid}), ["10.0.0.5"])

    def test_f2_a_public_cloud_id_host_is_extracted_too(self):
        cid = self.cloud_id("es.example.com:9243")
        self.assertEqual(reg.egress_hosts("elasticsearch", {"cloudId": cid}), ["es.example.com"])

    def test_f2_nodes_and_cloud_id_are_both_checked(self):
        cid = self.cloud_id("10.0.0.5:9243")
        hosts = reg.egress_hosts("elasticsearch", {"nodes": ["es.example.com:9200"], "cloudId": cid})
        self.assertIn("es.example.com", hosts)
        self.assertIn("10.0.0.5", hosts)

    def test_f2_an_undecodable_cloud_id_is_refused_not_silently_skipped(self):
        # Fail closed: no decodable host means nothing to resolve, so the guard
        # would be skipped entirely while Elastic still tried to connect.
        errors = reg.validate_config("elasticsearch", {"cloudId": "not-base64!!"})
        self.assertTrue(any("Cloud ID" in e for e in errors))

    def test_f2_decode_handles_missing_padding_and_junk(self):
        self.assertEqual(reg.decode_cloud_id_host(""), "")
        self.assertEqual(reg.decode_cloud_id_host("no-colon"), "")
        self.assertEqual(reg.decode_cloud_id_host("name:"), "")
        self.assertEqual(reg.decode_cloud_id_host(None), "")
        # Elastic omits '=' padding; the decoder must restore it.
        import base64
        raw = base64.b64encode(b"h.example.com:9243$a$b").decode().rstrip("=")
        self.assertEqual(reg.decode_cloud_id_host(f"n:{raw}"), "h.example.com:9243")


class TestF6ShortCredentialRedaction(unittest.TestCase):
    """F6: the redaction floor was 6 characters, so a short token survived."""

    def test_f6_a_short_credential_is_still_redacted(self):
        env = {"GITHUB_TOKEN": "abcd"}
        self.assertEqual(reg.redact("token=abcd here", env), "token=*** here")

    def test_f6_a_one_char_value_does_not_blank_unrelated_text(self):
        # The floor exists so a 1-2 char value cannot shred every log line.
        env = {"GITHUB_TOKEN": "a"}
        self.assertEqual(reg.redact("a normal sentence", env), "a normal sentence")


class TestBinaryVerifiedConstraints(unittest.TestCase):
    """Constraints proven against the pinned trufflehog 3.96.0 binary."""

    def test_gitlab_shorthand_repo_is_refused(self):
        # The binary logs "Gitlab requires http/https repo urls" at INFO and then
        # scans nothing for that repo — a silent miss, so refuse it up front.
        errors = reg.validate_config("gitlab", {"repos": ["acme/api"]})
        self.assertTrue(any("full URL" in e for e in errors))
        self.assertTrue(any("https://gitlab.com/acme/api.git" in e for e in errors))

    def test_gitlab_full_url_is_accepted(self):
        self.assertEqual(
            reg.validate_config("gitlab", {"repos": ["https://gitlab.com/acme/api.git"]}), [])

    def test_gitlab_with_no_repos_is_still_legal(self):
        # Empty scans every project the token can reach; that is a real mode.
        self.assertEqual(reg.validate_config("gitlab", {}), [])

    # --- gitlab include-repos is a CONJUNCTION of two globs -----------------
    # Measured against the pinned binary at --log-level=3, scanning a real group
    # of three projects. TruffleHog applies the pattern TWICE per project: once
    # to `group/project` while enumerating ("skipping project ... reason:
    # ignored in config"), and once to `https://host/group/project.git` before
    # scanning. A project is kept only when BOTH match, so a pattern has to
    # survive a string with no scheme and no `.git` AND one carrying both.
    #
    # Observed against a fixture group holding alpha/beta/gamma (<group> is the
    # group path; the real one lives only in the gitignored manifest):
    #     '*a*'          -> alpha, beta, gamma      (both stages match)
    #     '*/a*'         -> alpha                   (both stages match)
    #     '*alpha*'      -> alpha                   (both stages match)
    #     '*alpha'       -> enumerated, 0 findings  (path matched, URL did not)
    #     '<group>/a*'   -> NOTHING                 (path matched, URL did not)
    #     '*.git'        -> NOTHING                 (URL matched, path did not)
    #     'alpha'        -> NOTHING                 (neither matched)

    def test_gitlab_include_repos_needs_leading_and_trailing_star(self):
        # The shape that works on github. It matches the project path, fails the
        # clone URL, and selects NOTHING with no error anywhere.
        errors = reg.validate_config("gitlab", {"includeRepos": ["acme/api*"]})
        self.assertTrue(any("would match nothing" in e for e in errors), errors)
        self.assertTrue(any("*acme/api*" in e for e in errors), errors)

    def test_gitlab_include_repos_wrapped_in_stars_is_accepted(self):
        for pattern in ("*acme/api*", "*/a*", "*a*", "*"):
            self.assertEqual(
                reg.validate_config("gitlab", {"includeRepos": [pattern]}), [],
                f"{pattern!r} matches both strings and must be accepted")

    def test_gitlab_include_repos_half_anchored_is_refused(self):
        # Each of these matched exactly one of the two strings, so each selected
        # nothing while looking perfectly reasonable.
        for pattern in ("*alpha", "alpha*", "*.git", "alpha"):
            self.assertTrue(
                reg.validate_config("gitlab", {"includeRepos": [pattern]}),
                f"{pattern!r} matches only one of the two strings and must be refused")

    def test_gitlab_exclude_repos_is_deliberately_unrestricted(self):
        # Exclusion drops a project when EITHER string matches, so a full-path
        # pattern works there. Proven: --exclude-repos='<group>/b*' dropped beta.
        # Applying the include rule here would refuse a config that works.
        self.assertEqual(
            reg.validate_config("gitlab", {"excludeRepos": ["acme/api*"]}), [])

    def test_github_shorthand_stays_allowed(self):
        # GitHub resolves org/repo through its API; only GitLab is strict.
        self.assertEqual(reg.validate_config("github", {"repos": ["acme/api"]}), [])
