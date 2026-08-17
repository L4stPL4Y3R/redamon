"""TruffleHog run-keying: parallel sources, one run per source, correct keys.

C3 is the whole design: the run key IS the source id, which gives "no duplicate
sources, unlimited distinct sources" with no counter to maintain and no
trufflehog-specific cap to tune. These tests pin that, plus the two key formats
that must agree (admission and reconcile) — a mismatch there makes the 30 s
reaper free a live scan's reservation and the governor over-admit into OOM.
"""

import asyncio
import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import TrufflehogState, TrufflehogStatus  # noqa: E402


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def make_manager():
    """A ContainerManager with no Docker daemon and no real ledger."""
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = MagicMock()
    m.running_states = {}
    m.gvm_states = {}
    m.github_hunt_states = {}
    m.supply_chain_states = {}
    m.partial_recon_states = {}
    m.ai_attack_states = {}
    m.trufflehog_states = {}
    m.codefix_sandboxes = {}
    m.guarddog_jobs = set()
    m.trufflehog_image = "redamon-trufflehog:latest"
    m.trufflehog_network = "redamon-trufflehog-net"
    m.trufflehog_scan_roots = {}
    m.trufflehog_scope_checker = None
    m.ledger = MagicMock()
    m.ledger.envelope_for.return_value = 805306368
    # get_trufflehog_status hands Docker inspection to this pool (_run_blocking).
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    return m


def running(project_id, source):
    return TrufflehogState(
        project_id=project_id, user_id="u1", source=source, run_id=source,
        status=TrufflehogStatus.RUNNING, container_id=f"c-{source}",
    )


class TestRunKeys(unittest.TestCase):
    def test_admission_kind_is_source_qualified(self):
        m = make_manager()
        self.assertEqual(m._trufflehog_kind("docker"), "trufflehog:docker")
        self.assertEqual(m._trufflehog_kind(""), "trufflehog")

    def test_reservation_key_matches_between_admission_and_reconcile(self):
        """The reaper frees any reservation whose key is not in
        _active_scan_keys. If admission and reconcile build different keys, a
        live scan's RAM is released and the next admit over-commits."""
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}

        admission_key = m._scan_key(m._trufflehog_kind("docker"), "p1", "docker")
        self.assertIn(admission_key, m._active_scan_keys())

    def test_each_parallel_source_holds_its_own_reservation(self):
        m = make_manager()
        m.trufflehog_states = {
            "p1": {"docker": running("p1", "docker"), "huggingface": running("p1", "huggingface")},
        }
        keys = m._active_scan_keys()
        self.assertIn("trufflehog:docker:p1:docker", keys)
        self.assertIn("trufflehog:huggingface:p1:huggingface", keys)

    def test_terminal_runs_release_their_reservation(self):
        m = make_manager()
        done = running("p1", "docker")
        done.status = TrufflehogStatus.COMPLETED
        m.trufflehog_states = {"p1": {"docker": done}}
        self.assertEqual(
            [k for k in m._active_scan_keys() if k.startswith("trufflehog")], [])

    def test_container_names_are_per_source(self):
        """A shared name would make starting docker force-remove a live
        huggingface container."""
        m = make_manager()
        self.assertNotEqual(
            m._get_trufflehog_container_name("p1", "docker"),
            m._get_trufflehog_container_name("p1", "huggingface"),
        )

    def test_container_name_sanitises_both_parts(self):
        m = make_manager()
        name = m._get_trufflehog_container_name("p/1", "github experimental")
        self.assertNotIn("/", name)
        self.assertNotIn(" ", name)

    def test_run_dirs_are_per_source(self):
        m = make_manager()
        self.assertNotEqual(
            m._trufflehog_run_dir("p1", "docker"),
            m._trufflehog_run_dir("p1", "huggingface"),
        )


class TestEnumerations(unittest.TestCase):
    """Six sites walk the state dict; a flat walk on a nested dict either leaks
    reservations or silently under-counts."""

    def test_active_scan_projects_sees_a_nested_run(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}
        self.assertIn("p1", m.active_scan_projects())

    def test_active_scan_projects_ignores_a_project_whose_runs_all_finished(self):
        m = make_manager()
        done = running("p1", "docker")
        done.status = TrufflehogStatus.COMPLETED
        m.trufflehog_states = {"p1": {"docker": done}}
        self.assertNotIn("p1", m.active_scan_projects())

    def test_running_count_counts_runs_not_projects(self):
        """/health and the dispatcher's admission accounting read this. Counting
        projects would report three parallel sources as one."""
        m = make_manager()
        m.trufflehog_states = {
            "p1": {"docker": running("p1", "docker"), "s3": running("p1", "s3")},
            "p2": {"github": running("p2", "github")},
        }
        self.assertEqual(m.get_trufflehog_running_count(), 3)

    def test_running_count_includes_starting(self):
        m = make_manager()
        st = running("p1", "docker")
        st.status = TrufflehogStatus.STARTING
        m.trufflehog_states = {"p1": {"docker": st}}
        self.assertEqual(m.get_trufflehog_running_count(), 1)


class TestStartGates(unittest.TestCase):
    """Every gate must fail closed BEFORE a reservation or container exists."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=AssertionError("must not admit"))
        # No real DNS in the gate tests; the egress guard has its own suite.
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

    def start(self, **kw):
        params = dict(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source="github",
            config={"orgs": ["acme"]}, common={},
            secrets={"trufflehogGithubToken": "ghp_x"},
        )
        params.update(kw)
        return run(self.m.start_trufflehog(**params))

    def test_unknown_source_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.start(source="slack")
        self.assertIn("unknown trufflehog source", str(ctx.exception))

    def test_invalid_config_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.start(config={})
        self.assertIn("organization", str(ctx.exception))

    def test_missing_mandatory_credential_is_refused_server_side(self):
        # Re-checked here and not only in the UI: a queued job can reach dispatch
        # long after the operator cleared the key.
        with self.assertRaises(ValueError) as ctx:
            self.start(secrets={})
        self.assertIn("GitHub Token", str(ctx.exception))
        self.assertIn("API Keys", str(ctx.exception))

    def test_optional_credential_source_starts_without_one(self):
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        with self.assertRaises(RuntimeError):
            self.start(source="jenkins", config={"url": "https://ci.example.com"}, secrets={})

    def test_nothing_is_registered_when_a_gate_refuses(self):
        with self.assertRaises(ValueError):
            self.start(config={})
        self.assertEqual(self.m.trufflehog_states, {})

    def test_same_source_twice_is_refused(self):
        self.m.trufflehog_states = {"p1": {"github": running("p1", "github")}}
        self.m.client.containers.get.return_value = MagicMock(status="running")
        with self.assertRaises(ValueError) as ctx:
            self.start()
        self.assertIn("already running", str(ctx.exception))

    def test_a_different_source_reaches_admission(self):
        """The whole point of C3: docker and huggingface coexist."""
        self.m.trufflehog_states = {"p1": {"github": running("p1", "github")}}
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        with self.assertRaises(RuntimeError):
            self.start(source="docker", config={"images": ["nginx:1.25"]}, secrets={})


class TestEgressGuard(unittest.TestCase):
    """12.4: deny on the RESOLVED IP, before spawning, fail closed."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))

    def start(self, source, config, secrets=None):
        return run(self.m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source=source,
            config=config, common={}, secrets=secrets or {},
        ))

    def test_loopback_target_is_refused(self):
        with patch.object(cm_mod, "classify_host",
                          return_value=(False, None, "internal-ip:127.0.0.1")):
            with self.assertRaises(ValueError) as ctx:
                self.start("jenkins", {"url": "http://127.0.0.1:7687"})
        self.assertIn("not allowed", str(ctx.exception))

    def test_cloud_metadata_target_is_refused(self):
        with patch.object(cm_mod, "classify_host",
                          return_value=(False, None, "internal-ip:169.254.169.254")):
            with self.assertRaises(ValueError):
                self.start("elasticsearch", {"nodes": ["169.254.169.254:9200"]})

    def test_unresolvable_target_is_refused(self):
        # Fails closed: no resolved IP means no decision, which means no scan.
        with patch.object(cm_mod, "classify_host", return_value=(False, None, "unresolvable")):
            with self.assertRaises(ValueError):
                self.start("jenkins", {"url": "https://nope.invalid"})

    def test_public_target_passes_the_guard(self):
        with patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok")):
            with self.assertRaises(RuntimeError):  # reached admission
                self.start("jenkins", {"url": "https://ci.example.com"})

    def test_sources_with_no_host_skip_the_guard_entirely(self):
        # circleci's target is defined by its token; there is nothing to resolve.
        with patch.object(cm_mod, "classify_host",
                          side_effect=AssertionError("nothing to classify")):
            with self.assertRaises(RuntimeError):
                self.start("circleci", {}, {"trufflehogCircleciToken": "t"})

    def test_guard_can_be_disabled_only_by_an_explicit_env_opt_out(self):
        with patch.dict(os.environ, {"TRUFFLEHOG_EGRESS_GUARD": "off"}):
            with patch.object(cm_mod, "classify_host",
                              side_effect=AssertionError("guard should be skipped")):
                with self.assertRaises(RuntimeError):
                    self.start("jenkins", {"url": "http://127.0.0.1:8080"})


class TestScopeCheck(unittest.TestCase):
    """12.5: a source may not be pointed outside the project's authorised scope."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

    def start(self, source="docker", config=None):
        return run(self.m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source=source,
            config=config or {"images": ["nginx:1.25"]}, common={}, secrets={},
        ))

    def test_out_of_scope_target_is_refused(self):
        self.m.trufflehog_scope_checker = lambda pid, src, target: (False, "not in ROE")
        with self.assertRaises(ValueError) as ctx:
            self.start()
        self.assertIn("outside the project scope", str(ctx.exception))

    def test_in_scope_target_proceeds(self):
        self.m.trufflehog_scope_checker = lambda pid, src, target: (True, "")
        with self.assertRaises(RuntimeError):
            self.start()

    def test_scope_check_receives_the_redacted_target_descriptor(self):
        seen = {}

        def checker(pid, src, target):
            seen["target"] = target
            return (True, "")

        self.m.trufflehog_scope_checker = checker
        with self.assertRaises(RuntimeError):
            self.start("git", {"uri": "https://svc:glpat_secret@git.example.com/a.git"})
        self.assertNotIn("glpat_secret", seen["target"])

    def test_no_checker_configured_is_a_no_op(self):
        self.m.trufflehog_scope_checker = None
        with self.assertRaises(RuntimeError):
            self.start()


if __name__ == "__main__":
    unittest.main()


class TestDirtyContainerShape(unittest.TestCase):
    """12.3: what the scan container may and may not reach.

    The source-text assertions are deliberate: the spawn kwargs are what a future
    reviewer is most likely to "clean up", and every one of them was chosen
    against a specific failure.
    """

    def _spawn_source(self) -> str:
        import inspect
        src = inspect.getsource(cm_mod.ContainerManager)
        start = src.index("    async def start_trufflehog(")
        return src[start:src.index("\n    def _trufflehog_credential_env(", start)]

    def test_no_host_networking(self):
        # On host networking a target of 127.0.0.1:7687 resolves straight into
        # RedAmon's own Neo4j.
        spawn = self._spawn_source()
        self.assertNotIn('network_mode="host"', spawn)
        self.assertIn("network=self.trufflehog_network", spawn)

    def test_capabilities_dropped_and_root_filesystem_read_only(self):
        spawn = self._spawn_source()
        self.assertIn('cap_drop=["ALL"]', spawn)
        self.assertIn("read_only=True", spawn)
        self.assertIn("tmpfs=", spawn)

    def test_the_source_tree_is_mounted_read_only(self):
        # rw would let a compromised scan rewrite the scanner and persist into
        # every future run.
        spawn = self._spawn_source()
        self.assertIn('"/app/trufflehog_scan", "mode": "ro"', spawn.replace('"bind": ', ''))

    def test_no_secret_beyond_the_one_source_credential(self):
        spawn = self._spawn_source()
        for forbidden in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD",
                          "_scanner_env(", "WEBAPP_API_URL", "INTERNAL_API_KEY"):
            self.assertNotIn(forbidden, spawn, f"{forbidden} must not reach the scan container")
        self.assertIn("_trufflehog_credential_env(src, secrets)", spawn)

    def test_cap_drop_is_safe_here_because_nothing_host_owned_is_written(self):
        """cap_drop=ALL broke recon precisely because that container writes a
        host-owned bind mount as root. This one writes ONLY its own scratch dir
        (chmod 0o777 by the orchestrator); the findings are published to the
        shared output dir by the orchestrator afterwards."""
        spawn = self._spawn_source()
        self.assertIn('"output_file": "/work/out.json"', spawn)
        # The shared output dir must NOT be mounted into the container.
        self.assertNotIn('"/out"', spawn)
        self.assertIn("os.chmod(run_dir, 0o777)", spawn)

    def test_only_this_sources_credentials_are_injected(self):
        m = make_manager()
        github = cm_mod.th_sources.get_source("github")
        env = m._trufflehog_credential_env(github, {
            "trufflehogGithubToken": "ghp_x",
            "trufflehogAwsSecretKey": "aws_should_not_travel",
        })
        self.assertEqual(env, {"GITHUB_TOKEN": "ghp_x"})

    def test_credential_env_names_are_the_ones_trufflehog_documents(self):
        # The binary reads these itself, which is how the token stays out of argv.
        m = make_manager()
        es = cm_mod.th_sources.get_source("elasticsearch")
        env = m._trufflehog_credential_env(es, {
            "trufflehogElasticApiKey": "k", "trufflehogElasticUsername": "u",
        })
        self.assertEqual(sorted(env), ["ELASTICSEARCH_API_KEY", "ELASTICSEARCH_USERNAME"])

    def test_blank_credentials_are_not_injected(self):
        m = make_manager()
        github = cm_mod.th_sources.get_source("github")
        self.assertEqual(m._trufflehog_credential_env(github, {"trufflehogGithubToken": "  "}), {})

    def test_filesystem_scan_roots_are_server_resolved(self):
        m = make_manager()
        m.trufflehog_scan_roots = {"recon_output": "/host/recon/output"}
        mounts = m._trufflehog_scan_root_mounts("filesystem", {"scanRoot": "recon_output"})
        self.assertEqual(mounts, {"/host/recon/output": {"bind": "/scan-roots/recon_output", "mode": "ro"}})

    def test_an_unconfigured_scan_root_is_simply_not_mounted(self):
        # Better an empty dir than a guessed host path.
        m = make_manager()
        m.trufflehog_scan_roots = {}
        self.assertEqual(m._trufflehog_scan_root_mounts("filesystem", {"scanRoot": "recon_output"}), {})

    def test_an_operator_typed_path_is_never_mounted(self):
        m = make_manager()
        m.trufflehog_scan_roots = {"recon_output": "/host/recon/output"}
        self.assertEqual(m._trufflehog_scan_root_mounts("filesystem", {"scanRoot": "/etc"}), {})

    def test_other_sources_get_no_scan_root_mount(self):
        m = make_manager()
        m.trufflehog_scan_roots = {"recon_output": "/host/recon/output"}
        self.assertEqual(m._trufflehog_scan_root_mounts("docker", {"scanRoot": "recon_output"}), {})


class TestAuditability(unittest.TestCase):
    """12.9: reconstructing who scanned which target with which key — from the
    log alone, and without the log ever holding a secret."""

    def test_the_start_log_names_the_credential_field_never_its_value(self):
        import inspect
        src = inspect.getsource(cm_mod.ContainerManager.start_trufflehog)
        self.assertIn("c.settings_key", src)
        # The VALUE must never be interpolated into a log line.
        self.assertNotIn("secrets.get(c.settings_key)}", src)
        self.assertIn("target: {target}", src)
        self.assertIn("user: {user_id}", src)
