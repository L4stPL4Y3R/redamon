"""GVM scan hardening - regression tests for issue #174.

Three independent defects put a GVM scan into a state where it ran for 18 hours
and produced nothing:

  1. The scan read its project settings with INTERNAL_API_KEY, but the
     orchestrator hands scan containers the SCOPED SCANNER_API_KEY, so the webapp
     answered 401 and every user-chosen setting was silently replaced by defaults.
  2. gvmd lists the OpenVAS scanner from its own database, so the scan connected
     happily even though ospd-openvas was never started, then sat at 0% until the
     4h task timeout - once per target, 1140 targets.
  3. (compose-side, covered by tests/redamon_gvm_compose_test.sh)

These tests pin 1 and 2.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402
from gvm_scan import project_settings as gvm_settings  # noqa: E402
from github_secret_hunt import project_settings as hunt_settings  # noqa: E402


def _json_response(payload):
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class ScannerTokenTest(unittest.TestCase):
    """The scan must present the token it was actually given."""

    def test_gvm_settings_fetch_sends_the_scanner_token(self):
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok",
                                            "INTERNAL_API_KEY": "master-tok"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        sent = get.call_args.kwargs["headers"]["X-Internal-Key"]
        self.assertEqual(sent, "scoped-tok",
                         "the GVM scan must send SCANNER_API_KEY, not the master key")

    def test_gvm_settings_fetch_falls_back_to_the_master_key(self):
        """Pre-secret installs have no SCANNER_API_KEY; those must not break."""
        env = {"INTERNAL_API_KEY": "master-tok"}
        with mock.patch.dict("os.environ", env, clear=True), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        self.assertEqual(get.call_args.kwargs["headers"]["X-Internal-Key"], "master-tok")

    def test_gvm_settings_are_applied_not_defaulted(self):
        """The 401 made every project value fall back to DEFAULT_GVM_SETTINGS."""
        project = {"gvmScanConfig": "Discovery", "gvmScanTargets": "ips_only",
                   "gvmTaskTimeout": 600, "gvmPollInterval": 5,
                   "gvmCleanupAfterScan": False}
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response(project)):
            settings = gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        self.assertEqual(settings["SCAN_CONFIG"], "Discovery")
        self.assertEqual(settings["TASK_TIMEOUT"], 600)
        self.assertNotEqual(settings["TASK_TIMEOUT"],
                            gvm_settings.DEFAULT_GVM_SETTINGS["TASK_TIMEOUT"])

    def test_github_hunt_sends_the_scanner_token_on_both_calls(self):
        """The hunt reads the project AND the user's GitHub token; both were 401."""
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok",
                                            "INTERNAL_API_KEY": "master-tok",
                                            "USER_ID": "user-1"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            hunt_settings.fetch_github_settings("proj-1", "http://webapp:3000")

        self.assertGreaterEqual(get.call_count, 2, "expected a project and a user-settings call")
        for call in get.call_args_list:
            self.assertEqual(call.kwargs["headers"]["X-Internal-Key"], "scoped-tok")

    def test_no_scanner_reads_the_master_key_alone(self):
        """Structural: the next scanner added must not repeat the omission.

        The S3/E6 rollout updated recon and supply-chain but missed gvm_scan and
        github_secret_hunt, and nothing failed until a live scan 401'd.
        """
        offenders = []
        for settings_file in sorted((REPO_ROOT / "scanners").glob("*/project_settings.py")):
            # Comments are stripped first: the whole point is what the CODE sends,
            # and every one of these call sites carries a comment naming the key.
            lines = [ln.split("#", 1)[0] for ln in settings_file.read_text().splitlines()]
            for lineno, line in enumerate(lines, 1):
                if "X-Internal-Key" not in line:
                    continue
                # The credential may be built on a preceding line (supply-chain) or
                # wrapped onto the next one (gvm, hunt), so look either side.
                window = "\n".join(lines[max(0, lineno - 4):lineno + 2])
                if "SCANNER_API_KEY" not in window:
                    offenders.append(f"{settings_file.relative_to(REPO_ROOT)}:{lineno}")
        self.assertEqual(offenders, [],
                         "these scanners send only the master key and will 401: "
                         + ", ".join(offenders))


def _task(status, progress, report_id="report-1"):
    return ET.fromstring(
        f'<get_tasks_response><task id="task-1">'
        f'<status>{status}</status><progress>{progress}</progress>'
        f'<report id="{report_id}"/></task></get_tasks_response>'
    )


def _scanner(**overrides):
    """A GVMScanner built without python-gvm present (the agent test image)."""
    with mock.patch.object(gvm_mod, "GVM_AVAILABLE", True):
        s = gvm_mod.GVMScanner(socket_path="/tmp/none", username="u", password="p",
                               scan_config="Full and fast", task_timeout=0, poll_interval=0)
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


class ScannerLivenessTest(unittest.TestCase):
    """A scanner row in gvmd's database is not a running scanner."""

    @staticmethod
    def _verify_response(status, status_text="detail"):
        return ET.fromstring(
            f'<verify_scanner_response status="{status}" status_text="{status_text}"/>'
        )

    def test_unreachable_scanner_is_rejected(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = self._verify_response(
            "500", "Service temporarily down")

        with self.assertRaises(RuntimeError) as ctx:
            s._verify_scanner_alive()
        self.assertIn("not reachable", str(ctx.exception))
        self.assertIn("ospd", str(ctx.exception))

    def test_reachable_scanner_passes(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = self._verify_response("200", "OK")
        s._verify_scanner_alive()   # must not raise

    def test_a_service_down_status_is_what_blocks(self):
        for status in gvm_mod.GVMScanner.SCANNER_DOWN_STATUSES:
            with self.subTest(status=status):
                s = _scanner()
                s.scanner_id = "scanner-1"
                s.gmp = mock.Mock()
                s.gmp.verify_scanner.return_value = self._verify_response(
                    status, "Service temporarily down")
                with self.assertRaises(RuntimeError):
                    s._verify_scanner_alive()

    def test_an_inconclusive_reply_never_vetoes_a_healthy_stack(self):
        """A probe that can block a working scan is worse than no probe."""
        for status in ("400", "404", "401", ""):
            with self.subTest(status=status):
                s = _scanner()
                s.scanner_id = "scanner-1"
                s.gmp = mock.Mock()
                s.gmp.verify_scanner.return_value = self._verify_response(
                    status, "Bad command")
                s._verify_scanner_alive()   # no verdict is not a failure

    def test_a_raising_verify_does_not_block_the_scan(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.side_effect = OSError("socket closed")
        s._verify_scanner_alive()   # must not raise

    def test_connect_verifies_liveness(self):
        """The probe has to be ON the connect path, not merely defined."""
        src = (REPO_ROOT / "scanners/gvm_scan/gvm_scanner.py").read_text()
        connect_body = src.split("def connect(", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("self._verify_scanner_alive()", connect_body)


class StallWatchdogTest(unittest.TestCase):
    """A task nothing is running must fail in minutes, not in four hours."""

    class _Clock:
        """time.time() advancing a fixed step per call."""

        def __init__(self, step=60.0):
            self.now = 0.0
            self.step = step

        def __call__(self):
            self.now += self.step
            return self.now

    def test_a_task_that_never_progresses_is_abandoned(self):
        # task_timeout stays at the shipped 4h so this test is BOUNDED: strip the
        # watchdog and it raises TimeoutError instead of looping forever, which is
        # a clean red rather than a hung suite.
        s = _scanner(no_progress_timeout=1800, task_timeout=14400)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "0")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            with self.assertRaises(RuntimeError) as ctx:
                s.wait_for_task("task-1")

        message = str(ctx.exception)
        self.assertIn("no progress", message)
        self.assertIn("redamon-gvm-ospd", message)

    def test_minus_one_progress_also_trips_it(self):
        """gvmd reports -1 for a task that has produced nothing at all."""
        s = _scanner(no_progress_timeout=600, task_timeout=14400)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "-1")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            with self.assertRaises(RuntimeError):
                s.wait_for_task("task-1")

    def test_a_slow_but_advancing_scan_is_never_cut_off(self):
        """The watchdog measures time since the last MOVE, not since the start."""
        s = _scanner(no_progress_timeout=120)
        s.gmp = mock.Mock()
        # Each poll advances by 1%, far slower than the 120s watchdog window,
        # then finishes. A start-relative timer would kill this scan.
        s.gmp.get_task.side_effect = (
            [_task("Running", str(p)) for p in range(1, 40)] + [_task("Done", "100")]
        )

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            status, report_id = s.wait_for_task("task-1")

        self.assertEqual(status, "Done")
        self.assertEqual(report_id, "report-1")

    def test_a_finished_task_is_reported_even_with_no_progress_number(self):
        """Terminal status wins over the watchdog."""
        s = _scanner(no_progress_timeout=1)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Done", "-1")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    def test_the_watchdog_can_be_disabled(self):
        s = _scanner(no_progress_timeout=0, task_timeout=100)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "0")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            # With the watchdog off, only the task timeout stops it.
            with self.assertRaises(TimeoutError):
                s.wait_for_task("task-1")

    def test_default_is_far_below_the_task_timeout(self):
        defaults = gvm_settings.DEFAULT_GVM_SETTINGS
        self.assertGreater(defaults["NO_PROGRESS_TIMEOUT"], 0)
        self.assertLess(defaults["NO_PROGRESS_TIMEOUT"], defaults["TASK_TIMEOUT"],
                        "a watchdog that outlasts the task timeout never fires")


class FailureStreakTest(unittest.TestCase):
    """A broken stack fails every target, so the scan must stop asking."""

    def setUp(self):
        from gvm_scan import main as gvm_main
        self.main = gvm_main

    @staticmethod
    def _failed(error="Task made no progress for 1800s"):
        return {"status": "error", "error": error, "vulnerabilities": []}

    @staticmethod
    def _ok():
        return {"status": "Done", "vulnerability_count": 2, "vulnerabilities": []}

    def test_failures_below_the_limit_keep_scanning(self):
        streak = 0
        for i in range(self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1):
            streak = self.main.check_failure_streak(self._failed(), streak, f"10.0.0.{i}")
        self.assertEqual(streak, self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1)

    def test_the_limit_aborts_the_scan(self):
        streak = self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1
        with self.assertRaises(self.main.ScanAborted) as ctx:
            self.main.check_failure_streak(self._failed(), streak, "10.0.0.9")
        message = str(ctx.exception)
        self.assertIn("redamon-gvm-ospd", message)
        self.assertIn("10.0.0.9", message)

    def test_a_working_target_resets_the_streak(self):
        """Targets legitimately fail one at a time; only a RUN of them is systemic."""
        streak = self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1
        streak = self.main.check_failure_streak(self._ok(), streak, "10.0.0.1")
        self.assertEqual(streak, 0)
        # ...and the next failure therefore starts counting again from one.
        streak = self.main.check_failure_streak(self._failed(), streak, "10.0.0.2")
        self.assertEqual(streak, 1)

    def test_both_scan_phases_use_the_breaker(self):
        """IP and hostname phases are separate loops; neither may be left out."""
        src = (REPO_ROOT / "scanners/gvm_scan/main.py").read_text()
        self.assertEqual(src.count("check_failure_streak("), 3,
                         "expected the helper definition plus one call per scan phase")


class ScannerlessStackTest(unittest.TestCase):
    """End to end on the reported symptom, through the real code paths.

    Reproduces the state the issue was filed from: gvmd is up and accepts
    everything, but nothing is running the scans. Before the fix this walked
    1140 targets at 4h each; here it must give up after MAX_CONSECUTIVE_TARGET_
    FAILURES, having spent one stall window per target.
    """

    def test_the_scan_gives_up_instead_of_walking_1140_targets(self):
        from gvm_scan import main as gvm_main

        scanner = _scanner(no_progress_timeout=1800, task_timeout=14400)
        scanner.config_id = "cfg-1"
        scanner.scanner_id = "scanner-1"
        scanner.port_list_id = "pl-1"
        # A gvmd with no scanner behind it: every call succeeds, the task is
        # accepted, and it then sits at 0% forever.
        gmp = mock.Mock()
        gmp.create_target.return_value = ET.fromstring('<r status="201" id="tgt-1"/>')
        gmp.create_task.return_value = ET.fromstring('<r status="201" id="task-1"/>')
        gmp.start_task.return_value = ET.fromstring(
            '<r status="202"><report_id>rep-1</report_id></r>')
        gmp.get_task.return_value = _task("Running", "0")
        scanner.gmp = gmp

        targets = [f"10.0.0.{n}" for n in range(1, 1141)]
        attempted = 0
        streak = 0

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(gvm_main.ScanAborted) as ctx:
                for ip in targets:
                    attempted += 1
                    result = scanner.scan_targets(targets=[ip], target_name=f"IP_{ip}",
                                                  cleanup=False)
                    streak = gvm_main.check_failure_streak(result, streak, ip)

        self.assertEqual(attempted, gvm_main.MAX_CONSECUTIVE_TARGET_FAILURES,
                         "the scan must stop after the streak limit, not grind on")
        self.assertLess(attempted, len(targets))
        self.assertIn("redamon-gvm-ospd", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
