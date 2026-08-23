"""
Unit + regression tests for per-session log routing.

Covers:
  - PerSessionRoutingHandler fans records out to agent.<session_id>.log based on
    the current_log_session_id ContextVar, preserving interleaved order.
  - Records with no bound session fall back to the shared agent.log.
  - I5 secret redaction still runs on the per-session files.
  - Filenames from hostile session ids are sanitised.
  - Open file descriptors are bounded (LRU eviction), and the fallback is never
    evicted; files stay correct even after their handler was evicted.
  - setup_logging honours the LOG_PER_SESSION toggle (routing vs single file).
  - REGRESSION: current_log_session_id is a SEPARATE ContextVar from
    current_session_id, so the per-node set_tenant_context(user, project) call
    (which resets current_session_id to "") does NOT re-route a running
    session's logs. This is the whole reason the extra var exists.
  - REGRESSION: create_config / get_config_values bind the routing key at the
    graph entrypoint (image-only deps -> skipped on host, run in the gate).

Run in the gate with: ./agentic/run_tests.sh tests/test_logging_per_session.py
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import agent_context  # noqa: E402  (import-light, no heavy deps)
import logging_config  # noqa: E402  (imports only project_settings + stdlib)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


class _RoutingBase(unittest.TestCase):
    """Attaches a PerSessionRoutingHandler to a private logger so tests never
    touch the root logger (which pytest and the app also use)."""

    max_open = 64

    def setUp(self):
        agent_context.current_log_session_id.set("")
        self._tmp = tempfile.mkdtemp()
        self.dir = Path(self._tmp)
        fmt = logging.Formatter(
            logging_config.FILE_LOG_FORMAT, datefmt=logging_config.LOG_DATE_FORMAT
        )
        self.handler = logging_config.PerSessionRoutingHandler(
            log_dir=self.dir,
            fallback_name="agent.log",
            formatter=fmt,
            max_bytes=10 * 1024 * 1024,
            backup_count=2,
            max_open=self.max_open,
        )
        # A unique logger name per test id keeps handlers from leaking between tests.
        self.logger = logging.getLogger(f"test.persession.{self.id()}")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.handler.close()
        self.logger.handlers.clear()
        agent_context.current_log_session_id.set("")

    def log_as(self, session_id: str, message: str):
        agent_context.current_log_session_id.set(session_id)
        self.logger.info(message)


class TestRouting(_RoutingBase):
    def test_records_route_to_per_session_files(self):
        self.log_as("session_AAA", "alpha one")
        self.log_as("session_BBB", "bravo one")
        self.log_as("session_AAA", "alpha two")
        self.handler.close()

        a = _read(self.dir / "agent.session_AAA.log")
        b = _read(self.dir / "agent.session_BBB.log")
        self.assertIn("alpha one", a)
        self.assertIn("alpha two", a)
        self.assertNotIn("bravo one", a)
        self.assertIn("bravo one", b)
        self.assertNotIn("alpha one", b)
        # order within a session is preserved
        self.assertLess(a.index("alpha one"), a.index("alpha two"))

    def test_unscoped_records_go_to_fallback(self):
        # no session bound (default "")
        self.logger.info("startup, no session")
        self.log_as("session_ZZZ", "scoped line")
        self.handler.close()

        fallback = _read(self.dir / "agent.log")
        self.assertIn("startup, no session", fallback)
        self.assertNotIn("scoped line", fallback)
        self.assertIn("scoped line", _read(self.dir / "agent.session_ZZZ.log"))

    def test_redaction_applies_to_per_session_files(self):
        self.log_as("session_SEC", "authorization: Bearer abcdef1234567890 trailing")
        self.handler.close()
        content = _read(self.dir / "agent.session_SEC.log")
        self.assertIn("[REDACTED]", content)
        self.assertNotIn("abcdef1234567890", content)

    def test_filename_is_sanitised(self):
        # A hostile session id must not escape the log dir or inject separators.
        self.log_as("../../etc/pwn abc", "sneaky")
        self.handler.close()
        names = os.listdir(self.dir)
        # exactly one per-session file, and it contains no path separators / spaces
        session_files = [n for n in names if n.startswith("agent.") and n != "agent.log"]
        self.assertEqual(len(session_files), 1, names)
        name = session_files[0]
        self.assertNotIn("/", name)
        self.assertNotIn(" ", name)
        self.assertNotIn("..", name)
        # the real guarantee: the resolved file never escapes the log dir
        resolved = (self.dir / name).resolve()
        self.assertEqual(resolved.parent, self.dir.resolve())
        self.assertIn("sneaky", _read(self.dir / name))


class TestEviction(_RoutingBase):
    max_open = 3

    def test_lru_eviction_bounds_open_handlers_and_keeps_files(self):
        # First an unscoped record so the protected fallback handler is cached.
        self.logger.info("fallback line")
        for i in range(10):
            self.log_as(f"session_{i:02d}", f"line for {i}")
        # cache is bounded
        self.assertLessEqual(len(self.handler._handlers), self.max_open)
        # fallback is never evicted
        self.assertIn("agent.log", self.handler._handlers)
        self.handler.close()
        # every session's file still exists with its content, even ones whose
        # in-memory handler was evicted mid-run
        for i in range(10):
            content = _read(self.dir / f"agent.session_{i:02d}.log")
            self.assertIn(f"line for {i}", content)

    def test_evicted_session_reopens_on_late_write(self):
        # Write to A, flood past the cap to evict A, then write to A again.
        self.log_as("session_A", "A first")
        for i in range(5):
            self.log_as(f"session_flood{i}", "x")
        self.log_as("session_A", "A second")
        self.handler.close()
        content = _read(self.dir / "agent.session_A.log")
        self.assertIn("A first", content)
        self.assertIn("A second", content)


class TestSetupToggle(unittest.TestCase):
    """Exercises setup_logging's LOG_PER_SESSION branch. Snapshots and restores
    the root logger + module globals so it does not disturb other tests."""

    def setUp(self):
        self._root = logging.getLogger()
        self._saved_handlers = list(self._root.handlers)
        self._saved_level = self._root.level
        self._saved_log_dir = logging_config.LOG_DIR
        self._saved_module_logs = logging_config.MODULE_LOGS
        self._saved_get_setting = logging_config.get_setting
        self._tmp = tempfile.mkdtemp()
        logging_config.LOG_DIR = Path(self._tmp)
        logging_config.MODULE_LOGS = []  # avoid the root-owned codefix/triage dirs

    def tearDown(self):
        for h in list(self._root.handlers):
            try:
                h.close()
            except Exception:
                pass
        self._root.handlers.clear()
        for h in self._saved_handlers:
            self._root.addHandler(h)
        self._root.setLevel(self._saved_level)
        logging_config.LOG_DIR = self._saved_log_dir
        logging_config.MODULE_LOGS = self._saved_module_logs
        logging_config.get_setting = self._saved_get_setting

    def _patch_setting(self, per_session: bool):
        real = self._saved_get_setting

        def fake(key, default=None):
            if key == "LOG_PER_SESSION":
                return per_session
            return real(key, default)

        logging_config.get_setting = fake

    def _file_handlers(self):
        return [
            h for h in self._root.handlers
            if isinstance(h, (logging_config.RotatingFileHandler,
                              logging_config.PerSessionRoutingHandler))
        ]

    def test_toggle_on_installs_routing_handler(self):
        self._patch_setting(True)
        logging_config.setup_logging(log_to_console=False, log_to_file=True)
        fhs = self._file_handlers()
        self.assertTrue(any(isinstance(h, logging_config.PerSessionRoutingHandler)
                            for h in fhs), fhs)

    def test_toggle_off_installs_single_file_handler(self):
        self._patch_setting(False)
        logging_config.setup_logging(log_to_console=False, log_to_file=True)
        fhs = self._file_handlers()
        self.assertTrue(fhs, "expected a file handler")
        self.assertFalse(any(isinstance(h, logging_config.PerSessionRoutingHandler)
                             for h in fhs), fhs)
        self.assertTrue(all(isinstance(h, logging_config.RotatingFileHandler)
                            for h in fhs), fhs)


class TestSeparateVarRegression(unittest.TestCase):
    """The routing key must survive a node's set_tenant_context(user, project),
    which resets current_session_id to "" mid-run."""

    def setUp(self):
        agent_context.current_log_session_id.set("")
        agent_context.current_session_id.set("")

    def test_set_tenant_context_does_not_clobber_log_session(self):
        agent_context.current_log_session_id.set("session_RUN")
        # A graph node re-asserts tenant context WITHOUT a session id.
        agent_context.set_tenant_context("user-1", "proj-1")
        # current_session_id is intentionally cleared...
        self.assertEqual(agent_context.current_session_id.get(), "")
        # ...but the log routing key must be untouched.
        self.assertEqual(agent_context.current_log_session_id.get(), "session_RUN")

    def test_log_session_var_is_distinct_object(self):
        self.assertIsNot(agent_context.current_log_session_id,
                         agent_context.current_session_id)


class TestConfigBindingRegression(unittest.TestCase):
    """create_config / get_config_values bind the routing key. These import
    orchestrator_helpers.config, which needs image-only deps (pydantic), so they
    skip cleanly on the host and run in the Docker gate."""

    def setUp(self):
        agent_context.current_log_session_id.set("")

    def _cfg(self):
        try:
            from orchestrator_helpers import config as cfg
        except Exception as e:  # pragma: no cover - host without image deps
            self.skipTest(f"orchestrator_helpers.config needs image deps: {e}")
        return cfg

    def test_create_config_binds_log_session(self):
        cfg = self._cfg()
        cfg.create_config("u", "p", "session_FROM_CONFIG")
        self.assertEqual(agent_context.current_log_session_id.get(),
                         "session_FROM_CONFIG")

    def test_get_config_values_binds_real_session(self):
        cfg = self._cfg()
        config = {"configurable": {"user_id": "u", "project_id": "p",
                                   "session_id": "session_FROM_VALUES"}}
        cfg.get_config_values(config)
        self.assertEqual(agent_context.current_log_session_id.get(),
                         "session_FROM_VALUES")

    def test_get_config_values_unknown_does_not_clobber(self):
        cfg = self._cfg()
        agent_context.current_log_session_id.set("session_KEEP")
        # a config missing session_id yields "unknown" and must NOT overwrite
        cfg.get_config_values({"configurable": {"user_id": "u", "project_id": "p"}})
        self.assertEqual(agent_context.current_log_session_id.get(), "session_KEEP")


class TestFlagDetection(unittest.TestCase):
    """session_log.detect_flags underpins the flag_captured event."""

    def setUp(self):
        import session_log  # host-importable (stdlib only)
        self.detect = session_log.detect_flags

    def test_detects_common_shapes(self):
        self.assertEqual(self.detect("here is flag{abc_123}"), ["flag{abc_123}"])
        self.assertEqual(self.detect("FLAG{UP_CASE}"), ["FLAG{UP_CASE}"])
        self.assertEqual(self.detect("nahamcon{win}"), ["nahamcon{win}"])

    def test_no_false_positive(self):
        self.assertEqual(self.detect("no flags here, just a { brace"), [])
        self.assertEqual(self.detect(""), [])
        self.assertEqual(self.detect(None), [])

    def test_skips_css_and_identifier_lookalikes(self):
        # CSS selectors / identifiers are the common false positive
        self.assertEqual(self.detect(".flag{color:red}"), [])
        self.assertEqual(self.detect("#flag{display:none}"), [])
        self.assertEqual(self.detect("my-flag{x}"), [])
        self.assertEqual(self.detect("keyflag{x}"), [])
        # 'key{...}' is not a recognised prefix (too collision-prone)
        self.assertEqual(self.detect("key{value}"), [])
        # but a real flag at a word boundary still matches
        self.assertEqual(self.detect("Response: flag{real_one}"), ["flag{real_one}"])
        self.assertEqual(self.detect("<p>FLAG{html_ok}</p>"), ["FLAG{html_ok}"])

    def test_dedup_preserves_order(self):
        out = self.detect("flag{a} noise flag{b} flag{a}")
        self.assertEqual(out, ["flag{a}", "flag{b}"])

    def test_multiline_body_is_bounded(self):
        # a runaway "{" with no close on the line must not match across newlines
        self.assertEqual(self.detect("flag{" + "\n" + "x}"), [])


class TestEventStream(_RoutingBase):
    """log_event() writes one JSON object per line to the per-session jsonl."""

    def setUp(self):
        super().setUp()
        import session_log
        self.session_log = session_log
        # Re-point the events logger at our tmp dir via a jsonl routing handler.
        self.events_logger = __import__("logging").getLogger("session_events")
        self._saved = list(self.events_logger.handlers)
        self._saved_level = self.events_logger.level
        self.events_logger.handlers.clear()
        self.events_logger.setLevel(__import__("logging").INFO)
        self.events_logger.propagate = False
        self.events_handler = logging_config.PerSessionRoutingHandler(
            log_dir=self.dir,
            fallback_name="agent.events.jsonl",
            formatter=__import__("logging").Formatter("%(message)s"),
            max_bytes=10 * 1024 * 1024,
            backup_count=2,
            name_template="agent.{session}.events.jsonl",
        )
        self.events_logger.addHandler(self.events_handler)

    def tearDown(self):
        self.events_handler.close()
        self.events_logger.handlers.clear()
        self.events_logger.setLevel(self._saved_level)
        for h in self._saved:
            self.events_logger.addHandler(h)
        super().tearDown()

    def test_event_written_as_json_to_session_file(self):
        import json
        agent_context.current_log_session_id.set("session_EVT")
        self.session_log.log_event("flag_captured", session="session_EVT",
                                   iteration=7, tool="execute_curl", flag="flag{x}")
        self.events_handler.close()
        path = self.dir / "agent.session_EVT.events.jsonl"
        lines = [l for l in _read(path).splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        obj = json.loads(lines[0])
        self.assertEqual(obj["kind"], "flag_captured")
        self.assertEqual(obj["flag"], "flag{x}")
        self.assertEqual(obj["iteration"], 7)

    def test_events_route_by_session_and_never_hit_prose_log(self):
        agent_context.current_log_session_id.set("session_E1")
        self.session_log.log_event("decision", action="plan_tools")
        agent_context.current_log_session_id.set("session_E2")
        self.session_log.log_event("decision", action="complete")
        self.events_handler.close()
        self.assertIn("plan_tools",
                      _read(self.dir / "agent.session_E1.events.jsonl"))
        self.assertIn("complete",
                      _read(self.dir / "agent.session_E2.events.jsonl"))
        # events must not leak into the prose per-session log
        self.assertFalse((self.dir / "agent.session_E1.log").exists())

    def test_secret_in_field_stays_valid_json_and_redacted(self):
        import json
        agent_context.current_log_session_id.set("session_SECRET")
        # an error field carrying a token shape that abuts the JSON closing quote
        self.session_log.log_event("tool_result", session="session_SECRET",
                                   error="Authorization=abcdef1234567890")
        self.events_handler.close()
        path = self.dir / "agent.session_SECRET.events.jsonl"
        lines = [l for l in _read(path).splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        obj = json.loads(lines[0])  # must be valid JSON despite the secret
        self.assertIn("[REDACTED]", obj["error"])
        self.assertNotIn("abcdef1234567890", obj["error"])

    def test_log_event_never_raises(self):
        # non-serialisable value falls back to str(), still one line, no raise
        agent_context.current_log_session_id.set("session_SAFE")
        self.session_log.log_event("weird", obj=object())
        self.events_handler.close()
        self.assertTrue((self.dir / "agent.session_SAFE.events.jsonl").exists())


class TestSetupInstallsEventStream(TestSetupToggle):
    def test_toggle_on_installs_event_stream_logger(self):
        self._patch_setting(True)  # LOG_PER_SESSION True; LOG_EVENT_STREAM default True
        logging_config.setup_logging(log_to_console=False, log_to_file=True)
        ev = logging.getLogger("session_events")
        self.assertFalse(ev.propagate)
        self.assertTrue(any(isinstance(h, logging_config.PerSessionRoutingHandler)
                            for h in ev.handlers), ev.handlers)

    def test_event_stream_off_still_isolates_logger(self):
        # LOG_EVENT_STREAM off: the logger must still NOT propagate (so unconditional
        # log_event calls can't leak JSON into the prose log/console) and must carry
        # only a NullHandler, not a routing handler.
        real = self._saved_get_setting

        def fake(key, default=None):
            if key == "LOG_PER_SESSION":
                return True
            if key == "LOG_EVENT_STREAM":
                return False
            return real(key, default)

        logging_config.get_setting = fake
        logging_config.setup_logging(log_to_console=False, log_to_file=True)
        ev = logging.getLogger("session_events")
        self.assertFalse(ev.propagate)
        self.assertFalse(any(isinstance(h, logging_config.PerSessionRoutingHandler)
                             for h in ev.handlers), ev.handlers)
        self.assertTrue(any(isinstance(h, logging.NullHandler) for h in ev.handlers))


if __name__ == "__main__":
    unittest.main(verbosity=2)
