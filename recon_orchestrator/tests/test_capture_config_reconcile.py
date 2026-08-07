"""
Unit/integration tests for the orchestrator's DB->file reconciler helpers
(_fetch_capture_config, _atomic_write, _capture_config_reconcile) — the control
plane half of "DB is the single source of truth" for the capture proxy.

Asserts:
  - a successful webapp fetch is atomically materialised to the config file;
  - a webapp error (non-200 / exception -> None) NEVER clobbers the last-good file;
  - _atomic_write leaves no partial / .tmp turd and writes exact content.

Run: python3 -m unittest tests.test_capture_config_reconcile   (from /app in the
recon-orchestrator container).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import api  # noqa: E402


class TestAtomicWrite(unittest.TestCase):
    def test_writes_exact_content_no_tmp_left(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", ".capture-config.json")  # nested dir auto-created
            api._atomic_write(path, '{"a":1}')
            with open(path) as fh:
                self.assertEqual(fh.read(), '{"a":1}')
            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_overwrite_is_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            api._atomic_write(path, "v1")
            api._atomic_write(path, "v2")
            with open(path) as fh:
                self.assertEqual(fh.read(), "v2")


class TestEnsureSpoolShared(unittest.TestCase):
    """Issue #159: this root process is the first mounter of the shared spool
    volume, so it must leave the mount point writable by the capture containers'
    non-root uid or they crash-loop on mkdir /spool/.tmp."""

    def test_creates_dir_world_writable(self):
        with tempfile.TemporaryDirectory() as d:
            spool = os.path.join(d, "spool")
            api._ensure_spool_shared(spool)
            self.assertTrue(os.path.isdir(spool))
            self.assertEqual(os.stat(spool).st_mode & 0o777, 0o777)

    def test_repairs_existing_root_owned_style_dir(self):
        # The already-broken-in-the-field case: dir exists at 0755, must be widened.
        with tempfile.TemporaryDirectory() as d:
            spool = os.path.join(d, "spool")
            os.makedirs(spool, mode=0o755)
            os.chmod(spool, 0o755)
            api._ensure_spool_shared(spool)
            self.assertEqual(os.stat(spool).st_mode & 0o777, 0o777)

    def test_never_raises_when_chmod_fails(self):
        # A read-only / unowned mount must degrade to a warning, never kill the
        # reconciler task (which would strand the proxy fail-closed).
        with tempfile.TemporaryDirectory() as d:
            spool = os.path.join(d, "spool")
            with mock.patch.object(api.os, "chmod", side_effect=PermissionError("nope")):
                api._ensure_spool_shared(spool)  # must not raise
            self.assertTrue(os.path.isdir(spool))

    def test_atomic_write_normalises_the_dir(self):
        with tempfile.TemporaryDirectory() as d:
            spool = os.path.join(d, "spool")
            api._atomic_write(os.path.join(spool, ".capture-config.json"), "{}")
            self.assertEqual(os.stat(spool).st_mode & 0o777, 0o777)


class TestFetchCaptureConfig(unittest.TestCase):
    def _mock_urlopen(self, status, body):
        cm = mock.MagicMock()
        resp = mock.MagicMock()
        resp.status = status
        resp.read.return_value = body.encode() if isinstance(body, str) else body
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False
        return cm

    def test_200_returns_parsed_dict(self):
        payload = json.dumps({"egress": {"block_private": False}, "source": "db"})
        with mock.patch("urllib.request.urlopen", return_value=self._mock_urlopen(200, payload)):
            got = api._fetch_capture_config("http://webapp/x", "key")
        self.assertEqual(got["egress"]["block_private"], False)

    def test_non_200_returns_none(self):
        with mock.patch("urllib.request.urlopen", return_value=self._mock_urlopen(503, "err")):
            self.assertIsNone(api._fetch_capture_config("http://webapp/x", "key"))

    def test_exception_returns_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("boom")):
            self.assertIsNone(api._fetch_capture_config("http://webapp/x", "key"))

    def test_200_with_garbage_body_returns_none(self):
        # A 200 whose body is not JSON must NOT be materialised (would corrupt the
        # file / crash the proxy parse) — return None so the last-good file survives.
        with mock.patch("urllib.request.urlopen", return_value=self._mock_urlopen(200, "<html>not json</html>")):
            self.assertIsNone(api._fetch_capture_config("http://webapp/x", "key"))


class TestReconcileLoop(unittest.TestCase):
    def _run_one_iteration(self, fetch_result, path):
        """Drive exactly one reconcile iteration by making asyncio.sleep abort the loop."""
        async def _stop_sleep(_):
            raise asyncio.CancelledError

        async def _fake_to_thread(fn, *a, **k):
            return fn(*a, **k)

        with mock.patch.object(api, "_fetch_capture_config", return_value=fetch_result), \
             mock.patch.object(api.asyncio, "sleep", _stop_sleep), \
             mock.patch.object(api.asyncio, "to_thread", _fake_to_thread), \
             mock.patch.dict(os.environ, {"CAPTURE_CONFIG_FILE": path,
                                          "INTERNAL_API_KEY": "k",
                                          "WEBAPP_API_URL": "http://webapp:3000"}, clear=False):
            try:
                asyncio.run(api._capture_config_reconcile())
            except asyncio.CancelledError:
                pass

    def test_successful_fetch_materialises_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".capture-config.json")
            cfg = {"egress": {"block_private": False}, "body": {}, "enabled": True, "source": "db"}
            self._run_one_iteration(cfg, path)
            self.assertTrue(os.path.exists(path))
            with open(path) as fh:
                written = json.load(fh)
            self.assertEqual(written["egress"]["block_private"], False)

    def test_repairs_spool_even_when_webapp_is_down(self):
        # No successful fetch means no write, but the operator can still toggle
        # capture on and spawn the non-root proxy against this volume (#159).
        with tempfile.TemporaryDirectory() as d:
            spool = os.path.join(d, "spool")
            os.makedirs(spool, mode=0o755)
            os.chmod(spool, 0o755)
            self._run_one_iteration(None, os.path.join(spool, ".capture-config.json"))
            self.assertEqual(os.stat(spool).st_mode & 0o777, 0o777)

    def test_webapp_error_keeps_last_good_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".capture-config.json")
            api._atomic_write(path, '{"last":"good"}')       # simulate an existing good file
            self._run_one_iteration(None, path)              # webapp returns None
            with open(path) as fh:
                self.assertEqual(json.load(fh), {"last": "good"})  # untouched

    def test_rewrites_when_file_deleted_out_of_band(self):
        # Self-heal: if the file vanishes (deleted volume) while the DB payload is
        # unchanged, the next iteration must re-materialise it (not stay dedup'd out).
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".capture-config.json")
            cfg = {"egress": {"block_private": False}, "enabled": True}
            state = {"n": 0}

            async def sleep_hook(_):
                state["n"] += 1
                if state["n"] == 1:
                    os.remove(path)               # delete after the 1st write
                else:
                    raise asyncio.CancelledError  # stop after the 2nd iteration

            async def _fake_to_thread(fn, *a, **k):
                return fn(*a, **k)

            with mock.patch.object(api, "_fetch_capture_config", return_value=cfg), \
                 mock.patch.object(api.asyncio, "sleep", sleep_hook), \
                 mock.patch.object(api.asyncio, "to_thread", _fake_to_thread), \
                 mock.patch.dict(os.environ, {"CAPTURE_CONFIG_FILE": path,
                                              "INTERNAL_API_KEY": "k"}, clear=False):
                try:
                    asyncio.run(api._capture_config_reconcile())
                except asyncio.CancelledError:
                    pass
            self.assertTrue(os.path.exists(path), "file must be re-materialised after deletion")


if __name__ == "__main__":
    unittest.main()
