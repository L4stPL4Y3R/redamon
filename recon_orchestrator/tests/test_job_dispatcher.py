"""
Scan Queue — the queue dispatcher worker (plan Phase 2).

The dispatcher is a TICKER, not the thing that reserves: the webapp's dispatch
route runs the start path and try_admit inside it owns admission (R1). What must
hold here:

  - it head-of-line reserves: a big job that does not fit the ledger budget BLOCKS
    the smaller jobs behind it (anti-starvation) rather than being skipped,
  - it applies its OWN concurrency ceiling (JOB_QUEUE_MAX_CONCURRENT),
  - it defers the whole tick when free disk is below the floor,
  - a capacity-bound dispatch block (ram/hard) stops the walk; a per-project block
    (agent_running/busy) lets later jobs through,
  - it NEVER calls try_admit,
  - a single bad response never kills the loop.

Run: python3 -m unittest tests.test_job_dispatcher   (from /app in the
recon-orchestrator container).
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import job_dispatcher as jd  # noqa: E402

MB = 1024 ** 2
GB = 1024 ** 3


class _Ledger:
    def __init__(self, remaining=8000 * MB, envelopes=None):
        self._remaining = remaining
        self._envelopes = envelopes or {}
        self.admit_calls = []

    def remaining_for_new(self):
        return self._remaining

    def envelope_for(self, kind):
        return self._envelopes.get(kind, 2000 * MB)

    async def try_admit(self, *a, **kw):  # must never be called by the dispatcher
        self.admit_calls.append((a, kw))
        raise AssertionError("the dispatcher must not reserve; the start path owns admission")


class _Manager:
    def __init__(self, ledger=None):
        self.ledger = ledger if ledger is not None else _Ledger()


def _cand(id_, kind="full_recon", project="p1", envelope=2000 * MB, priority=0):
    return {
        "id": id_, "kind": kind, "projectId": project, "userId": "u1",
        "envelopeBytes": envelope, "priority": priority,
        "enqueuedAt": "2026-08-09T00:00:00Z", "attempts": 0, "maxAttempts": 20,
    }


def _run_tick(responses, manager=None, disk=(500 * GB, 400 * GB)):
    """Drive one tick with a scripted request_json + disk_stats; returns (summary, calls)."""
    calls = []

    def fake_request(url, key, method="GET", payload=None, timeout=15.0, tag="webapp"):
        calls.append({"url": url, "method": method, "payload": payload})
        for pattern, value in responses:
            if pattern in url:
                return value() if callable(value) else value
        return None

    with mock.patch.dict(os.environ, {
        "INTERNAL_API_KEY": "test-key",
        "WEBAPP_API_URL": "http://webapp:3000",
    }), mock.patch.object(jd, "request_json", side_effect=fake_request), \
            mock.patch.object(jd.rg, "disk_stats", return_value=disk):
        summary = jd.run_dispatcher_tick(manager or _Manager())
    return summary, calls


class TestConfig(unittest.TestCase):
    def test_enabled_by_default_and_switchable(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(jd.dispatcher_enabled())
        for off in ("false", "0", "no", "off"):
            with mock.patch.dict(os.environ, {"JOB_QUEUE_DISPATCHER_ENABLED": off}):
                self.assertFalse(jd.dispatcher_enabled())

    def test_tick_interval_has_a_floor(self):
        with mock.patch.dict(os.environ, {"JOB_QUEUE_TICK_SECONDS": "1"}):
            self.assertEqual(jd.tick_seconds(), jd.MIN_TICK_SECONDS)
        with mock.patch.dict(os.environ, {"JOB_QUEUE_TICK_SECONDS": "x"}):
            self.assertEqual(jd.tick_seconds(), jd.DEFAULT_TICK_SECONDS)

    def test_max_concurrent_default_and_override(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(jd.max_concurrent(), jd._FALLBACK_MAX_CONCURRENT)
        with mock.patch.dict(os.environ, {"JOB_QUEUE_MAX_CONCURRENT": "2"}):
            self.assertEqual(jd.max_concurrent(), 2)


class TestTick(unittest.TestCase):
    def test_nothing_queued_is_a_no_op(self):
        summary, calls = _run_tick([("/candidates", {"candidates": [], "activeCount": 0})])
        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(summary["dispatched"], 0)
        self.assertEqual(len([c for c in calls if "/dispatch" in c["url"]]), 0)

    def test_dispatches_a_fitting_job(self):
        summary, calls = _run_tick([
            ("/candidates", {"candidates": [_cand("j1")], "activeCount": 0}),
            ("/dispatch", {"ok": True, "runId": "r1"}),
        ])
        self.assertEqual(summary["dispatched"], 1)
        disp = [c for c in calls if "/dispatch" in c["url"]]
        self.assertEqual(len(disp), 1)
        self.assertEqual(disp[0]["method"], "POST")
        self.assertIn("/api/internal/job-queue/j1/dispatch", disp[0]["url"])

    def test_head_of_line_reserve_blocks_smaller_jobs_behind_a_big_one(self):
        ledger = _Ledger(remaining=1000 * MB, envelopes={"gvm": 2500 * MB, "trufflehog": 768 * MB})
        summary, calls = _run_tick(
            [
                ("/candidates", {"candidates": [
                    _cand("big", kind="gvm", project="pa", envelope=2500 * MB),
                    _cand("small", kind="trufflehog", project="pb", envelope=768 * MB),
                ], "activeCount": 0}),
                ("/dispatch", {"ok": True}),
            ],
            manager=_Manager(ledger),
        )
        # The 2.5 GB head does not fit 1 GB budget -> BREAK, do not skip ahead.
        self.assertEqual(summary["dispatched"], 0)
        self.assertEqual([c for c in calls if "/dispatch" in c["url"]], [])
        self.assertEqual(ledger.admit_calls, [])

    def test_max_concurrent_ceiling_stops_the_walk(self):
        summary, calls = _run_tick([
            ("/candidates", {"candidates": [_cand("j1")], "activeCount": 4}),
            ("/dispatch", {"ok": True}),
        ])
        self.assertEqual(summary["dispatched"], 0)
        self.assertEqual([c for c in calls if "/dispatch" in c["url"]], [])

    def test_disk_floor_defers_the_whole_tick(self):
        summary, calls = _run_tick(
            [("/candidates", {"candidates": [_cand("j1")], "activeCount": 0})],
            disk=(500 * GB, 1 * GB),  # 1 GB free < 10 GB floor
        )
        self.assertTrue(summary["disk_blocked"])
        self.assertEqual([c for c in calls if "/candidates" in c["url"]], [],
                         "must not even peek candidates when disk is below the floor")

    def test_capacity_block_stops_but_per_project_block_continues(self):
        # First job blocked for RAM (capacity) -> break; second never attempted.
        _, calls = _run_tick([
            ("/candidates", {"candidates": [
                _cand("a", project="pa"), _cand("b", project="pb"),
            ], "activeCount": 0}),
            ("/job-queue/a/dispatch", {"ok": False, "blocked": "ram"}),
            ("/job-queue/b/dispatch", {"ok": True}),
        ])
        disp = [c for c in calls if "/dispatch" in c["url"]]
        self.assertEqual(len(disp), 1)
        self.assertIn("/a/dispatch", disp[0]["url"])

    def test_per_project_block_lets_later_jobs_through(self):
        summary, calls = _run_tick([
            ("/candidates", {"candidates": [
                _cand("a", project="pa"), _cand("b", project="pb"),
            ], "activeCount": 0}),
            ("/job-queue/a/dispatch", {"ok": False, "blocked": "agent_running"}),
            ("/job-queue/b/dispatch", {"ok": True}),
        ])
        self.assertEqual(summary["dispatched"], 1)
        disp = [c for c in calls if "/dispatch" in c["url"]]
        self.assertEqual(len(disp), 2)

    def test_try_admit_is_never_called_over_a_full_tick(self):
        ledger = _Ledger()
        _run_tick([
            ("/candidates", {"candidates": [_cand("j1")], "activeCount": 0}),
            ("/dispatch", {"ok": True}),
        ], manager=_Manager(ledger))
        self.assertEqual(ledger.admit_calls, [])

    def test_unreachable_webapp_skips_the_tick(self):
        summary, _ = _run_tick([("/candidates", None)])
        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(summary["dispatched"], 0)

    def test_without_an_internal_key_the_dispatcher_does_nothing(self):
        calls = []

        def fake_request(*a, **kw):
            calls.append(a)
            return None

        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}), \
                mock.patch.object(jd, "request_json", side_effect=fake_request), \
                mock.patch.object(jd.rg, "disk_stats", return_value=(500 * GB, 400 * GB)):
            summary = jd.run_dispatcher_tick(_Manager())
        self.assertEqual(summary["dispatched"], 0)
        self.assertEqual(calls, [])

    def test_a_manager_without_a_ledger_still_dispatches(self):
        class _NoLedger:
            ledger = None
        summary, _ = _run_tick([
            ("/candidates", {"candidates": [_cand("j1", envelope=768 * MB)], "activeCount": 0}),
            ("/dispatch", {"ok": True}),
        ], manager=_NoLedger())
        self.assertEqual(summary["dispatched"], 1)


class TestLoop(unittest.TestCase):
    def test_disabled_loop_returns_immediately(self):
        with mock.patch.dict(os.environ, {"JOB_QUEUE_DISPATCHER_ENABLED": "false"}):
            asyncio.run(asyncio.wait_for(jd.job_dispatcher_loop(lambda: None), timeout=2))

    def test_a_concurrent_tick_is_skipped_while_one_is_in_flight(self):
        # The periodic loop and the reaper trigger must not both dispatch at once
        # (they would race on the per-row claim). asyncio single-threading + the
        # in-flight flag make the second call a no-op.
        import time

        def slow(cm):
            time.sleep(0.05)
            return {"candidates": 0, "dispatched": 0, "deferred": 0, "failed": 0, "disk_blocked": False}

        async def drive():
            with mock.patch.object(jd, "run_dispatcher_tick", side_effect=slow):
                r1, r2 = await asyncio.gather(jd._guarded_tick(_Manager()), jd._guarded_tick(_Manager()))
            # Exactly one ran; the other was skipped (returned None).
            self.assertTrue((r1 is None) != (r2 is None), (r1, r2))

        jd._tick_in_progress = False
        try:
            asyncio.run(drive())
        finally:
            jd._tick_in_progress = False

    def test_a_failing_tick_does_not_kill_the_loop(self):
        async def drive():
            with mock.patch.dict(os.environ, {
                "JOB_QUEUE_DISPATCHER_ENABLED": "true",
                "JOB_QUEUE_TICK_SECONDS": "5",
                "INTERNAL_API_KEY": "k",
            }), mock.patch.object(jd, "run_dispatcher_tick", side_effect=RuntimeError("boom")):
                task = asyncio.create_task(jd.job_dispatcher_loop(lambda: _Manager()))
                await asyncio.sleep(0.05)
                self.assertFalse(task.done(), "the loop must survive a failing tick")
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        asyncio.run(drive())


if __name__ == "__main__":
    unittest.main()
