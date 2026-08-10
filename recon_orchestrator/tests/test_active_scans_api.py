"""
Tests for GET /system/active-scans - the cross-kind "what is running right now"
read used by the Scan queue table in the webapp.

The recon-orchestrator image has no httpx, so FastAPI's TestClient is unavailable;
the route coroutine is exercised directly against a faked container_manager (same
approach as tests.test_local_llm_api).

    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_active_scans_api -v
"""
import asyncio
import unittest
from datetime import datetime
from types import SimpleNamespace

from fastapi import HTTPException

import api


def run(coro):
    return asyncio.run(coro)


def state(project_id, status, started=None, **extra):
    """A per-kind state object; `status` is a bare string here, but the route must
    also cope with an Enum member (`.value`), which is what the real models use."""
    return SimpleNamespace(
        project_id=project_id, status=status, current_phase=None,
        started_at=started, **extra,
    )


class _Status:
    """Stand-in for the str-Enum members the real state models carry."""
    def __init__(self, value):
        self.value = value


class _FakeManager:
    def __init__(self):
        self.running_states = {}
        self.gvm_states = {}
        self.github_hunt_states = {}
        self.trufflehog_states = {}
        self.supply_chain_states = {}
        self.partial_recon_states = {}
        self.ai_attack_states = {}


class TestActiveScans(unittest.TestCase):
    def setUp(self):
        self._saved = api.container_manager
        self.cm = _FakeManager()
        api.container_manager = self.cm

    def tearDown(self):
        api.container_manager = self._saved

    def test_not_initialized_is_503(self):
        api.container_manager = None
        with self.assertRaises(HTTPException) as ctx:
            run(api.system_active_scans())
        self.assertEqual(ctx.exception.status_code, 503)

    def test_empty_when_nothing_is_running(self):
        self.assertEqual(run(api.system_active_scans()), {"scans": []})

    def test_every_kind_is_reported(self):
        """The point of the endpoint: one read covers all seven kinds, not just
        full recon (the only one with a scan_jobs row)."""
        self.cm.running_states = {"p1": state("p1", "running")}
        self.cm.gvm_states = {"p1": state("p1", "running")}
        self.cm.github_hunt_states = {"p2": state("p2", "starting")}
        self.cm.trufflehog_states = {"p2": state("p2", "running")}
        self.cm.supply_chain_states = {"p3": state("p3", "paused")}
        self.cm.partial_recon_states = {
            "p1": {"r1": state("p1", "running", tool_id="katana")}
        }
        self.cm.ai_attack_states = {"p4": {"r9": state("p4", "running", tool="garak")}}

        kinds = sorted(s["kind"] for s in run(api.system_active_scans())["scans"])
        self.assertEqual(kinds, [
            "ai_attack", "full_recon", "github_hunt", "gvm",
            "partial_recon", "supply_chain", "trufflehog",
        ])

    def test_terminal_and_idle_states_are_excluded(self):
        """A completed scan still sits in the state dict; reporting it as active
        would show finished work as running forever."""
        self.cm.running_states = {
            "p1": state("p1", "completed"),
            "p2": state("p2", "idle"),
            "p3": state("p3", "error"),
            "p4": state("p4", "running"),
        }
        scans = run(api.system_active_scans())["scans"]
        self.assertEqual([s["project_id"] for s in scans], ["p4"])

    def test_stopping_and_paused_still_count_as_active(self):
        """They still hold a container and its RAM."""
        self.cm.running_states = {"p1": state("p1", "stopping")}
        self.cm.gvm_states = {"p2": state("p2", "paused")}
        statuses = sorted(s["status"] for s in run(api.system_active_scans())["scans"])
        self.assertEqual(statuses, ["paused", "stopping"])

    def test_enum_status_is_unwrapped(self):
        self.cm.running_states = {"p1": state("p1", _Status("running"))}
        scans = run(api.system_active_scans())["scans"]
        self.assertEqual(scans[0]["status"], "running")

    def test_run_keyed_kinds_carry_run_id_and_tool(self):
        started = datetime(2026, 8, 9, 21, 30, 0)
        self.cm.partial_recon_states = {
            "p1": {"r1": state("p1", "running", started, tool_id="katana")}
        }
        self.cm.ai_attack_states = {"p1": {"r2": state("p1", "running", started, tool="garak")}}
        by_kind = {s["kind"]: s for s in run(api.system_active_scans())["scans"]}
        self.assertEqual(by_kind["partial_recon"]["run_id"], "r1")
        self.assertEqual(by_kind["partial_recon"]["tool_id"], "katana")
        self.assertEqual(by_kind["ai_attack"]["run_id"], "r2")
        self.assertEqual(by_kind["ai_attack"]["tool_id"], "garak")
        self.assertEqual(by_kind["partial_recon"]["started_at"], "2026-08-09T21:30:00")

    def test_missing_started_at_is_null_not_a_crash(self):
        self.cm.running_states = {"p1": state("p1", "running")}
        self.assertIsNone(run(api.system_active_scans())["scans"][0]["started_at"])


if __name__ == "__main__":
    unittest.main()
