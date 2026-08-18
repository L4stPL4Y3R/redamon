"""
Regression tests for the parallel-scan orchestrator freeze.

Root cause (fixed): docker-py is synchronous, and the async status/log paths
called it directly on the single uvicorn event loop. With several parallel
partial recons + heavy log streaming, those blocking Docker calls starved the
loop, so the orchestrator stopped answering ALL requests (health, status polls,
new scan starts) and the webapp crashed.

Two behaviors are locked in here:
  Fix 1 - status refreshes run in the thread pool (_run_blocking), so a slow
          Docker daemon can never block the event loop, and N runs refresh
          CONCURRENTLY rather than serially.
  Fix 2 - the log-reader liveness reload() is throttled to ~once/30s instead of
          once PER LINE, so a high-volume scan no longer floods the daemon.

These mock Docker; no daemon required.
"""
import asyncio
import os
import threading
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from models import (
    PartialReconState,
    PartialReconStatus,
    ReconState,
    ReconStatus,
    GvmState,
    GvmStatus,
    GithubHuntState,
    GithubHuntStatus,
    TrufflehogState,
    TrufflehogStatus,
)
from container_manager import ContainerManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_docker_client():
    client = MagicMock()
    client.containers = MagicMock()
    client.images = MagicMock()
    return client


@pytest.fixture
def manager(mock_docker_client):
    with patch('container_manager.docker') as mock_docker_mod:
        mock_docker_mod.from_env.return_value = mock_docker_client
        mgr = ContainerManager()
        mgr.client = mock_docker_client
        return mgr


# ---------------------------------------------------------------------------
# Fix 1: blocking Docker status calls run off the event loop
# ---------------------------------------------------------------------------

class TestStatusPollDoesNotBlockEventLoop:

    @pytest.mark.asyncio
    async def test_partial_status_poll_keeps_event_loop_responsive(self, manager, mock_docker_client):
        """The regression: 4 running partial recons, each with a SLOW (0.2s)
        blocking Docker status call. While get_all_partial_recon_statuses runs,
        a heartbeat coroutine must keep ticking -- proving the event loop is not
        blocked. With the old direct-call code the loop would be frozen for
        ~0.8s and the heartbeat could not advance."""
        manager.partial_recon_states["p"] = {
            f"r{i}": PartialReconState(
                project_id="p", run_id=f"r{i}",
                status=PartialReconStatus.RUNNING, container_id=f"c{i}",
            )
            for i in range(4)
        }

        def slow_get(_cid):
            time.sleep(0.2)  # simulate a slow Docker daemon (blocking I/O)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(200):
                await asyncio.sleep(0.01)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        await manager.get_all_partial_recon_statuses("p")
        # The blocking calls happened in the thread pool; the loop kept servicing
        # the heartbeat throughout. A frozen loop would leave ticks at ~0.
        assert ticks >= 5, f"event loop was blocked during status poll (ticks={ticks})"
        hb.cancel()

    @pytest.mark.asyncio
    async def test_partial_status_poll_runs_refreshes_concurrently(self, manager, mock_docker_client):
        """N blocking refreshes must run CONCURRENTLY (asyncio.gather over the
        executor), so wall time ~= one call, not N calls. Old code was serial."""
        n = 6
        manager.partial_recon_states["p"] = {
            f"r{i}": PartialReconState(
                project_id="p", run_id=f"r{i}",
                status=PartialReconStatus.RUNNING, container_id=f"c{i}",
            )
            for i in range(n)
        }

        def slow_get(_cid):
            time.sleep(0.15)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        start = time.monotonic()
        result = await manager.get_all_partial_recon_statuses("p")
        elapsed = time.monotonic() - start

        assert len(result) == n
        # Serial would be n*0.15 = 0.9s; concurrent is ~0.15s. Allow generous
        # slack for a small default thread pool but stay well under serial.
        assert elapsed < n * 0.15 * 0.6, f"refreshes were not concurrent (elapsed={elapsed:.2f}s)"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("poller,states_attr,state_cls,status_cls", [
        ("get_gvm_status", "gvm_states", GvmState, GvmStatus),
        ("get_github_hunt_status", "github_hunt_states", GithubHuntState, GithubHuntStatus),
    ])
    async def test_other_scan_type_pollers_keep_event_loop_responsive(
        self, manager, mock_docker_client, poller, states_attr, state_cls, status_cls
    ):
        """The identical freeze hits ANY scan type polled on the same cadence.
        gvm / github-hunt / trufflehog status pollers must also run their Docker
        inspection off the event loop -- a slow daemon on one must not freeze the
        worker for all the others."""
        getattr(manager, states_attr)["p"] = state_cls(
            project_id="p", status=status_cls.RUNNING, container_id="c1",
        )

        def slow_get(_cid):
            time.sleep(0.3)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(200):
                await asyncio.sleep(0.01)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        state = await getattr(manager, poller)("p")
        assert state.status == status_cls.RUNNING
        assert ticks >= 5, f"{poller} blocked the event loop (ticks={ticks})"
        hb.cancel()

    @pytest.mark.asyncio
    async def test_trufflehog_poller_keeps_event_loop_responsive(self, manager, mock_docker_client):
        """Same guarantee for the run-keyed TruffleHog poller.

        It matters more here than for the single-run scan types: several sources
        poll in parallel, so a Docker inspection on the event loop multiplies
        across every live run instead of stalling one.
        """
        manager.trufflehog_states["p"] = {
            "docker": TrufflehogState(
                project_id="p", source="docker", run_id="docker",
                status=TrufflehogStatus.RUNNING, container_id="c1",
            )
        }

        def slow_get(_cid):
            time.sleep(0.3)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(200):
                await asyncio.sleep(0.01)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        state = await manager.get_trufflehog_status("p", "docker")
        assert state.status == TrufflehogStatus.RUNNING
        assert ticks >= 5, f"trufflehog poller blocked the event loop (ticks={ticks})"
        hb.cancel()

    @pytest.mark.asyncio
    async def test_full_recon_get_status_keeps_event_loop_responsive(self, manager, mock_docker_client):
        """Same guarantee for the full-recon get_status() path (polled while a
        complete pipeline runs, and hit by the partial-recon mutual-exclusion
        check)."""
        manager.running_states["p"] = ReconState(
            project_id="p", status=ReconStatus.RUNNING, container_id="c1",
        )

        def slow_get(_cid):
            time.sleep(0.3)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(200):
                await asyncio.sleep(0.01)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        state = await manager.get_status("p")
        assert state.status == ReconStatus.RUNNING
        assert ticks >= 5, f"event loop was blocked during get_status (ticks={ticks})"
        hb.cancel()


# ---------------------------------------------------------------------------
# Fix 1b: short Docker ops use a DEDICATED pool, isolated from the long-lived
# log-stream reader threads, so they can never be starved by pool exhaustion.
# ---------------------------------------------------------------------------

class TestDockerOpsIsolatedFromLogStreamPool:

    @pytest.mark.asyncio
    async def test_status_poll_not_starved_by_a_saturated_default_pool(self, manager, mock_docker_client):
        """A log-stream reader blocks its worker for the whole scan. If status
        Docker ops shared that pool, enough streams would starve them and the
        freeze would return via pool exhaustion. This saturates the DEFAULT
        executor completely and asserts a status poll STILL returns promptly --
        proving status ops run on their own pool. Reverting _run_blocking to
        run_in_executor(None, ...) makes this hang and fail the timeout."""
        loop = asyncio.get_running_loop()
        default_pool_size = min(32, (os.cpu_count() or 1) + 4)
        release = threading.Event()
        # Fully saturate + overflow the default pool with blocked workers.
        blockers = [
            loop.run_in_executor(None, release.wait)
            for _ in range(default_pool_size + 4)
        ]
        try:
            # Give the blockers a moment to occupy every default-pool thread.
            await asyncio.sleep(0.05)

            manager.partial_recon_states["p"] = {
                f"r{i}": PartialReconState(
                    project_id="p", run_id=f"r{i}",
                    status=PartialReconStatus.RUNNING, container_id=f"c{i}",
                )
                for i in range(4)
            }
            fast = MagicMock()
            fast.status = "running"
            mock_docker_client.containers.get.return_value = fast

            start = time.monotonic()
            # If status ops shared the (now-saturated) default pool, this would
            # queue behind the blockers forever and trip the timeout.
            result = await asyncio.wait_for(
                manager.get_all_partial_recon_statuses("p"), timeout=2.0
            )
            elapsed = time.monotonic() - start
            assert len(result) == 4
            assert elapsed < 1.0, (
                f"status poll was starved by the saturated default pool "
                f"(elapsed={elapsed:.2f}s) -- docker ops are not isolated"
            )
        finally:
            release.set()
            await asyncio.gather(*blockers, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_concurrent_status_polls_cleanup_is_idempotent(self, manager, mock_docker_client):
        """The gather() added an await point inside get_all; many concurrent
        polls (HTTP + background reconcile) must all clean up old completed runs
        without a KeyError. pop() makes this idempotent under any interleaving."""
        old = datetime.now(timezone.utc) - timedelta(seconds=120)
        mock_docker_client.containers.get.return_value = MagicMock(status="running")

        def seed():
            manager.partial_recon_states["p"] = {
                f"r{i}": PartialReconState(
                    project_id="p", run_id=f"r{i}",
                    status=PartialReconStatus.COMPLETED, completed_at=old,
                )
                for i in range(10)
            }

        # Repeat to widen the interleaving window.
        for _ in range(25):
            seed()
            results = await asyncio.gather(
                *[manager.get_all_partial_recon_statuses("p") for _ in range(12)],
                return_exceptions=True,
            )
            raised = [r for r in results if isinstance(r, Exception)]
            assert not raised, f"concurrent cleanup raised: {raised}"

    def test_dedicated_executors_are_separate_instances(self, manager):
        """The two pools must be distinct objects and neither may be the default
        executor, or the isolation is only nominal."""
        assert manager._docker_op_executor is not manager._log_stream_executor
        assert manager._docker_op_executor is not None
        assert manager._log_stream_executor is not None


# ---------------------------------------------------------------------------
# Fix 2: the log-reader liveness reload() is throttled, not per-line
# ---------------------------------------------------------------------------

class TestLogReaderDoesNotReloadPerLine:

    def _fake_container(self, lines):
        container = MagicMock()
        container.id = "c1"
        container.status = "running"
        container.logs.return_value = iter(lines)
        # .reload() is the call we are asserting is NOT made per line.
        container.reload = MagicMock()
        return container

    @pytest.mark.asyncio
    async def test_partial_log_reader_no_reload_per_line(self, manager, mock_docker_client):
        """Streaming a burst of many log lines must NOT trigger a Docker
        reload() per line. The 30s throttle gate means a fast burst produces
        zero reload() calls, while every line is still delivered."""
        line_count = 500
        lines = [f"scan progress line {i}".encode() for i in range(line_count)]
        container = self._fake_container(lines)
        mock_docker_client.containers.get.return_value = container

        manager.partial_recon_states["p"] = {
            "r1": PartialReconState(
                project_id="p", run_id="r1",
                status=PartialReconStatus.RUNNING, container_id="c1",
            )
        }

        events = []
        async for ev in manager.stream_partial_logs("p", "r1"):
            events.append(ev)

        # Every non-empty line was delivered ...
        assert len(events) == line_count
        # ... and the per-line reload() is gone: a sub-30s burst reloads 0 times.
        assert container.reload.call_count == 0, (
            f"reload() was called {container.reload.call_count} times for "
            f"{line_count} lines -- the per-line reload regressed"
        )

    @pytest.mark.asyncio
    async def test_full_recon_log_reader_no_reload_per_line(self, manager, mock_docker_client):
        """Same throttle guarantee for the full-recon stream_logs() reader."""
        line_count = 300
        lines = [f"recon line {i}".encode() for i in range(line_count)]
        container = self._fake_container(lines)
        mock_docker_client.containers.get.return_value = container

        manager.running_states["p"] = ReconState(
            project_id="p", status=ReconStatus.RUNNING, container_id="c1",
        )

        events = []
        async for ev in manager.stream_logs("p"):
            events.append(ev)

        assert len(events) == line_count
        assert container.reload.call_count == 0, (
            f"reload() was called {container.reload.call_count} times for "
            f"{line_count} lines -- the per-line reload regressed"
        )
