#!/bin/bash
# Run the agent-image test suite via pytest, with the determinism the legacy
# per-file `unittest` runner gave for free.
#
# WHY per-file isolation: a large body of these tests was written for
# `python -m unittest tests.test_x` (one process per file). Many stub
# langchain/langgraph into sys.modules at import time and bake real tool objects
# against a fake decorator during import — order-dependent in a single pytest
# process. So the gate runs each test FILE in its own pytest subprocess
# (parallelized) via scripts/pytest_isolated.py. See readmes/README.TESTING.md.
#
# The whole repo is mounted at /repo (workdir /repo/agentic) so the cross-layer
# tests resolve: REPO_ROOT=parents[2]=/repo, git HEAD is available, and sibling
# dirs (capture_proxy/, recon_orchestrator/, webapp/, mcp/) are present.
#
# Usage:
#   ./agentic/run_tests.sh                 # unit gate (default) — must be 100% green
#   ./agentic/run_tests.sh unit            # same
#   ./agentic/run_tests.sh focused         # back-compat alias -> unit
#   ./agentic/run_tests.sh integration     # integration tier
#   ./agentic/run_tests.sh live            # live tier (self-skips when stack down)
#   ./agentic/run_tests.sh all             # unit + integration
#   ./agentic/run_tests.sh coverage        # unit+integration with --cov + floor
#   ./agentic/run_tests.sh tests/test_x.py [pytest args...]   # passthrough (single proc)
set -u
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-unit}"
shift || true

IMAGE="redamon-agent:latest"
COV_FLOOR="${REDAMON_COV_FLOOR:-38}"     # agentic ratchet floor (see README)
PARALLEL="${REDAMON_TEST_PARALLEL:-8}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">> SKIP agent tests ($IMAGE not built)"
    exit 0
fi

# Ensure test deps (baked in the rebuilt image; runtime-install fallback for an
# older image) + neutralize git's dubious-ownership guard on the mounted repo.
PREP='python -c "import pytest" 2>/dev/null || pip install -q -r /repo/requirements-test.txt >/dev/null 2>&1;
      git config --global --add safe.directory "*" 2>/dev/null || true;'

run_in_image() {
    docker run --rm \
        -v "$REPO_ROOT:/repo" \
        -w /repo/agentic \
        -e PYTHONPATH=/repo/agentic:/repo:/repo/mcp/servers:/repo/recon_orchestrator \
        -e COVERAGE_FILE=/tmp/redamon.coverage \
        -e HOME=/tmp \
        -e REDAMON_TEST_PARALLEL="$PARALLEL" \
        --entrypoint sh \
        "$IMAGE" -c "$PREP $*"
}

case "$MODE" in
    unit|focused)  run_in_image 'exec python /repo/scripts/pytest_isolated.py unit tests' ;;
    integration)   run_in_image 'exec python /repo/scripts/pytest_isolated.py integration tests' ;;
    live)          run_in_image 'exec python /repo/scripts/pytest_isolated.py live tests' ;;
    all|discover)  run_in_image 'exec python /repo/scripts/pytest_isolated.py all tests' ;;
    coverage)      run_in_image "exec python /repo/scripts/pytest_isolated.py all tests --cov . --cov-floor $COV_FLOOR" ;;
    tests/*|*.py|-*)
        # Passthrough: a specific file / node id / pytest args (single process).
        run_in_image "exec python -m pytest $MODE $*" ;;
    *)
        echo "Unknown mode: $MODE" >&2; exit 2 ;;
esac
