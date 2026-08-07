#!/bin/bash
# Run agent tests with the correct mounts.
#
# Tests under agentic/tests/ split into two groups:
#   - Unit tests of agent code (default focused list) — only need agentic/.
#   - Integration / consistency tests (test_*_integration, test_*_skill, etc.) —
#     reach into mcp/servers/, mcp/kali-sandbox/Dockerfile, and webapp/prisma/
#     to verify cross-layer consistency. They need those dirs mounted too.
#
# Usage:
#   ./agentic/run_tests.sh focused    # 522-test regression set (fast path)
#   ./agentic/run_tests.sh discover   # full unittest discover
#   ./agentic/run_tests.sh <modules>  # arbitrary `python -m unittest` args

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-focused}"
shift || true

FOCUSED_TESTS=(
    # Collected first so it imports the REAL langgraph before test_tool_confirmation
    # stubs langgraph into sys.modules (its stubbing is conditional on absence).
    tests.test_lats_checkpoint
    tests.test_prompt_caching
    tests.test_fireteam_regressions
    tests.test_fireteam_core
    tests.test_fireteam_deploy
    tests.test_fireteam_member_llm_retry
    tests.test_tool_confirmation
    tests.test_system_mcp_tool_coverage
    tests.test_guarddog_native_tool
    tests.test_tool_complete_emission
    tests.test_productivity
    tests.test_productivity_v2_review
    tests.test_peer_task_scope
    tests.test_phase_gating
    tests.test_soft_allowlist
    tests.test_token_tracking
    tests.test_root_think_and_guardrail_retry
    tests.test_plan_mutex
    tests.test_plan_parallelism
    tests.test_state_priority_coercion
    tests.test_chain_context
    tests.test_startup_guard
    tests.test_lats_models
    tests.test_lats
    tests.test_lats_trace
    tests.test_lats_hook
    tests.test_lats_emission
    tests.test_lats_settings
    tests.test_lats_drive
    tests.test_lats_integration
    tests.test_lats_attribution
    tests.test_lats_smoke
    tests.test_lats_view_contract
)

case "$MODE" in
    focused)
        ARGS="${FOCUSED_TESTS[*]}"
        ;;
    discover)
        ARGS="discover -s tests -p test_*.py"
        ;;
    *)
        ARGS="$MODE $*"
        ;;
esac

exec docker run --rm \
    -v "$REPO_ROOT/agentic:/app" \
    -v "$REPO_ROOT/graph_db:/app/graph_db" \
    -v "$REPO_ROOT/knowledge_base:/app/knowledge_base" \
    -v "$REPO_ROOT/mcp:/mcp" \
    -v "$REPO_ROOT/webapp:/webapp" \
    -w /app \
    -e PYTHONPATH=/app:/mcp/servers \
    redamon-agent:latest \
    python -m unittest $ARGS
