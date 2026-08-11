#!/usr/bin/env bash
# Run the guinea-pig test suites.
#   - unit:        Flask test_client, INSIDE the backend container (app logic in isolation)
#   - integration: urllib from the HOST against the live stack (cache, persistence, regressions)
#
# Usage:  ./tests/run_tests.sh            (from the web-cache-poisoning dir)
set -uo pipefail
cd "$(dirname "$0")/.."

echo "==================== UNIT (in container) ===================="
docker compose exec -T backend python tests/unit_backend.py
unit=$?

echo
echo "==================== INTEGRATION (host -> live stack) ===================="
python3 tests/integration_stack.py
integ=$?

echo
echo "============================================================"
[ $unit -eq 0 ] && echo "UNIT: PASS" || echo "UNIT: FAIL"
[ $integ -eq 0 ] && echo "INTEGRATION: PASS" || echo "INTEGRATION: FAIL"
exit $(( unit || integ ))
