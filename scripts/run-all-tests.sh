#!/usr/bin/env bash
# run-all-tests.sh — run the whole test suite the safe way: in lanes.
#
# `pytest tests/` in one pass hangs (integration/coverage open real sockets to
# the Docker mocks and fixtures aren't timed). This runs the three lanes with
# the right flags each, and keeps going even if a lane fails so you see the
# full picture. See docs/TESTING.md for the why.
#
# Usage:
#   ./scripts/run-all-tests.sh            # all three lanes
#   ./scripts/run-all-tests.sh unit       # fast lane only (no Docker)
#   ./scripts/run-all-tests.sh integration
#   ./scripts/run-all-tests.sh coverage
#
# Exit code: 0 only if every lane that ran passed.

set -uo pipefail
cd "$(dirname "$0")/.."

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
LANE="${1:-all}"
rc=0

run_lane() { echo -e "\n${BLUE}== $1 ==${NC}"; shift; "$@" || rc=1; }

need_mocks() {
    echo -e "${YELLOW}Checking mocks (integration/coverage need them up)…${NC}"
    if ! uv run python services.py status 2>/dev/null | grep -qiE "healthy|running|up"; then
        echo -e "${YELLOW}Mocks don't look up — starting core group…${NC}"
        uv run python services.py up core || {
            echo -e "${RED}Could not start mocks; skipping mock-backed lanes.${NC}"; return 1; }
    fi
}

if [[ "$LANE" == "all" || "$LANE" == "unit" ]]; then
    run_lane "unit + contracts (parallel)" \
        uv run pytest tests/unit tests/contracts -p no:randomly -n auto --dist worksteal -q
fi

if [[ "$LANE" == "all" || "$LANE" == "integration" ]]; then
    if need_mocks; then
        run_lane "integration (bounded + loadgroup)" \
            uv run pytest tests/integration -p no:randomly -n 8 --dist loadgroup -q
    else rc=1; fi
fi

if [[ "$LANE" == "all" || "$LANE" == "coverage" ]]; then
    if need_mocks; then
        run_lane "coverage (serial)" \
            uv run pytest tests/coverage -p no:randomly -q
    else rc=1; fi
fi

echo ""
if [[ $rc -eq 0 ]]; then echo -e "${GREEN}All lanes passed.${NC}"
else echo -e "${RED}One or more lanes failed (re-run a lone flake serially to confirm).${NC}"; fi
exit $rc
