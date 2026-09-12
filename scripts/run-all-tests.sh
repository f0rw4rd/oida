#!/usr/bin/env bash
# run-all-tests.sh — run the whole test suite the safe way: in lanes.
#
# `pytest tests/` in one pass hangs (integration/coverage open real sockets to
# the Docker mocks and fixtures aren't timed). This runs the lanes with the
# right flags each, and keeps going even if a lane fails so you see the full
# picture. See docs/TESTING.md for the why.
#
# Usage:
#   ./scripts/run-all-tests.sh [lane] [select-opts] [-- pytest-args]
#
# Lanes (positional, default 'all'):  all | unit | integration | coverage
#
# Select WHICH tests run within the chosen lane(s):
#   -k, --keyword EXPR   pytest -k expr   (e.g. -k bacnet, -k 'hart or astm',
#                                          -k realstack to run one file by name)
#   -m, --marker  EXPR   pytest -m expr   (protocol/marker, ANDed with the lane's
#                                          base marker; e.g. -m bacnet, -m smoke)
#   --                   pass everything after straight to pytest (e.g. -- -x --lf)
#
#   --coverage  measure line coverage across whichever lanes run and print one
#               combined total at the end (separate lane runs merged via
#               `coverage combine`; a single `pytest --cov` pass would hang).
#   -h, --help  show this usage and exit.
#
# Examples:
#   ./scripts/run-all-tests.sh                         # all lanes
#   ./scripts/run-all-tests.sh integration -k bacnet   # bacnet integration tests
#   ./scripts/run-all-tests.sh integration -m hart     # hart-marked integration
#   ./scripts/run-all-tests.sh unit -k modbus          # modbus unit tests
#   ./scripts/run-all-tests.sh integration -- -x --lf  # stop at first fail, last-failed
#   ./scripts/run-all-tests.sh unit --coverage         # unit coverage slice
#
# Strict mode (default): a missing mock, missing optional dependency, missing
# native lib, or unhealthy container makes the depending test FAIL, not skip —
# so the suite can't go green while whole protocols are silently untested. To
# run a subset locally without the full mock+dependency matrix, set
# OIDA_SKIP_MISSING_SERVICES=1 to turn those failures back into skips. This
# runner intentionally leaves that var unset (CI runs strict).
#
# Exit code: 0 only if every lane that ran passed.

set -uo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"   # absolute path, for usage()
cd "$(dirname "$0")/.."

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'

usage() { sed -n '2,/^# Exit code/p' "$SELF" | sed 's/^#\s\?//'; }

# Parse: lane (positional), --coverage, selection (-k/-m), and a `--` passthrough.
LANE="all"; COV=0; KEY=""; MARK=""; PASS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --coverage|--cov)               COV=1; shift ;;
        -k|--keyword)  [[ ${2:-} ]] || { echo -e "${RED}$1 needs an argument${NC}"; exit 2; }; KEY="$2";  shift 2 ;;
        -m|--marker)   [[ ${2:-} ]] || { echo -e "${RED}$1 needs an argument${NC}"; exit 2; }; MARK="$2"; shift 2 ;;
        unit|integration|coverage|all)  LANE="$1"; shift ;;
        -h|--help)                      usage; exit 0 ;;
        --)                             shift; PASS=("$@"); break ;;
        *) echo -e "${RED}Unknown argument: $1${NC}\n"; usage; exit 2 ;;
    esac
done
rc=0

# Announce the availability-gate mode so a green/red run is unambiguous.
if [[ -n "${OIDA_SKIP_MISSING_SERVICES:-}" ]]; then
    echo -e "${YELLOW}OIDA_SKIP_MISSING_SERVICES set — missing mocks/deps will SKIP (non-strict).${NC}"
else
    echo -e "${BLUE}Strict mode: missing mocks/deps FAIL (set OIDA_SKIP_MISSING_SERVICES=1 to skip instead).${NC}"
fi

# Per-lane selection. unit/integration keep the addopts default marker
# (`not network`); coverage keeps its `coverage` marker. A user -m is ANDed with
# the lane base so neither default is lost. -k and the `--` passthrough apply to
# every lane that runs.
SEL=(); CSEL=(); COVMARK="coverage"
[[ -n "$KEY"  ]] && { SEL+=(-k "$KEY"); CSEL+=(-k "$KEY"); }
[[ -n "$MARK" ]] && { SEL+=(-m "(not network) and ($MARK)"); COVMARK="(coverage) and ($MARK)"; }
SEL+=("${PASS[@]}"); CSEL+=("${PASS[@]}")

# When --coverage is on, each lane's pytest gets these extra flags; otherwise the
# array is empty and the commands are byte-for-byte what they were before.
COV_ARGS=()
if [[ $COV -eq 1 ]]; then
    COV_ARGS=(--cov=oida --cov-append --cov-report=)
    echo -e "${YELLOW}Coverage on — erasing prior data.${NC}"
    uv run coverage erase
fi

run_lane() { echo -e "\n${BLUE}== $1 ==${NC}"; shift; "$@" || rc=1; }

need_mocks() {
    echo -e "${YELLOW}Checking mocks (integration/coverage need them up)…${NC}"
    # Detect already-running mocks by container name, not by compose project:
    # the stack may have been started from another worktree (a different project
    # name), so `services.py status` here can miss it and then collide trying to
    # start a second stack on the same network pool.
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'mock-server|hipserver|conpot'; then
        echo -e "${GREEN}Mocks already running — using them.${NC}"; return 0
    fi
    echo -e "${YELLOW}No mocks detected — starting core group…${NC}"
    uv run python services.py up core || {
        echo -e "${RED}Could not start mocks; skipping mock-backed lanes.${NC}"; return 1; }
}

if [[ "$LANE" == "all" || "$LANE" == "unit" ]]; then
    run_lane "unit + contracts (parallel)" \
        uv run pytest tests/unit tests/contracts -p no:randomly -n auto --dist worksteal -q \
            "${SEL[@]}" "${COV_ARGS[@]}"
fi

if [[ "$LANE" == "all" || "$LANE" == "integration" ]]; then
    if need_mocks; then
        run_lane "integration (bounded + loadgroup)" \
            uv run pytest tests/integration -p no:randomly -n 8 --dist loadgroup -q \
                "${SEL[@]}" "${COV_ARGS[@]}"
    else rc=1; fi
fi

if [[ "$LANE" == "all" || "$LANE" == "coverage" ]]; then
    if need_mocks; then
        run_lane "coverage (serial)" \
            uv run pytest tests/coverage -m "$COVMARK" -p no:randomly -q \
                "${CSEL[@]}" "${COV_ARGS[@]}"
    else rc=1; fi
fi

if [[ $COV -eq 1 ]]; then
    echo -e "\n${BLUE}== combined coverage ==${NC}"
    # Merge the per-lane / per-xdist-worker .coverage.* files into one dataset.
    uv run coverage combine || true
    uv run coverage report -m || rc=1
    uv run coverage json -o coverage.json >/dev/null 2>&1 \
        && echo -e "${YELLOW}Machine-readable total written to coverage.json${NC}"
    [[ "$LANE" != "all" ]] && echo -e "${YELLOW}Note: '$LANE'-only run — this is a lane slice, not the project total.${NC}"
fi

echo ""
if [[ $rc -eq 0 ]]; then echo -e "${GREEN}All lanes passed.${NC}"
else echo -e "${RED}One or more lanes failed (re-run a lone flake serially to confirm).${NC}"; fi
exit $rc
