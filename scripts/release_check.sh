#!/usr/bin/env bash
# release_check.sh — Local release quality gate for OIDA
#
# Usage:
#   ./scripts/release_check.sh          # Quick release check (~2 min)
#   ./scripts/release_check.sh --full   # Full check with integration tests (~25 min)
#
# Step 3 probes the container registry, so it needs Docker and network; without
# either it reports SKIP rather than failing. It runs before the integration tests
# deliberately — outdated mock images make step 8 refuse to run, because a pass
# against stale mocks would certify images this release doesn't ship.
#
# Exit codes: 0 = all gates passed, 1 = failure

set -euo pipefail

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
BOLD='\033[1m'
RESET='\033[0m'

FULL=false
[[ "${1:-}" == "--full" ]] && FULL=true

PASS=0
FAIL=0
SKIP=0
RESULTS=()

step() {
    local num="$1" name="$2"
    echo ""
    echo -e "${BLUE}${BOLD}[$num] $name${RESET}"
    echo "────────────────────────────────────────"
}

record() {
    local name="$1" status="$2"
    if [[ "$status" == "pass" ]]; then
        RESULTS+=("${GREEN}PASS${RESET}  $name")
        PASS=$((PASS + 1))
    elif [[ "$status" == "skip" ]]; then
        RESULTS+=("${YELLOW}SKIP${RESET}  $name")
        SKIP=$((SKIP + 1))
    else
        RESULTS+=("${RED}FAIL${RESET}  $name")
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${BOLD}OIDA Release Quality Gate${RESET}"
echo "========================="
$FULL && echo -e "Mode: ${YELLOW}full${RESET} (includes integration tests)" \
      || echo -e "Mode: ${BLUE}quick${RESET}"
echo ""

# ── Step 1: Lint ──────────────────────────────────────────────────────────

step 1 "Lint (ruff format --check)"
# Format check on all code; full ruff check deferred to CI (pre-existing issues)
LINT_OK=true
ruff format --check src/oida/ tests/ || LINT_OK=false
if $LINT_OK; then
    echo -e "${GREEN}OK${RESET}"
    record "Lint" "pass"
else
    echo -e "${RED}Lint failed${RESET}"
    record "Lint" "fail"
fi

# ── Step 2: Security scan ─────────────────────────────────────────────────

step 2 "Security scan (bandit)"
# Skip rules expected in a security testing framework:
#   B104 (bind 0.0.0.0), B310 (urlopen), B501 (verify=False)
if bandit -r src/oida/ -ll -ii -q --skip B104,B310,B314,B318,B324,B501 2>/dev/null; then
    echo -e "${GREEN}OK${RESET}"
    record "Security scan" "pass"
else
    echo -e "${RED}Bandit found issues${RESET}"
    record "Security scan" "fail"
fi

# ── Step 3: Mock images published ────────────────────────────────────────

step 3 "Mock images published (services.py stale)"
# Runs BEFORE the integration tests on purpose: those tests are only meaningful
# against mocks built from the committed source. If the registry is behind, a green
# integration run is testing last month's mocks and proves nothing about this
# release, so step 8 refuses to run rather than reporting a misleading pass.
# Exit 1 = outdated (fail), 2 = could not verify — no Docker or an unreadable
# registry — which is a skip, not a false failure.
set +e
python services.py stale
STALE_RC=$?
set -e
case $STALE_RC in
    0)
        echo -e "${GREEN}OK${RESET}"
        record "Mock images published" "pass"
        ;;
    2)
        echo -e "${YELLOW}Skipped — could not verify (Docker or registry unreachable)${RESET}"
        record "Mock images published" "skip"
        ;;
    *)
        echo -e "${RED}Mock images are outdated — run: python services.py push${RESET}"
        record "Mock images published" "fail"
        ;;
esac

# ── Step 4: Test collection ───────────────────────────────────────────────

step 4 "Test collection (import/syntax check)"
if python -m pytest tests/unit/ --collect-only -q --no-header; then
    echo -e "${GREEN}OK${RESET}"
    record "Test collection" "pass"
else
    echo -e "${RED}Test collection failed — import or syntax error in tests${RESET}"
    record "Test collection" "fail"
fi

# ── Step 5: Core unit tests ──────────────────────────────────────────────

step 5 "Unit tests (core)"
if python -m pytest tests/unit/ -x -q --tb=short; then
    echo -e "${GREEN}OK${RESET}"
    record "Unit tests" "pass"
else
    echo -e "${RED}Unit tests failed${RESET}"
    record "Unit tests" "fail"
fi

# ── Step 6: Package build ────────────────────────────────────────────────

step 6 "Package build (sdist + wheel)"
DIST_DIR=$(mktemp -d)
    # Prefer uv build (fast, no extra dependency); fall back to python -m build
    # for environments where uv isn't installed but the build package is.
    if command -v uv >/dev/null 2>&1; then
        BUILD_CMD=(uv build --out-dir "$DIST_DIR")
    else
        BUILD_CMD=(python -m build --outdir "$DIST_DIR")
    fi
    if "${BUILD_CMD[@]}" >/dev/null 2>&1; then
    WHEEL=$(ls "$DIST_DIR"/*.whl 2>/dev/null | head -1)
    if [[ -n "$WHEEL" ]]; then
        echo -e "${GREEN}OK${RESET} — $(basename "$WHEEL")"
        record "Package build" "pass"
    else
        echo -e "${RED}No wheel produced${RESET}"
        record "Package build" "fail"
    fi
else
    echo -e "${RED}Build failed${RESET}"
    record "Package build" "fail"
fi

# ── Step 7: Wheel install + CLI smoke ────────────────────────────────────

step 7 "Wheel install + CLI smoke test"
if [[ -n "${WHEEL:-}" ]]; then
    VENV_DIR=$(mktemp -d)
    # Prefer uv (10x faster venv create + install) when available; fall
    # back to stdlib venv + pip for environments where uv isn't installed.
    if command -v uv >/dev/null 2>&1; then
        INSTALLER="uv"
        uv venv "$VENV_DIR" >/dev/null 2>&1
    else
        INSTALLER="pip"
        python -m venv "$VENV_DIR"
    fi
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    if [[ "$INSTALLER" == "uv" ]]; then
        INSTALL_CMD=(uv pip install "$WHEEL" --quiet)
    else
        INSTALL_CMD=(pip install "$WHEEL" --quiet)
    fi

    if "${INSTALL_CMD[@]}" 2>/dev/null; then
        OK=true
        oida --version >/dev/null 2>&1   || OK=false
        oida modbus --help >/dev/null 2>&1 || OK=false
        if $OK; then
            echo -e "${GREEN}OK${RESET} — wheel installs (${INSTALLER}); oida --version and oida modbus --help work"
            record "Wheel install + CLI" "pass"
        else
            echo -e "${RED}CLI commands failed${RESET}"
            record "Wheel install + CLI" "fail"
        fi
    else
        echo -e "${RED}${INSTALLER} install of wheel failed${RESET}"
        record "Wheel install + CLI" "fail"
    fi

    deactivate
    rm -rf "$VENV_DIR"
else
    echo -e "${YELLOW}Skipped (no wheel from step 6)${RESET}"
    record "Wheel install + CLI" "skip"
fi
rm -rf "$DIST_DIR"

# ── Step 8: Integration tests (--full only) ──────────────────────────────

step 8 "Integration tests (Docker mocks)"
if [[ "${STALE_RC:-0}" == "1" ]]; then
    # Refuse rather than mislead: the mocks in the registry are behind the committed
    # source (step 3), so a pass here would certify images this release doesn't ship.
    echo -e "${RED}Skipped — mock images are outdated (step 3).${RESET}"
    echo -e "${RED}Testing against them would certify stale mocks; run: python services.py push${RESET}"
    record "Integration tests" "fail"
elif $FULL; then
    # Feed the whole listing through grep (no -q): `grep -q` exits at the
    # first match, docker compose takes SIGPIPE, and under `set -o pipefail`
    # the pipeline reads as failed even with mocks running.
    if docker compose -f docker/mocks/compose.yml ps --status running 2>/dev/null | grep "mock" >/dev/null; then
        if python -m pytest tests/integration/ -v; then
            echo -e "${GREEN}OK${RESET}"
            record "Integration tests" "pass"
        else
            echo -e "${RED}Integration tests failed${RESET}"
            record "Integration tests" "fail"
        fi
    else
        echo -e "${YELLOW}Skipped — mock services not running (start with: just up)${RESET}"
        record "Integration tests" "skip"
    fi
else
    echo -e "${YELLOW}Skipped (use --full to include)${RESET}"
    record "Integration tests" "skip"
fi

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo ""
echo -e "${BOLD}Summary${RESET}"
echo "═══════════════════════════════════════"
for r in "${RESULTS[@]}"; do
    echo -e "  $r"
done
echo "───────────────────────────────────────"
echo -e "  ${GREEN}$PASS passed${RESET}  ${RED}$FAIL failed${RESET}  ${YELLOW}$SKIP skipped${RESET}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}RELEASE CHECK FAILED${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}RELEASE CHECK PASSED${RESET}"
    exit 0
fi
