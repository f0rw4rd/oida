#!/usr/bin/env bash
# release_check.sh — Local release quality gate for OIDA
#
# Usage:
#   ./scripts/release_check.sh          # Quick release check (~2 min)
#   ./scripts/release_check.sh --full   # Full check with integration tests (~25 min)
#
# --full is the release gate of record for the docker-mock integration suite:
# CI does not run it (release.yml passes run_integration: false), because a
# timing flake on a contended hosted runner cost a 60-minute job plus the whole
# publish pipeline. Here a flake costs a serial re-run of just the failures and
# the maintainer decides. A run that reaches step 10 writes .release-evidence.json
# pinned to the commit; a run that skips it says so in the summary.
#
# Step 5 probes the container registry, so it needs Docker and network; without
# either it reports SKIP rather than failing. It runs before the integration tests
# deliberately — outdated mock images make step 10 refuse to run, because a pass
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

# ── Step 2: Pre-push quality gates ────────────────────────────────────────

step 2 "Pre-push quality gates (pre-commit)"
# Exactly the hooks `git push` runs: vulture ratchet, structural clones,
# low-assurance test detection, mypy. Without this a release only learns about
# them at push time, with the tag already placed on a commit that can't ship.
# Pre-push stage only — the pre-commit stage runs `ruff check --fix`, which
# would rewrite the tree mid-check; step 1 covers formatting read-only.
if ! command -v pre-commit >/dev/null 2>&1; then
    echo -e "${YELLOW}Skipped — pre-commit not installed (uv sync --extra dev)${RESET}"
    record "Pre-push quality gates" "skip"
elif pre-commit run --hook-stage pre-push --all-files; then
    echo -e "${GREEN}OK${RESET}"
    record "Pre-push quality gates" "pass"
else
    echo -e "${RED}Pre-push hooks failed — this is the same gate git push enforces${RESET}"
    record "Pre-push quality gates" "fail"
fi

# ── Step 3: Type gate (mypy_gate.py, blocking) ────────────────────────────

step 3 "Type gate (mypy_gate.py, blocking)"
# The pre-push mypy hook above is informational (exit 0 always) — it never
# catches anything. scripts/quality/mypy_gate.py is the real, baseline-diffed
# gate CI runs and blocks on. CI syncs `--extra dev --frozen` only (no protocol
# extras), so run it against an isolated venv with the same extras rather than
# the full-extras dev .venv: extra protocol stubs change what mypy can infer
# and surface findings CI would never see (or hide ones it would).
MYPY_GATE_VENV=".venv-mypy-gate"
if UV_PROJECT_ENVIRONMENT="$MYPY_GATE_VENV" uv sync --extra dev --frozen --quiet \
    && UV_PROJECT_ENVIRONMENT="$MYPY_GATE_VENV" uv run python scripts/quality/mypy_gate.py; then
    echo -e "${GREEN}OK${RESET}"
    record "Type gate" "pass"
else
    echo -e "${RED}mypy_gate.py failed — same gate CI blocks on${RESET}"
    record "Type gate" "fail"
fi

# ── Step 4: Security scan ─────────────────────────────────────────────────

step 4 "Security scan (bandit)"
# Skip rules expected in a security testing framework:
#   B104 (bind 0.0.0.0), B310 (urlopen), B501 (verify=False)
if bandit -r src/oida/ -ll -ii -q --skip B104,B310,B314,B318,B324,B501 2>/dev/null; then
    echo -e "${GREEN}OK${RESET}"
    record "Security scan" "pass"
else
    echo -e "${RED}Bandit found issues${RESET}"
    record "Security scan" "fail"
fi

# ── Step 5: Mock images published ────────────────────────────────────────

step 5 "Mock images published (services.py stale)"
# Runs BEFORE the integration tests on purpose: those tests are only meaningful
# against mocks built from the committed source. If the registry is behind, a green
# integration run is testing last month's mocks and proves nothing about this
# release, so step 10 refuses to run rather than reporting a misleading pass.
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

# ── Step 6: Test collection ───────────────────────────────────────────────

step 6 "Test collection (import/syntax check)"
if python -m pytest tests/unit/ --collect-only -q --no-header; then
    echo -e "${GREEN}OK${RESET}"
    record "Test collection" "pass"
else
    echo -e "${RED}Test collection failed — import or syntax error in tests${RESET}"
    record "Test collection" "fail"
fi

# ── Step 7: Core unit tests ──────────────────────────────────────────────

step 7 "Unit tests (core)"
if python -m pytest tests/unit/ -x -q --tb=short; then
    echo -e "${GREEN}OK${RESET}"
    record "Unit tests" "pass"
else
    echo -e "${RED}Unit tests failed${RESET}"
    record "Unit tests" "fail"
fi

# ── Step 8: Package build ────────────────────────────────────────────────

step 8 "Package build (sdist + wheel)"
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

# ── Step 9: Wheel install + CLI smoke ────────────────────────────────────

step 9 "Wheel install + CLI smoke test"
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
    echo -e "${YELLOW}Skipped (no wheel from step 7)${RESET}"
    record "Wheel install + CLI" "skip"
fi
rm -rf "$DIST_DIR"

# ── Step 10: Integration tests (--full only) ──────────────────────────────

step 10 "Integration tests (Docker mocks)"
INTEG_STATUS=skip
INTEG_FLAKES=0
if [[ "${STALE_RC:-0}" == "1" ]]; then
    # Refuse rather than mislead: the mocks in the registry are behind the committed
    # source (step 5), so a pass here would certify images this release doesn't ship.
    echo -e "${RED}Skipped — mock images are outdated (step 5).${RESET}"
    echo -e "${RED}Testing against them would certify stale mocks; run: python services.py push${RESET}"
    record "Integration tests" "fail"
    INTEG_STATUS=fail
elif $FULL; then
    # Feed the whole listing through grep (no -q): `grep -q` exits at the
    # first match, docker compose takes SIGPIPE, and under `set -o pipefail`
    # the pipeline reads as failed even with mocks running.
    if docker compose -f docker/mocks/compose.yml ps --status running 2>/dev/null | grep "mock" >/dev/null; then
        # Two passes. Pass 1 is the fast parallel lane; loadgroup pins each
        # shared-mock xdist_group to one worker. Pass 2 re-runs only the
        # failures, serially — contention is gone, so a timing flake passes
        # while a real bug fails again. What needed pass 2 is reported, not
        # swallowed: that count is the flakiness signal now that CI no longer
        # runs this suite.
        if python -m pytest tests/integration/ -n 8 --dist loadgroup -q; then
            echo -e "${GREEN}OK${RESET}"
            record "Integration tests" "pass"
            INTEG_STATUS=pass
        else
            echo -e "${YELLOW}Parallel pass had failures — re-running just those, serially${RESET}"
            RERUN_LOG=$(mktemp)
            if python -m pytest tests/integration/ --lf -v 2>&1 | tee "$RERUN_LOG"; then
                INTEG_FLAKES=$(sed -n 's/.*rerun previous \([0-9]*\) failure.*/\1/p' "$RERUN_LOG" | tail -1)
                INTEG_FLAKES=${INTEG_FLAKES:-0}
                echo -e "${YELLOW}OK on serial re-run — $INTEG_FLAKES test(s) flaked under parallelism${RESET}"
                record "Integration tests ($INTEG_FLAKES flaked, green serially)" "pass"
                INTEG_STATUS=flaky-pass
            else
                echo -e "${RED}Integration tests failed twice — this is a bug, not a flake${RESET}"
                record "Integration tests" "fail"
                INTEG_STATUS=fail
            fi
            rm -f "$RERUN_LOG"
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

# The integration suite no longer runs in CI (see .github/workflows/release.yml),
# so this run is the only record that it passed. Write it down, pinned to the
# commit, and say so plainly when it did not run at all.
if [[ "$INTEG_STATUS" == "skip" ]]; then
    echo -e "${YELLOW}${BOLD}Integration tests did not run here — and CI does not run them either.${RESET}"
    echo -e "${YELLOW}Before tagging: python services.py up core && ./scripts/release_check.sh --full${RESET}"
    echo ""
else
    cat > .release-evidence.json <<EOF
{
  "commit": "$(git rev-parse HEAD)",
  "dirty": $(git diff --quiet HEAD 2>/dev/null && echo false || echo true),
  "checked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "integration": "$INTEG_STATUS",
  "flaked_under_parallelism": $INTEG_FLAKES,
  "passed": $PASS,
  "failed": $FAIL,
  "skipped": $SKIP
}
EOF
    echo -e "Evidence written to ${BOLD}.release-evidence.json${RESET} (commit $(git rev-parse --short HEAD))"
    echo ""
fi

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}RELEASE CHECK FAILED${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}RELEASE CHECK PASSED${RESET}"
    exit 0
fi
