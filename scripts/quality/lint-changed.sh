#!/usr/bin/env bash
# Strict lint for CHANGED files only.
#
# The blocking `select` in pyproject.toml is the set that is already at zero
# across the tree. This script applies the *stricter* set — the rules that
# still have thousands of pre-existing violations — to changed files only, so
# new code meets the standard while old code is paid down in waves.
#
# See AI_SLOP_REMEDIATION_PLAN.md for the wave schedule.
#
# Usage:
#   scripts/quality/lint-changed.sh              # vs origin/main
#   scripts/quality/lint-changed.sh HEAD~1       # vs an explicit base
set -uo pipefail

BASE="${1:-origin/main}"
git rev-parse --verify --quiet "$BASE" >/dev/null || BASE="$(git rev-parse HEAD~1 2>/dev/null || echo HEAD)"

# BLE001 blind-except was the single most common smell in the audit (1,864).
# ARG/RUF012/RUF013/TRY/SIM are the next tier. B904 keeps exception chains.
STRICT="BLE001,S110,S112,ARG001,ARG002,RUF012,RUF013,TRY300,TRY301,TRY400,SIM105,SIM115,B904,PLW0603"

mapfile -t FILES < <(git diff --name-only --diff-filter=d "$BASE"...HEAD -- 'src/oida/*.py' 2>/dev/null)

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "lint-changed: no changed files under src/oida/ vs ${BASE}"
    exit 0
fi

echo "lint-changed: ${#FILES[@]} changed file(s) vs ${BASE}, strict set: ${STRICT}"
if ! ruff check --no-cache --select "$STRICT" "${FILES[@]}"; then
    cat >&2 <<'EOF'

These rules are enforced on changed files only. Fix them here rather than
widening an except or adding a noqa: a blind `except Exception` around a
security check is how AI_SLOP_AUDIT.md F11-F13 shipped (a crashed check
reported as "clean").
EOF
    exit 1
fi
echo "lint-changed: clean"
