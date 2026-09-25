#!/usr/bin/env bash
# build-all-mocks.sh - try to `docker build` every mock/CVE Dockerfile and
# report which ones are broken.
#
# Mock and CVE container builds rot over time independently of our own
# commits: upstream tarball URLs disappear, apt package versions get pruned
# from EOL distro mirrors, base images get new tags. Nothing in CI exercises
# these builds, so breakage is only found when a user hits it manually (see
# the bullseye/apt-404 bug this script exists to catch earlier). Run this
# periodically (or in CI on a schedule) to find rot before a user does.
#
# Usage:
#   ./scripts/build-all-mocks.sh [filter] [-- extra docker build args]
#
#   filter   optional substring/grep -E pattern on the Dockerfile path,
#            e.g. 'cve' to only build CVE targets, or 'modbus' for one
#            protocol.
#
# Exit code: 0 only if every build that ran succeeded.

set -o pipefail
cd "$(dirname "$0")/.." || exit 1

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; NC='\033[0m'

FILTER="${1:-}"
[ $# -gt 0 ] && shift
if [ "${1:-}" = "--" ]; then
    shift
fi
EXTRA_ARGS=("$@")

mapfile -t DOCKERFILES < <(find docker/mocks/services -name "Dockerfile.*" -o -name "Dockerfile" | sort)

if [ -n "$FILTER" ]; then
    mapfile -t DOCKERFILES < <(printf '%s\n' "${DOCKERFILES[@]}" | grep -E "$FILTER")
fi

TOTAL=${#DOCKERFILES[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "No Dockerfiles matched filter '$FILTER'"
    exit 1
fi

echo "Building $TOTAL Dockerfile(s)..."
echo

declare -a FAILED
LOGDIR="$(mktemp -d)"
i=0
for dockerfile in "${DOCKERFILES[@]}"; do
    i=$((i + 1))
    context="$(dirname "$dockerfile")"
    logfile="$LOGDIR/$(echo "$dockerfile" | tr '/' '_').log"

    printf "[%d/%d] %-90s " "$i" "$TOTAL" "$dockerfile"
    if docker build -f "$dockerfile" "$context" "${EXTRA_ARGS[@]}" >"$logfile" 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        FAILED+=("$dockerfile")
    fi
done

echo
echo "=================================================================="
echo "Results: $((TOTAL - ${#FAILED[@]}))/$TOTAL succeeded"

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo -e "${RED}Failed builds:${NC}"
    for f in "${FAILED[@]}"; do
        logfile="$LOGDIR/$(echo "$f" | tr '/' '_').log"
        echo -e "  ${YELLOW}$f${NC}  (log: $logfile)"
        echo "    $(tail -n 3 "$logfile" | tr '\n' ' ' | cut -c1-200)"
    done
    echo
    echo "Full logs kept in $LOGDIR"
    exit 1
fi

rm -rf "$LOGDIR"
exit 0
