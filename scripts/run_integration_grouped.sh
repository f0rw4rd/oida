#!/usr/bin/env bash
# run_integration_grouped.sh - memory-bounded integration test runner.
#
# WHY: `pytest tests/integration` in one process needs every mock the whole
# suite touches running at once. The full mock fleet is ~158 containers and the
# JVM-based mocks alone (3× HAPI FHIR ≈ 5 GB, HL7 Mirth, 3× OCPP SteVe) hold
# ~7 GB. On a shared / memory-constrained host that leaves too little headroom
# and the run gets OOM-killed (the pytest process itself is tiny - ~300 MB flat,
# no leak; the memory is in the container fleet).
#
# WHAT: run the integration suite one PROTOCOL GROUP at a time. Each group's
# pytest invocation only collects that group's tests, so tests/integration/
# conftest.py (pytest_collection_finish) starts ONLY that group's compose
# services. After the group finishes we stop everything the harness started
# under the `oida-test` project, so peak concurrent mock memory is bounded to a
# single group (the heaviest single group, not the union of all groups).
#
# This relies on the marker-driven container management already in the conftest
# (PROTOCOL_SERVICES map + @pytest.mark.<protocol>). No test changes needed.
#
# Usage:
#   scripts/run_integration_grouped.sh [MODE] [-- <pytest args>]
#
# Modes (pick one; default --heavy-only):
#   --heavy-only   RECOMMENDED. Keep the ~150 tiny mocks always-up (fast) and
#                  isolate ONLY the JVM heavyweights - 3× HAPI FHIR (~5 GB),
#                  3× OCPP SteVe (~1.6 GB), HL7 Mirth (~0.5 GB). They are stopped
#                  for the main pass (frees ~7 GB) and each is brought up only
#                  for its own group, so peak added memory is the single
#                  heaviest group (~5 GB), not their ~7 GB union. Drives the
#                  heavy containers by their real `mocks`-project container names
#                  (docker start/stop - they already exist, so no name clash).
#   --fresh        Strictest bounding: `python services.py down` first, then run
#                  ALL 29 protocol groups one at a time so only one group's mocks
#                  are ever up (peak = one group). Slowest (per-group container
#                  start/stop for every protocol).
#   --keep-fleet   Run groups against whatever is already up. Fast, but does NOT
#                  bound memory - use only when the whole fleet already fits.
#   -- <args>      everything after `--` is passed straight to each pytest call.
#
# Exit code: 0 only if every group passed.

set -uo pipefail
cd "$(dirname "$0")/.."

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'

MODE="heavy-only"   # heavy-only | fresh | keep-fleet
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --heavy-only) MODE="heavy-only"; shift ;;
    --fresh) MODE="fresh"; shift ;;
    --keep-fleet) MODE="keep-fleet"; shift ;;
    --) shift; EXTRA=("$@"); break ;;
    -h|--help) sed -n '2,48p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
FRESH=0; [[ "$MODE" == "fresh" ]] && FRESH=1

# Protocol marker groups (keys of PROTOCOL_SERVICES in tests/integration/conftest.py).
# Order heaviest-startup last so quick groups report first.
GROUPS=(
  modbus opcua ethernetip ads bacnet bacnetsc iec104 mms s7comm knx mqtt
  hart snmp dnp3 astm ocpp dicom hl7 fhir http2 vnc ftp smtp http coap
  ethercat profinet goose can
)

COMPOSE_FILE="docker/mocks/compose.yml"
TEST_PROJECT="oida-test"
BASE_MARK="not network and not slow"

# Join args into a pytest "a or b or c" marker fragment.
join_or() { local IFS='|'; local s="$*"; echo "${s//|/ or }"; }

# `docker ps` of everything the harness started this run, so we can stop it.
stop_test_project() {
  local ids
  ids=$(docker ps -q --filter "label=com.docker.compose.project=${TEST_PROJECT}" 2>/dev/null)
  [[ -n "$ids" ]] && docker stop $ids >/dev/null 2>&1 || true
}

# --- Heavy-only mode: the JVM heavyweights, by real container name -----------
# marker group -> containers that group's tests need brought up (the tiny mocks
# for these markers stay always-up; only these heavy JVM containers cycle).
HEAVY_ORDER=(fhir ocpp hl7)
declare -A HEAVY_CONTAINERS=(
  [fhir]="fhir-hapi-r4-server fhir-hapi-r5-server fhir-hapi-r4-strict-server"
  [ocpp]="ocpp-steve-db ocpp-steve-open ocpp-steve-secure ocpp-steve-registered"
  [hl7]="hl7-mirth-db hl7-mirth"
)
all_heavy_containers() { local g; for g in "${HEAVY_ORDER[@]}"; do echo "${HEAVY_CONTAINERS[$g]}"; done; }

docker_stop_if_present() {  # stop containers that exist, ignore missing
  local c present=()
  for c in "$@"; do docker inspect "$c" >/dev/null 2>&1 && present+=("$c"); done
  [[ ${#present[@]} -gt 0 ]] && docker stop "${present[@]}" >/dev/null 2>&1 || true
}
docker_start_if_present() {
  local c present=()
  for c in "$@"; do docker inspect "$c" >/dev/null 2>&1 && present+=("$c"); done
  [[ ${#present[@]} -gt 0 ]] && docker start "${present[@]}" >/dev/null 2>&1 || true
}
# Wait until every named container reports Docker health=healthy (or 90s).
wait_heavy_healthy() {
  local deadline=$((SECONDS + 90)) c st ready
  while [[ $SECONDS -lt $deadline ]]; do
    ready=1
    for c in "$@"; do
      docker inspect "$c" >/dev/null 2>&1 || continue
      st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null)
      [[ "$st" == "healthy" || "$st" == "none" ]] || ready=0
    done
    [[ $ready -eq 1 ]] && return 0
    sleep 3
  done
  return 1
}

run_group() {  # $1 = human label, $2 = -m marker expression
  local label="$1" mark="$2" t0 rc dt sum
  t0=$SECONDS
  python -m pytest tests/integration -p no:cacheprovider --no-header -q -o addopts="" \
    -m "$mark" -rf "${EXTRA[@]}" > "/tmp/grp_${label}.out" 2>&1
  rc=$?
  dt=$((SECONDS - t0))
  sum=$(grep -E "[0-9]+ (passed|failed|error|skipped)" "/tmp/grp_${label}.out" | tail -1)
  local color=$GREEN; [[ $rc -ne 0 ]] && color=$RED
  printf "${color}[%-10s] rc=%d  %4ds  %s${NC}\n" "$label" "$rc" "$dt" "${sum:-<no summary>}"
  grep -E "^FAILED|^ERROR" "/tmp/grp_${label}.out" | sed 's/^/    /'
  # Free this group's mock memory before the next group starts.
  [[ $FRESH -eq 1 ]] && stop_test_project
  return $rc
}

echo -e "${BLUE}== memory-bounded grouped integration run (mode: ${MODE}) ==${NC}"
FAILED_GROUPS=()
START=$SECONDS

if [[ "$MODE" == "heavy-only" ]]; then
  # Keep the tiny fleet up; cycle only the JVM heavyweights.
  echo -e "${YELLOW}Stopping JVM heavyweights (frees ~7 GB), keeping tiny fleet up...${NC}"
  RESTORE=$(all_heavy_containers)
  docker_stop_if_present $RESTORE
  # ensure the heavy mocks come back even if the run is interrupted
  trap 'echo "restoring heavy mocks..."; docker_start_if_present $RESTORE' EXIT INT TERM

  # Main pass: everything EXCEPT the heavy groups (their JVM mocks are down;
  # any realstack test needing them self-skips via its _require() port guard).
  run_group "main" "not ($(join_or "${HEAVY_ORDER[@]}")) and $BASE_MARK" || FAILED_GROUPS+=("main")

  # Each heavy group: bring up only its containers, run, tear them down again.
  for g in "${HEAVY_ORDER[@]}"; do
    echo -e "${YELLOW}[$g] starting: ${HEAVY_CONTAINERS[$g]}${NC}"
    docker_start_if_present ${HEAVY_CONTAINERS[$g]}
    wait_heavy_healthy ${HEAVY_CONTAINERS[$g]} \
      || echo -e "${YELLOW}[$g] not healthy within 90s - tests may skip/fail${NC}"
    run_group "$g" "$g and $BASE_MARK" || FAILED_GROUPS+=("$g")
    docker_stop_if_present ${HEAVY_CONTAINERS[$g]}
  done
else
  # fresh / keep-fleet: run all 29 protocol groups one at a time.
  if [[ $FRESH -eq 1 ]]; then
    echo -e "${YELLOW}Bringing the always-on mock fleet down for a clean slate...${NC}"
    python services.py down >/dev/null 2>&1 || true
    stop_test_project
  fi
  for g in "${GROUPS[@]}"; do
    run_group "$g" "$g and $BASE_MARK" || FAILED_GROUPS+=("$g")
  done
  # Everything with no protocol marker (pcap listeners, common, cli, marker-less
  # fuzz) - needs no mock fleet, so run it as one final group.
  NOMARK="not ($(join_or "${GROUPS[@]}")) and $BASE_MARK"
  run_group "no-mock" "$NOMARK" || FAILED_GROUPS+=("no-mock")
fi

TOTAL=$((SECONDS - START))
echo -e "${BLUE}== done in ${TOTAL}s ==${NC}"
if [[ ${#FAILED_GROUPS[@]} -eq 0 ]]; then
  echo -e "${GREEN}All groups passed.${NC}"; exit 0
else
  echo -e "${RED}Failed groups: ${FAILED_GROUPS[*]}${NC}"; exit 1
fi
