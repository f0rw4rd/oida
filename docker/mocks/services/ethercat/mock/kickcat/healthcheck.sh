#!/bin/bash
# OIDA EtherCAT Mock Slaves (KickCAT) - Healthcheck
#
# Healthy when:
#   1. the network_simulator process is running, AND
#   2. both veth endpoints exist and are UP.
#
# (There is no listening port -- EtherCAT is raw L2 -- so liveness of the
#  simulator process plus an UP slave-bus interface is the health signal.)
#
# Exit 0 = healthy, Exit 1 = unhealthy

set -e

IF_SLAVE="${ECAT_IF_SLAVE:-ecatsimA}"
IF_SCAN="$(cat /tmp/ethercat_scan_iface 2>/dev/null || echo "${ECAT_IF_SCAN:-ecatsimB}")"

# NOTE: use `pgrep -f` (full command line). The kernel truncates /proc/<pid>/comm
# to 15 chars ("network_simulat"), so `pgrep -x network_simulator` never matches.
if ! pgrep -f network_simulator >/dev/null 2>&1; then
    echo "UNHEALTHY: network_simulator process not running"
    exit 1
fi

if ! ip link show "${IF_SLAVE}" up >/dev/null 2>&1; then
    echo "UNHEALTHY: slave-bus interface ${IF_SLAVE} not UP"
    exit 1
fi

if ! ip link show "${IF_SCAN}" up >/dev/null 2>&1; then
    echo "UNHEALTHY: scanner interface ${IF_SCAN} not UP"
    exit 1
fi

exit 0
