#!/bin/bash
# OIDA EtherCAT Mock Slave - Healthcheck
#
# Verifies:
#   1. The ethercat_slave process is running
#   2. The configured network interface is UP
#   3. (Veth mode) The veth pair endpoints exist
#
# Exit 0 = healthy, Exit 1 = unhealthy

set -e

# Check 1: Process is running
if ! pgrep -x ethercat_slave >/dev/null 2>&1; then
    echo "UNHEALTHY: ethercat_slave process not running"
    exit 1
fi

# Check 2: Interface is up
IFACE=""
if [ -f /tmp/ethercat_interface ]; then
    IFACE=$(cat /tmp/ethercat_interface)
fi
IFACE="${IFACE:-${ETHERCAT_INTERFACE:-eth0}}"

if ! ip link show "${IFACE}" up >/dev/null 2>&1; then
    echo "UNHEALTHY: interface ${IFACE} not UP"
    exit 1
fi

# Check 3: In veth mode, verify both endpoints exist
if [ "${ETHERCAT_CREATE_VETH:-0}" = "1" ]; then
    if ! ip link show ecat0 >/dev/null 2>&1; then
        echo "UNHEALTHY: ecat0 veth endpoint missing"
        exit 1
    fi
    if ! ip link show ecat1 >/dev/null 2>&1; then
        echo "UNHEALTHY: ecat1 veth endpoint missing"
        exit 1
    fi
fi

exit 0
