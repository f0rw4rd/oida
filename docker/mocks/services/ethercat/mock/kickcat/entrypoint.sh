#!/bin/bash
# OIDA EtherCAT Mock Slave (KickCAT network_simulator) - Entrypoint
#
# Runs leducp/KickCAT's software EtherCAT slave simulator -- a REAL EtherCAT
# Slave Controller emulator (EmulatedESC: registers, SyncManagers, FMMUs,
# EEPROM/SII, CoE mailbox, DC clock) -- so a SOEM/pysoem master (which is what
# `oida ethercat` is) can enumerate it over Layer 2 (EtherType 0x88A4).
#
# REACHABILITY (verified on the wire with the real `oida ethercat` CLI):
#   KickCAT's network_simulator, when given a PLAIN interface name (NOT the
#   "tap:server" shared-memory pseudo-interface), opens a real PF_PACKET /
#   SOCK_RAW socket on that Linux interface (lib/src/OS/Linux/Socket.cc). That
#   is the *same* raw-L2 mechanism SOEM uses, so a FOREIGN SOEM master on the
#   peer end of a veth pair enumerates the simulated slaves.
#
#   This entrypoint therefore creates an internal veth pair:
#       ecatsimA  <-- KickCAT network_simulator binds here (the "slave bus")
#       ecatsimB  <-- the scanner targets this end (same netns)
#   and the OIDA scanner is run from the SAME network namespace, e.g.:
#       docker exec ethercat-kickcat-slaves oida ethercat ecatsimB
#   (or any SOEM master in this container's netns; see compose comments).
#
# EtherCAT is Layer 2 and non-routable: there are NO TCP/UDP ports. The slaves
# are only reachable inside this container's network namespace. CAP_NET_RAW is
# required for the raw socket; CAP_NET_ADMIN for the veth pair + promisc.
#
# Environment variables:
#   ECAT_IF_SLAVE   - veth end the simulator binds  (default: ecatsimA)
#   ECAT_IF_SCAN    - veth end the scanner targets   (default: ecatsimB)
#   ECAT_CONFIGS    - space-separated slave config JSONs (default: both shipped)

set -e

IF_SLAVE="${ECAT_IF_SLAVE:-ecatsimA}"
IF_SCAN="${ECAT_IF_SCAN:-ecatsimB}"
CONFIG_DIR="/opt/oida/slave_configs"
DEFAULT_CONFIGS="${CONFIG_DIR}/slave_a_ingenia.json ${CONFIG_DIR}/slave_b_infineon.json"
CONFIGS="${ECAT_CONFIGS:-${DEFAULT_CONFIGS}}"

echo "=================================================="
echo " OIDA EtherCAT Mock Slaves -- KickCAT simulator"
echo "=================================================="
echo " Slave-bus iface (simulator): ${IF_SLAVE}"
echo " Scanner iface  (oida side):  ${IF_SCAN}"
echo " Slave configs:               ${CONFIGS}"
echo "=================================================="

# Clean up any stale veth from a previous run
ip link del "${IF_SLAVE}" 2>/dev/null || true

# Create the veth pair connecting the simulator and the scanner end.
ip link add "${IF_SLAVE}" type veth peer name "${IF_SCAN}"
ip link set "${IF_SLAVE}" up
ip link set "${IF_SCAN}" up
ip link set "${IF_SLAVE}" promisc on
ip link set "${IF_SCAN}" promisc on

echo ""
echo "veth pair ready:"
ip -br link show "${IF_SLAVE}" || true
ip -br link show "${IF_SCAN}" || true
echo ""

# Sentinel for the healthcheck
echo "${IF_SCAN}" > /tmp/ethercat_scan_iface

echo "Launching KickCAT network_simulator..."
echo "  network_simulator -i ${IF_SLAVE} -s ${CONFIGS}"
echo ""
echo "Scan from THIS container's netns with:"
echo "  oida ethercat ${IF_SCAN}"
echo ""

# network_simulator must run in the slave_configs dir so the ESI paths in the
# JSON configs (relative to the config dir) resolve.
cd "${CONFIG_DIR}"

exec /usr/local/bin/network_simulator -i "${IF_SLAVE}" -s ${CONFIGS}
