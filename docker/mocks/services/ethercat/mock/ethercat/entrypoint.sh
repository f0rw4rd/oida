#!/bin/bash
# OIDA EtherCAT Mock Slave - Entrypoint
#
# Configures and launches the EtherCAT slave emulator for security testing.
#
# Two modes of operation:
#
#   1. Direct interface mode (ETHERCAT_CREATE_VETH=0, default for host networking):
#      Slave listens on ETHERCAT_INTERFACE (default: eth0).
#      The scanner runs on the host and targets the same interface.
#
#   2. Veth-pair mode (ETHERCAT_CREATE_VETH=1):
#      Creates a virtual Ethernet pair inside the container:
#        ecat0  -  slave end  (EtherCAT slave listens here)
#        ecat1  -  test end   (scanner probe / bridge to container eth0)
#      A Linux bridge (br-ecat) connects ecat1 and eth0 so that EtherCAT
#      frames arriving on the container's eth0 reach the slave via the bridge.
#      This allows testing without real EtherCAT hardware.
#
# Environment variables:
#   ETHERCAT_INTERFACE   - Network interface for direct mode (default: eth0)
#   ETHERCAT_POSITION    - Slave position on the bus (default: 1)
#   ETHERCAT_VERBOSITY   - Verbosity 0-3 (default: 1)
#   ETHERCAT_CREATE_VETH - Set to "1" to enable veth-pair mode (default: 0)

set -e

INTERFACE="${ETHERCAT_INTERFACE:-eth0}"
POSITION="${ETHERCAT_POSITION:-1}"
VERBOSITY="${ETHERCAT_VERBOSITY:-1}"
CREATE_VETH="${ETHERCAT_CREATE_VETH:-0}"

echo "========================================"
echo " OIDA EtherCAT Mock Slave"
echo "========================================"
echo " Mode:       $([ "${CREATE_VETH}" = "1" ] && echo "veth-pair" || echo "direct")"
echo " Interface:  ${INTERFACE}"
echo " Position:   ${POSITION}"
echo " Verbosity:  ${VERBOSITY}"
echo "========================================"

# -------------------------------------------------------------------
# Veth-pair mode: create ecat0/ecat1 pair and bridge to eth0
# -------------------------------------------------------------------
if [ "${CREATE_VETH}" = "1" ]; then
    echo ""
    echo "Setting up veth pair for self-contained EtherCAT testing..."

    # Clean up any stale state from previous runs
    ip link del ecat0 2>/dev/null || true
    ip link del br-ecat 2>/dev/null || true

    # Create the veth pair
    ip link add ecat0 type veth peer name ecat1
    ip link set ecat0 up
    ip link set ecat1 up

    # Set promiscuous mode on both ends (needed for raw socket capture)
    ip link set ecat0 promisc on
    ip link set ecat1 promisc on

    # Create a bridge that connects ecat1 and the container's eth0.
    # This allows EtherCAT frames from outside (via Docker bridge/macvlan)
    # to reach the slave on ecat0 through the bridge.
    if ip link show eth0 >/dev/null 2>&1; then
        # Save eth0's current IP so we can move it to the bridge
        ETH0_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+/\d+' || true)
        ETH0_GW=$(ip route | grep 'default.*eth0' | awk '{print $3}' || true)

        ip link add br-ecat type bridge
        ip link set br-ecat up

        # Add ecat1 to the bridge
        ip link set ecat1 master br-ecat

        # Add eth0 to the bridge and move its IP to br-ecat
        ip link set eth0 master br-ecat
        if [ -n "${ETH0_IP}" ]; then
            ip addr flush dev eth0
            ip addr add "${ETH0_IP}" dev br-ecat
            if [ -n "${ETH0_GW}" ]; then
                ip route add default via "${ETH0_GW}" dev br-ecat 2>/dev/null || true
            fi
        fi

        # Set bridge to forward EtherCAT frames (EtherType 0x88A4)
        # The bridge group_fwd_mask controls which L2 protocols are forwarded.
        # EtherCAT uses a standard EtherType so default bridging works.

        echo "Bridge br-ecat created: eth0 <-> ecat1 <-> ecat0 (slave)"
    else
        echo "No eth0 found -- standalone veth pair: ecat0 <-> ecat1"
    fi

    echo ""
    echo "Veth pair details:"
    ip link show ecat0 2>/dev/null || true
    ip link show ecat1 2>/dev/null || true
    echo ""

    # Write a sentinel file for the healthcheck to verify
    echo "ecat0" > /tmp/ethercat_interface
    INTERFACE="ecat0"

# -------------------------------------------------------------------
# Direct mode: use the specified interface
# -------------------------------------------------------------------
else
    # Wait for network interface
    MAX_WAIT=30
    WAITED=0
    while [ $WAITED -lt $MAX_WAIT ]; do
        if ip link show "${INTERFACE}" >/dev/null 2>&1; then
            break
        fi
        echo "Waiting for interface ${INTERFACE}..."
        sleep 1
        WAITED=$((WAITED + 1))
    done

    if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
        echo "ERROR: Interface ${INTERFACE} not found after ${MAX_WAIT}s"
        echo "Available interfaces:"
        ip link show
        exit 1
    fi

    echo ""
    echo "Interface ${INTERFACE} details:"
    ip addr show "${INTERFACE}" 2>/dev/null || true
    echo ""

    echo "${INTERFACE}" > /tmp/ethercat_interface
fi

# Build verbosity flags
VERBOSE_FLAGS=""
for i in $(seq 1 "${VERBOSITY}"); do
    VERBOSE_FLAGS="${VERBOSE_FLAGS} -v"
done

echo "Starting EtherCAT slave emulator..."
echo "Command: ethercat_slave -i ${INTERFACE} -p ${POSITION} ${VERBOSE_FLAGS}"
echo ""

exec /usr/local/bin/ethercat_slave \
    -i "${INTERFACE}" \
    -p "${POSITION}" \
    ${VERBOSE_FLAGS}
