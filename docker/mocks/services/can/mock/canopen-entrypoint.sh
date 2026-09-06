#!/bin/sh
# Entrypoint for the real CANopen mock node.
#
# CAN is an L2 bus, not routable. The virtual CAN interface (vcan0) must exist
# in THIS container's network namespace; any scanner that wants to reach the
# node must share that netns (docker run --network container:<this>).
#
# Requires NET_ADMIN (or --privileged) to create the link. Kernel 6.12 has
# built-in vcan, so no module load is needed inside the container.
set -e

CHAN="${CANOPEN_CHANNEL:-vcan0}"

if ! ip link show "$CHAN" >/dev/null 2>&1; then
    echo "[entrypoint] creating virtual CAN interface $CHAN"
    ip link add dev "$CHAN" type vcan
fi

# Bring the link up. When this container SHARES another container's netns
# (docker run --network container:<owner>) the interface is already created
# and UP by its owner, and this container may lack NET_ADMIN -- so a failed
# 'set up' on an already-UP link is fine; only abort if the link is down.
if ! ip link set up "$CHAN" 2>/dev/null; then
    if ip link show "$CHAN" | grep -q "state UP\|<NOARP,UP"; then
        echo "[entrypoint] $CHAN already UP (shared netns), continuing"
    else
        echo "[entrypoint] ERROR: cannot bring up $CHAN (need NET_ADMIN/privileged)" >&2
        exit 1
    fi
fi
echo "[entrypoint] $CHAN is up:"
ip -d link show "$CHAN" | sed 's/^/[entrypoint]   /'

exec python3 /app/canopen_node.py
