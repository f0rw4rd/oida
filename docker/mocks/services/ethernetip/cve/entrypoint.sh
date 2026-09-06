#!/bin/sh
# Start the real OpENer POSIX sample server, foregrounded so the ASan/UBSan
# abort trace lands in `docker logs`. OpENer takes the network interface name as
# argv[1] and reads its IP/MAC from that interface, so we pick the first
# non-loopback interface present in the container (normally eth0).
set -e

IFACE="${OPENER_IFACE:-}"
if [ -z "$IFACE" ]; then
    IFACE="$(ip -o link show 2>/dev/null \
             | awk -F': ' '{sub(/@.*/, "", $2); if ($2 != "lo") {print $2; exit}}')"
fi
[ -z "$IFACE" ] && IFACE="eth0"

echo "==========================================="
echo "  REAL OpENer vulnerable server (ASan+UBSan)"
echo "  Interface: $IFACE"
echo "  EtherNet/IP TCP 44818 / UDP 2222"
echo "  FOR SECURITY TESTING ONLY"
echo "==========================================="

# OpENer aborts on accept loop errors only; run it in the foreground as PID-ish
# so ASan's abort() terminates the container with the trace visible.
exec /app/OpENer "$IFACE"
