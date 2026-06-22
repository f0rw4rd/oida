#!/bin/sh
# Entrypoint for the CVE-2010-2156 (ISC DHCP 4.1.1 pre-P1) DoS reproducer.
#
# dhcpd binds via a Linux Packet Filter (AF_PACKET) raw socket and only listens
# on non-loopback, broadcast-capable interfaces (common/discover.c skips
# IFF_LOOPBACK / non-IFF_BROADCAST). A dummy interface is broadcast-capable so
# dhcpd binds it, but a dummy DROPS transmitted frames and never delivers them
# to its own RX -- the PoC packet would never arrive. So we use a VETH PAIR:
#
#     dhcp0  <-->  dhcpsink
#
# dhcpd binds dhcp0 (carrying 10.99.0.1/24, the subnet in the conf). The PoC
# injects a full Ethernet/IP/UDP/DHCP frame via AF_PACKET on dhcpsink; the
# kernel delivers it out of dhcpsink and into dhcp0's RX, where dhcpd's BPF
# filter (EtherType IP + UDP + dst port 67, no MAC/IP check) accepts it and
# hands it to the option-61 parser.
#
# dhcpd runs FOREGROUNDED (-f) and logs to stderr (-d) so the fatal
# "Impossible condition at .../hash.c:NNN" line reaches docker logs. dhcpd is
# the container's main process: when the zero-length-client-id packet drives
# log_fatal() -> exit(1), the container exits 1. That exit is the observable.
set -e

# veth pair: dhcp0 (dhcpd side) <-> dhcpsink (injection side).
ip link add dhcp0 type veth peer name dhcpsink 2>/dev/null || true
ip addr add 10.99.0.1/24 dev dhcp0 2>/dev/null || true
ip link set dhcp0 up 2>/dev/null || true
ip link set dhcpsink up 2>/dev/null || true
ip link set lo up 2>/dev/null || true

# Ensure a writable lease db.
mkdir -p /var/lib/dhcp
touch /var/lib/dhcp/dhcpd.leases

echo "[entrypoint] starting vulnerable dhcpd (ISC DHCP 4.1.1, CVE-2010-2156)"
/usr/local/sbin/dhcpd --version 2>&1 | head -1 || true

# -f foreground, -d log to stderr, -cf config. Bind to dhcp0 (the conf subnet).
# We do NOT use --no-pid (some 4.1.1 builds lack it); -f already keeps PID
# handling out of the way for a foreground run. Use a pid file under /tmp.
exec /usr/local/sbin/dhcpd -f -d \
    -cf /app/dhcpd-2010-2156.conf \
    -lf /var/lib/dhcp/dhcpd.leases \
    -pf /tmp/dhcpd-2010-2156.pid \
    dhcp0
