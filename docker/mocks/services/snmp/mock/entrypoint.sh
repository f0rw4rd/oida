#!/bin/bash
# OIDA SNMP Mock — entrypoint
# Creates SNMPv3 users then starts snmpd in foreground.
#
# Profile selection via SNMP_PROFILE env var:
#   linux   — ICS server with interfaces, TCP listeners, ARP, traps
#   windows — Windows ICS workstation with LanManager MIB
#   switch  — H3C managed switch with credential tables, MAC/FDB
#   v3only  — Hardened gateway, SNMPv3 auth required, no v1/v2c
#
# User matrix (all profiles):
#   initial   — noAuthNoPriv (no password)
#   engineer  — authNoPriv, SHA, pass=engineer1
#   readonly  — authNoPriv, MD5, pass=readonly1
#   admin     — authPriv, SHA+AES128, auth=admin123, priv=admin123
#   monitor   — authPriv, MD5+DES, auth=monitor1, priv=monitor1
#   service   — authPriv, SHA+AES128, auth=service1, priv=service1
#   operator  — authPriv, SHA-256+AES-256, auth=operator1, priv=operator1
#   backup    — authPriv, SHA-512+AES-192, auth=backup12, priv=backup12
#
# NOTE: USM passphrases must be >= 8 characters (net-snmp minimum).

set -e

# Select config based on profile
case "${SNMP_PROFILE}" in
  windows) cp /etc/snmp/snmpd-windows.conf /etc/snmp/snmpd.conf ;;
  switch)  cp /etc/snmp/snmpd-switch.conf /etc/snmp/snmpd.conf ;;
  v3only)  cp /etc/snmp/snmpd-v3only.conf /etc/snmp/snmpd.conf ;;
  *)       ;; # linux profile uses default snmpd.conf
esac

# Create SNMPv3 users (same for all profiles)
PERSIST=/var/lib/snmp/snmpd.conf

# Only create users on first start (after processing, snmpd replaces
# createUser lines with hashed usmUser rows)
if ! grep -q "usmUser" "$PERSIST" 2>/dev/null; then
    echo "=== Creating SNMPv3 users ==="

    if [ "${SNMP_PROFILE}" = "v3only" ]; then
        # v3only profile: no noauth user, only auth/priv users
        cat > "$PERSIST" <<'EOF'
createUser engineer SHA engineer1
createUser admin SHA admin123 AES admin123
createUser monitor MD5 monitor1 DES monitor1
createUser operator SHA-256 operator1 AES-256 operator1
EOF
    else
        cat > "$PERSIST" <<'EOF'
createUser initial
createUser engineer SHA engineer1
createUser readonly MD5 readonly1
createUser admin SHA admin123 AES admin123
createUser monitor MD5 monitor1 DES monitor1
createUser service SHA service1 AES service1
createUser operator SHA-256 operator1 AES-256 operator1
createUser backup SHA-512 backup12 AES-192 backup12
EOF
    fi

    echo "=== Users created ==="
fi

# Profile-specific OS state
case "${SNMP_PROFILE}" in
  linux)
    echo "=== Linux ICS profile: creating interfaces, listeners, ARP ==="

    # Create dummy veth interface for realistic ifTable data
    ip link add veth-ics0 type veth peer name veth-ics0-peer 2>/dev/null || true
    ip link set veth-ics0 up 2>/dev/null || true
    ip addr add 192.168.1.100/24 dev veth-ics0 2>/dev/null || true

    # Start ICS port listeners so tcpConnTable shows ICS services
    for port in 502 2404 4840 44818; do
      python3 -c "
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $port)); s.listen(1)
while True:
    c, a = s.accept(); c.close()
" &
    done

    # Add IPv6 addresses for --enum ipv6 testing
    # Global unicast (2001:db8::/32 is documentation prefix, safe for mocks)
    ip -6 addr add 2001:db8:ics::100/64 dev veth-ics0 2>/dev/null || true
    # Link-local is auto-assigned on veth-ics0, no action needed

    # Populate ARP cache for ipNetToMediaTable
    ip neigh add 192.168.1.1 lladdr 00:1a:2b:3c:4d:5e dev eth0 nud permanent 2>/dev/null || true
    ip neigh add 192.168.1.50 lladdr 00:de:ad:be:ef:01 dev eth0 nud permanent 2>/dev/null || true

    # Start dummy process with credentials in args (for --enum creds process scanning)
    # hrSWRunParameters reads from /proc/<pid>/cmdline — net-snmp reports argv as parameters
    python3 -c "import time; time.sleep(86400)" --host plc01 --password=S3cretICS &
    ;;
  switch)
    echo "=== Switch profile: creating dummy port interfaces ==="

    # Multiple dummy interfaces to simulate switch ports
    for i in $(seq 1 4); do
      ip link add "port$i" type dummy 2>/dev/null || true
      ip link set "port$i" up 2>/dev/null || true
    done
    ;;
  windows)
    echo "=== Windows ICS profile ==="
    ;;
esac

echo "=== Starting snmpd (profile: ${SNMP_PROFILE}) ==="
# No -C (suppresses persistent store), no -c (config at default path)
exec snmpd -f -Lo
