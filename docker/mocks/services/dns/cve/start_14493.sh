#!/bin/sh
# CVE-2017-14493 - dnsmasq 2.77 DHCPv6 server (ASan build)
# Stack-based buffer overflow in dhcp6_maybe_relay() / src/rfc3315.c when
# copying an oversized OPTION6_CLIENT_MAC (79) into the 16-byte state->mac[].
echo "=================================================="
echo "  REAL dnsmasq 2.77 - CVE-2017-14493 (ASan)"
echo "  Stack overflow in dhcp6_maybe_relay (rfc3315.c)"
echo "  DHCPv6 server on UDP/547 (loopback)"
echo "=================================================="

echo "[*] lo addresses:"
ip -6 addr show dev lo || true

echo "[*] starting dnsmasq 2.77 (foreground, debug)..."
exec dnsmasq -d -q -C /etc/dnsmasq.conf
