#!/bin/sh
# CVE-2017-14491 - dnsmasq 2.77 forwarder + malicious upstream (ASan fenced)
echo "=============================================="
echo "  REAL dnsmasq 2.77 - CVE-2017-14491 (ASan)"
echo "  Heap overflow: do_rfc1035_name / add_resource_record"
echo "  Port: 53/udp  (forwarder -> 127.0.0.1#5399)"
echo "  Trigger: A query for victim.example, sent twice"
echo "=============================================="
python3 /app/malicious_upstream_14491.py &
sleep 1
echo "[*] starting dnsmasq 2.77 (foreground, debug)..."
exec dnsmasq -d -q
