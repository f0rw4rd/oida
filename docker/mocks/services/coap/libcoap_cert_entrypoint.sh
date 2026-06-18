#!/bin/bash
# Entrypoint for libcoap-based CoAP DTLS certificate server.
#
# Starts coap-server-openssl with X.509 certificate authentication,
# then populates resources via the plain CoAP port (DTLS port + 1
# is the convention, but libcoap listens on port and port+1 when
# DTLS is enabled via certificates).
#
# Environment variables:
#   COAP_PORT       - Listen port (default: 5683, DTLS on port+1=5684)
#   COAP_VERBOSITY  - Log level 0-9 (default: 5)

set -e

PORT="${COAP_PORT:-5683}"
DTLS_PORT=$((PORT + 1))
VERBOSITY="${COAP_VERBOSITY:-5}"

CERT_DIR="/app/certs"
SERVER="coap-server-openssl"

echo "[libcoap-cert] Starting $SERVER with PKI on port $PORT (DTLS on $DTLS_PORT)"
echo "[libcoap-cert]   Server cert: $CERT_DIR/server.pem"
echo "[libcoap-cert]   Server key:  $CERT_DIR/server-key.pem"
echo "[libcoap-cert]   CA cert:     $CERT_DIR/ca.pem"

# Start server with certificate auth
# -c certfile  -j keyfile  -C cafile  -n (no peer cert required for testing)
$SERVER -p "$PORT" -d 60 -e -v "$VERBOSITY" \
    -c "$CERT_DIR/server.pem" \
    -j "$CERT_DIR/server-key.pem" \
    -C "$CERT_DIR/ca.pem" \
    -n &
SERVER_PID=$!

# Wait for server to be ready
echo "[libcoap-cert] Waiting for server to start..."
for i in $(seq 1 20); do
    if python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(b'\x40\x00\x00\x01', ('127.0.0.1', $PORT))
try:
    data, _ = s.recvfrom(64)
    sys.exit(0)
except:
    sys.exit(1)
finally:
    s.close()
" 2>/dev/null; then
        echo "[libcoap-cert] Server ready on port $PORT (DTLS on $DTLS_PORT)"
        break
    fi
    sleep 0.5
done

# Populate resources via plain CoAP port
CLIENT="coap-client-notls"
BASE_URI="coap://127.0.0.1:${PORT}"

put() {
    $CLIENT -m put -e "$2" "$BASE_URI$1" 2>/dev/null || true
}

echo "[libcoap-cert] Populating resources via PUT..."

put /sensor/temperature "23.45"
put /sensor/humidity    "55.2"
put /sensor/pressure    "1013.8"
put /device '{"manufacturer":"OIDA-Test","model":"libcoap-cert-v1","serial":"SN-LC-CERT-001","firmware":"4.3.1-cert"}'
put /config '{"device_name":"libcoap-cert","security":"certificate"}'
put /firmware/version   "4.3.1-cert"

# LwM2M Device Object
put /3/0/0  "OIDA-Test"
put /3/0/1  "libcoap-cert-v1"
put /3/0/2  "SN-LC-CERT-001"
put /3/0/3  "4.3.1-cert"
put /3/0/9  "95"

# LwM2M Security Object (mode=2 = Certificate)
put /0/0/2 "2"

echo "[libcoap-cert] Resources populated. Server PID=$SERVER_PID"
echo "[libcoap-cert] Ready. Plain CoAP on $PORT, DTLS on $DTLS_PORT"

wait $SERVER_PID
