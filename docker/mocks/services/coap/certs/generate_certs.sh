#!/bin/bash
# Generate self-signed CA and server/client certificates for CoAP DTLS testing.
#
# Creates:
#   ca.pem        - CA certificate
#   ca-key.pem    - CA private key
#   server.pem    - Server certificate (signed by CA)
#   server-key.pem - Server private key
#   client.pem    - Client certificate (signed by CA)
#   client-key.pem - Client private key
#
# All certs are valid for 3650 days (10 years) with localhost/127.0.0.1 SANs.

set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERT_DIR"

# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 3650 -nodes -batch \
    -subj "/CN=OIDA Test CA/O=OIDA/OU=Testing" \
    -keyout ca-key.pem -out ca.pem 2>/dev/null

# Server cert
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -batch \
    -subj "/CN=coap-dtls-cert/O=OIDA/OU=Mock" \
    -keyout server-key.pem -out server.csr 2>/dev/null

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 3650 \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:coap-dtls-cert,IP:127.0.0.1") \
    -out server.pem 2>/dev/null

# Client cert
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -batch \
    -subj "/CN=oida-client/O=OIDA/OU=Scanner" \
    -keyout client-key.pem -out client.csr 2>/dev/null

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 3650 \
    -out client.pem 2>/dev/null

# Cleanup CSRs
rm -f server.csr client.csr ca.srl

echo "Certificates generated in $CERT_DIR"
ls -la "$CERT_DIR"/*.pem
