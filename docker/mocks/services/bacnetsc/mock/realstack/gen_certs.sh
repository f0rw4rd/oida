#!/bin/sh
# Mint a self-signed PKI for the BACnet/SC mock:
#   ca.pem / ca.key                  -- the issuing CA
#   server_cert.pem / server_key.pem -- device operational cert (SAN: the host)
#   client_cert.pem / client_key.pem -- OIDA client operational cert
#
# BACnet/SC operational certs are X.509 with an EKU; bacnet-stack's
# libwebsockets TLS only requires that both ends present a cert chaining to a
# configured issuer CA. SAN is set so a strict client could verify hostname.
set -e
CERTDIR="${1:-/certs}"
HOST="${2:-localhost}"
mkdir -p "$CERTDIR"
cd "$CERTDIR"

# --- CA ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 3650 -subj "/CN=OIDA-BACnetSC-Test-CA" -sha256

gen_leaf() {
  name="$1"; cn="$2"; san="$3"
  openssl req -newkey rsa:2048 -nodes -keyout "${name}_key.pem" \
    -out "${name}.csr" -subj "/CN=${cn}" -sha256
  cat > "${name}.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${san}
EXT
  openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out "${name}_cert.pem" -days 3650 -sha256 \
    -extfile "${name}.ext"
  rm -f "${name}.csr" "${name}.ext"
}

gen_leaf server "OIDA-BACnetSC-Device" "DNS:${HOST},IP:127.0.0.1"
gen_leaf client "OIDA-BACnetSC-Client" "DNS:oida-client"

echo "certs minted in ${CERTDIR}:"
ls -1 "$CERTDIR"
