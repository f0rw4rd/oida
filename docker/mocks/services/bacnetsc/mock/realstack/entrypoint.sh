#!/bin/sh
# OIDA real-stack BACnet/SC mock — entrypoint
#
# Mints a self-signed PKI (CA + device operational cert + a CLIENT cert that
# OIDA presents) and launches the genuine bacnet-stack "bacserv" demo built for
# the BSC datalink in DIRECT-CONNECT accept mode over WSS/TLS.
#
# Env vars (set per service in compose.yml):
#   BACNET_DEVICE_INSTANCE  device object instance number (argv[1])
#   BACNET_DEVICE_NAME      device object name            (argv[2])
#   BACNET_PROFILE          object inventory: rtu | building | vav
#   BACNET_SC_DIRECT_PORT   TCP/WSS port for direct-connect accept, default 47800
#   BACNET_SC_WEAK          if "1", deliberately weak posture (see below)
#   BACNET_FILE_DIR         working dir for File-object backing files
#
# The client cert + CA are copied to a shared, world-readable path so the test
# harness / OIDA can present them: /certs is the canonical mount.
set -e

: "${BACNET_DEVICE_INSTANCE:=123}"
: "${BACNET_DEVICE_NAME:=OIDA-BACnetSC-Device}"
: "${BACNET_PROFILE:=building}"
: "${BACNET_SC_DIRECT_PORT:=47800}"
: "${BACNET_SC_WEAK:=0}"
: "${BACNET_FILE_DIR:=/data/bacnet}"
# CERTDIR is the canonical (mountable) location the test harness / OIDA read
# the client cert + CA from. bacnet-stack's posix bacfile backend, however,
# REJECTS absolute pathnames ("Absolute paths are prohibited") because the
# BSC cert files are exposed as BACnet File objects read through that backend.
# So the server reads its certs via RELATIVE paths from its working dir
# (BACNET_FILE_DIR): we mint into CERTDIR (for the client) and also stage a
# copy under the working dir, then reference those relatively.
: "${CERTDIR:=/certs}"

# --- PKI -------------------------------------------------------------------
# Mint once; persist across restarts if the dir is a volume.
if [ ! -f "${CERTDIR}/ca.pem" ]; then
    gen_certs.sh "${CERTDIR}" "${HOSTNAME:-localhost}"
fi
chmod -R a+rX "${CERTDIR}" || true

# Stage server-side certs under the working dir as RELATIVE paths.
mkdir -p "${BACNET_FILE_DIR}/certs"
cp "${CERTDIR}/ca.pem" "${CERTDIR}/server_cert.pem" "${CERTDIR}/server_key.pem" \
   "${BACNET_FILE_DIR}/certs/"

export BACNET_SC_ISSUER_1_CERTIFICATE_FILE="certs/ca.pem"
export BACNET_SC_OPERATIONAL_CERTIFICATE_FILE="certs/server_cert.pem"
export BACNET_SC_OPERATIONAL_CERTIFICATE_PRIVATE_KEY_FILE="certs/server_key.pem"

# --- BSC datalink: direct-connect accept mode ------------------------------
# A node that ACCEPTS direct connections on the given port. No hub needed —
# OIDA dials wss://host:PORT directly (subprotocol dc.bsc.bacnet.org).
export BACNET_SC_DIRECT_CONNECT_BINDING="${BACNET_SC_DIRECT_PORT}"
export BACNET_SC_DIRECT_CONNECT_INITIATE="n"

export BACNET_PROFILE

# --- posture --------------------------------------------------------------
# WEAK vs SECURE is decided at BUILD time, not here: stock bacnet-stack does
# NOT set the libwebsockets "require valid client cert" option and negotiates
# down to TLS 1.2, so the unpatched binary IS the weak posture (accepts
# anonymous/rogue clients + TLS 1.2 -> OIDA's findings fire). The secure image
# is built with STRICT=1, which patches websocket-srv.c to require a valid
# client cert chaining to the issuer CA and pin TLS 1.3 -> OIDA's findings are
# silent. BACNET_SC_WEAK here is informational only.
if [ "${BACNET_SC_WEAK}" = "1" ]; then
    echo "  [mock] posture: WEAK (mutual-auth not enforced, TLS 1.2 allowed)"
else
    echo "  [mock] posture: as built (SECURE if image built with STRICT=1)"
fi

mkdir -p "${BACNET_FILE_DIR}"
cd "${BACNET_FILE_DIR}"

echo "==========================================="
echo "  OIDA real bacnet-stack BSC server (bacserv)"
echo "  Profile:   ${BACNET_PROFILE}"
echo "  Device:    ${BACNET_DEVICE_INSTANCE} (${BACNET_DEVICE_NAME})"
echo "  Direct-connect WSS port (TCP): ${BACNET_SC_DIRECT_PORT}"
echo "  Certs:     ${CERTDIR}"
echo "==========================================="

exec bacserv "${BACNET_DEVICE_INSTANCE}" "${BACNET_DEVICE_NAME}"
