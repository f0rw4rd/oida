#!/bin/sh
# OIDA real-stack BACnet mock - entrypoint
#
# Launches the genuine bacnet-stack "bacserv" demo server (BACnet/IP, UDP).
# Configuration via env vars (set per service in compose.yml):
#   BACNET_DEVICE_INSTANCE  Device object instance number (argv[1])
#   BACNET_DEVICE_NAME      Device object name           (argv[2])
#   BACNET_PROFILE          object inventory profile: rtu | building | vav
#                           (read by Server_Profile_Init in profile.inc)
#   BACNET_IP_PORT          BACnet/IP UDP port (read by dlenv_init), default 47808
#   BACNET_IFACE            network interface (read by dlenv_init), default all
#   BACNET_REINIT_PASSWORD  ReinitializeDevice password (building profile),
#                           default "OIDA-Reinit" (see profile.inc)
#   BACNET_FILE_DIR         working dir holding the File-object backing files,
#                           default /data/bacnet
set -e

: "${BACNET_DEVICE_INSTANCE:=1234}"
: "${BACNET_DEVICE_NAME:=OIDA-BACnet-Device}"
: "${BACNET_PROFILE:=rtu}"
: "${BACNET_IP_PORT:=47808}"
: "${BACNET_FILE_DIR:=/data/bacnet}"

export BACNET_IP_PORT
export BACNET_PROFILE

# File objects (building profile) read their content from RELATIVE pathnames in
# the server's working directory -- the posix backend rejects absolute paths and
# "..". Seed realistic files here so AtomicReadFile returns real bytes, then run
# bacserv from this directory. Existing files are preserved (writable via
# AtomicWriteFile across restarts).
mkdir -p "${BACNET_FILE_DIR}"
if [ ! -f "${BACNET_FILE_DIR}/config.ini" ]; then
    cat > "${BACNET_FILE_DIR}/config.ini" <<EOF
[device]
name=${BACNET_DEVICE_NAME}
instance=${BACNET_DEVICE_INSTANCE}
vendor_id=15
[network]
ip_mode=dhcp
bacnet_port=${BACNET_IP_PORT}
[security]
reinit_password_set=true
EOF
fi
if [ ! -f "${BACNET_FILE_DIR}/firmware.bin" ]; then
    {
        printf 'OIDA-FW\x01BC-5000\x00fw=1.4.4\x00'
        head -c 480 /dev/zero 2>/dev/null
    } > "${BACNET_FILE_DIR}/firmware.bin"
fi
if [ ! -f "${BACNET_FILE_DIR}/audit.log" ]; then
    cat > "${BACNET_FILE_DIR}/audit.log" <<EOF
$(date -u '+%Y-%m-%dT%H:%M:%SZ') device boot, profile=${BACNET_PROFILE}
$(date -u '+%Y-%m-%dT%H:%M:%SZ') reinitialize password configured
EOF
fi
cd "${BACNET_FILE_DIR}"

echo "==========================================="
echo "  OIDA real bacnet-stack server (bacserv)"
echo "  Profile:  ${BACNET_PROFILE}"
echo "  Device:   ${BACNET_DEVICE_INSTANCE} (${BACNET_DEVICE_NAME})"
echo "  BACnet/IP UDP port: ${BACNET_IP_PORT}"
echo "  File dir: ${BACNET_FILE_DIR}"
echo "==========================================="

exec bacserv "${BACNET_DEVICE_INSTANCE}" "${BACNET_DEVICE_NAME}"
