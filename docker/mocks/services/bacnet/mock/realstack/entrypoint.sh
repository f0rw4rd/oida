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
set -e

: "${BACNET_DEVICE_INSTANCE:=1234}"
: "${BACNET_DEVICE_NAME:=OIDA-BACnet-Device}"
: "${BACNET_PROFILE:=rtu}"
: "${BACNET_IP_PORT:=47808}"

export BACNET_IP_PORT
export BACNET_PROFILE

echo "==========================================="
echo "  OIDA real bacnet-stack server (bacserv)"
echo "  Profile:  ${BACNET_PROFILE}"
echo "  Device:   ${BACNET_DEVICE_INSTANCE} (${BACNET_DEVICE_NAME})"
echo "  BACnet/IP UDP port: ${BACNET_IP_PORT}"
echo "==========================================="

exec bacserv "${BACNET_DEVICE_INSTANCE}" "${BACNET_DEVICE_NAME}"
