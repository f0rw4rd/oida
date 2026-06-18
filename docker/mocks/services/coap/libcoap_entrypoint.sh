#!/bin/bash
# Entrypoint for libcoap-based CoAP mock servers.
#
# Starts coap-server, waits for it to be ready, then uses coap-client to
# pre-populate dynamic resources via PUT so the scanner sees realistic data.
#
# This creates a rich resource tree that mimics a real IoT/ICS device:
#   - Sensor readings (temperature, humidity, pressure, vibration, flow)
#   - Actuator controls (led, relay, valve, motor)
#   - Device metadata and config
#   - LwM2M-style object paths (/3/0/*, /0/0/*, /1/0/*, /5/0/*)
#   - ICS-specific paths (PLC status, alarms, setpoints)
#
# Environment variables:
#   COAP_PORT       - Listen port (default: 5683)
#   COAP_PSK_KEY    - If set, use coap-server-openssl with DTLS-PSK
#   COAP_PSK_HINT   - PSK identity hint (default: "CoAP")
#   COAP_VERBOSITY  - Log level 0-9 (default: 5)

set -e

PORT="${COAP_PORT:-5683}"
VERBOSITY="${COAP_VERBOSITY:-5}"
PSK_KEY="${COAP_PSK_KEY:-}"
PSK_HINT="${COAP_PSK_HINT:-CoAP}"

# Select server binary based on DTLS config
if [ -n "$PSK_KEY" ]; then
    SERVER="coap-server-openssl"
    SERVER_ARGS="-p $PORT -d 60 -e -v $VERBOSITY -k $PSK_KEY -h $PSK_HINT"
    echo "[libcoap] Starting $SERVER with DTLS-PSK (hint=$PSK_HINT) on port $PORT (+1 for DTLS)"
else
    SERVER="coap-server-notls"
    SERVER_ARGS="-p $PORT -d 60 -e -v $VERBOSITY"
    echo "[libcoap] Starting $SERVER (no TLS) on port $PORT"
fi

# Start server in background
$SERVER $SERVER_ARGS &
SERVER_PID=$!

# Wait for server to be ready (try CoAP ping)
echo "[libcoap] Waiting for server to start..."
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
        echo "[libcoap] Server ready on port $PORT"
        break
    fi
    sleep 0.5
done

# Use the notls client for resource population (even for DTLS server,
# we populate via the plain CoAP port which is also listening)
CLIENT="coap-client-notls"
BASE_URI="coap://127.0.0.1:${PORT}"

put() {
    $CLIENT -m put -e "$2" "$BASE_URI$1" 2>/dev/null || true
}

echo "[libcoap] Populating resources via PUT..."

# ── Sensor resources ──
put /sensor/temperature "23.45"
put /sensor/humidity    "55.2"
put /sensor/pressure    "1013.8"
put /sensor/vibration   "0.42"
put /sensor/flow        "12.7"
put /sensor/level       "78"
put /sensor/voltage     "24.1"
put /sensor/current     "4.82"

# ── Actuator resources ──
put /actuator/led       "0"
put /actuator/relay     "0"
put /actuator/valve     "50"
put /actuator/motor     "0"
put /actuator/heater    "0"
put /actuator/pump      "1"

# ── Device metadata ──
put /device '{"manufacturer":"OIDA-Test","model":"libcoap-ICS-v1","serial":"SN-LC-2024-0042","firmware":"4.3.1-libcoap","hw_rev":"B2","uptime":86400}'
put /device/name        "Water Treatment PLC-03"
put /device/location    "Building A, Floor 2, Panel 7"

# ── Configuration ──
put /config '{"device_name":"libcoap-ICS","reporting_interval":30,"threshold_high":28.0,"threshold_low":18.0,"alarm_enabled":true}'
put /config/network     '{"ip":"192.168.1.42","mask":"255.255.255.0","gw":"192.168.1.1","dns":"8.8.8.8"}'
put /config/modbus      '{"enabled":true,"unit_id":1,"baud":9600,"parity":"none"}'

# ── Firmware ──
put /firmware/version   "4.3.1-libcoap"
put /firmware/status    "idle"
put /firmware/checksum  "a3f2b8c1d4e5f678"

# ── Status / diagnostics ──
put /status             '{"state":"running","uptime_s":86400,"cpu_pct":12,"mem_pct":34}'
put /status/alarms      '{"active":2,"ack":1,"history":["high_temp","low_flow"]}'
put /status/io          '{"di":[1,0,1,1,0,0,1,0],"do":[0,1,0,0],"ai":[23.4,55.1,1013.8],"ao":[50.0]}'

# ── ICS-specific paths ──
put /plc/run-state      "RUN"
put /plc/program        "WaterTreatment_v3.2"
put /plc/cycle-time     "12"
put /plc/error-count    "0"
put /setpoint/temperature "25.0"
put /setpoint/pressure    "6.0"
put /setpoint/flow        "15.0"
put /alarm/high-temp      '{"active":false,"threshold":30.0,"value":23.45}'
put /alarm/low-flow       '{"active":true,"threshold":10.0,"value":12.7}'

# ── LwM2M Device Object /3/0 ──
put /3/0/0  "OIDA-Test"
put /3/0/1  "libcoap-ICS-v1"
put /3/0/2  "SN-LC-2024-0042"
put /3/0/3  "4.3.1-libcoap"
put /3/0/9  "92"
put /3/0/13 "$(date +%s)"

# ── LwM2M Security Object /0/0 ──
if [ -n "$PSK_KEY" ]; then
    put /0/0/2 "0"   # PSK mode
else
    put /0/0/2 "3"   # NoSec mode
fi
put /0/0/0 "coap://localhost:${PORT}"
put /0/0/3 ""

# ── LwM2M Server Object /1/0 ──
put /1/0/1 "3600"
put /1/0/6 "U"
put /1/0/7 "true"

# ── LwM2M Firmware Update Object /5/0 ──
put /5/0/3 "0"
put /5/0/5 "0"

# ── LwM2M Connectivity Monitor /4/0 ──
put /4/0/0 "6"
put /4/0/1 "192.168.1.42"
put /4/0/4 "98"

# ── LwM2M Location Object /6/0 ──
put /6/0/0 "48.2082"
put /6/0/1 "16.3738"
put /6/0/2 "171"

echo "[libcoap] Resources populated. Server PID=$SERVER_PID"

# Verify .well-known/core
echo "[libcoap] .well-known/core:"
$CLIENT -m get "$BASE_URI/.well-known/core" 2>/dev/null || echo "(failed to list)"

echo "[libcoap] Ready. Waiting for connections..."

# Wait for server process
wait $SERVER_PID
