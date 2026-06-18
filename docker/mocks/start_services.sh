#!/bin/bash

# Start script for all mock ICS services
echo "Starting MSF-ICS Mock Services Container..."

# Create log directory
mkdir -p /var/log/msf-ics

# Function to start a service and log output
start_service() {
    local service_name=$1
    local script_path=$2
    local log_file="/var/log/msf-ics/${service_name}.log"
    
    echo "Starting ${service_name}..."
    python3 "${script_path}" > "${log_file}" 2>&1 &
    local pid=$!
    echo "${pid}" > "/var/run/${service_name}.pid"
    echo "${service_name} started with PID ${pid}"
}

# Start all mock services
cd /app/mock_services

echo "=== Starting Mock Industrial Control System Services ==="
echo "Services will be available on the following ports:"
echo "  - Modbus TCP:    502"
echo "  - OPC UA:        4840" 
echo "  - IEC 104:       2404"
echo "  - ADS:           48898"
echo "  - MMS/IEC 61850: 102"
echo "  - EtherNet/IP:   44818"
echo ""

# Start each service in background
start_service "modbus" "modbus_server.py"
sleep 2

start_service "opcua" "opcua_server.py" 
sleep 2

start_service "iec104" "iec104_server_c104.py"
sleep 2

start_service "ads" "ads_server_framework.py"
sleep 2

start_service "mms" "mms_server_framework.py"
sleep 2

start_service "ethernetip" "ethernetip_server.py"
sleep 2

echo ""
echo "=== All services started successfully ==="
echo ""
echo "Service Status:"
for service in modbus opcua iec104 ads mms ethernetip; do
    if [ -f "/var/run/${service}.pid" ]; then
        pid=$(cat "/var/run/${service}.pid")
        if ps -p $pid > /dev/null 2>&1; then
            echo "  ✓ ${service} (PID: ${pid})"
        else
            echo "  ✗ ${service} (failed to start)"
        fi
    else
        echo "  ✗ ${service} (no PID file)"
    fi
done

echo ""
echo "Logs are available in /var/log/msf-ics/"
echo "Container is ready for testing with MSF-ICS scanners"
echo ""

# Function to handle shutdown
shutdown_services() {
    echo ""
    echo "Shutting down services..."
    for service in modbus opcua iec104 ads mms ethernetip; do
        if [ -f "/var/run/${service}.pid" ]; then
            pid=$(cat "/var/run/${service}.pid")
            if ps -p $pid > /dev/null 2>&1; then
                echo "Stopping ${service} (PID: ${pid})"
                kill $pid
                rm -f "/var/run/${service}.pid"
            fi
        fi
    done
    echo "All services stopped."
    exit 0
}

# Handle shutdown signals
trap shutdown_services SIGTERM SIGINT

# Keep the container running and monitor services
while true; do
    # Check if all services are still running
    all_running=true
    for service in modbus opcua iec104 ads mms ethernetip; do
        if [ -f "/var/run/${service}.pid" ]; then
            pid=$(cat "/var/run/${service}.pid")
            if ! ps -p $pid > /dev/null 2>&1; then
                echo "WARNING: ${service} has stopped unexpectedly"
                all_running=false
            fi
        else
            all_running=false
        fi
    done
    
    if [ "$all_running" = false ]; then
        echo "Some services have failed. Check logs for details."
    fi
    
    sleep 30
done