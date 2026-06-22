#!/bin/bash
# HTTP/2 nghttpd startup script with frame-level logging
# Wraps nghttpd with verbose output and structured logging

set -e

CERT_FILE="${CERT_FILE:-/app/certs/server.crt}"
KEY_FILE="${KEY_FILE:-/app/certs/server.key}"
DOC_ROOT="${DOC_ROOT:-/app/www}"
TLS_PORT="${TLS_PORT:-8443}"
H2C_PORT="${H2C_PORT:-8080}"
LOG_DIR="${LOG_DIR:-/var/log/http2}"

# Build nghttpd arguments
NGHTTPD_ARGS=""

if [ "${HTTP2_VERBOSE:-true}" = "true" ]; then
    NGHTTPD_ARGS="$NGHTTPD_ARGS -v"
fi

if [ "${HTTP2_HEXDUMP:-false}" = "true" ]; then
    NGHTTPD_ARGS="$NGHTTPD_ARGS --hexdump"
fi

# Create log directory
mkdir -p "$LOG_DIR"

echo "=== HTTP/2 nghttpd Server ==="
echo "TLS Port: $TLS_PORT"
echo "H2C Port: $H2C_PORT"
echo "Document Root: $DOC_ROOT"
echo "Verbose: ${HTTP2_VERBOSE:-true}"
echo "Hexdump: ${HTTP2_HEXDUMP:-false}"
echo "Log Directory: $LOG_DIR"
echo "============================"

# Function to parse nghttpd verbose output to JSON
parse_frames() {
    local log_file="$LOG_DIR/nghttpd_frames.jsonl"
    while IFS= read -r line; do
        # Echo original line
        echo "$line"

        # Parse frame events
        if [[ "$line" =~ \[([0-9.]+)\]\ (recv|send)\ ([A-Z_]+)\ frame\ \<length=([0-9]+),\ flags=0x([0-9a-f]+),\ stream_id=([0-9]+)\> ]]; then
            timestamp="${BASH_REMATCH[1]}"
            direction="${BASH_REMATCH[2]}"
            frame_type="${BASH_REMATCH[3]}"
            length="${BASH_REMATCH[4]}"
            flags="${BASH_REMATCH[5]}"
            stream_id="${BASH_REMATCH[6]}"

            # Write JSON event
            echo "{\"timestamp\":\"$(date -Iseconds)\",\"offset\":\"$timestamp\",\"direction\":\"$direction\",\"frame_type\":\"$frame_type\",\"length\":$length,\"flags\":\"0x$flags\",\"stream_id\":$stream_id}" >> "$log_file"
        fi
    done
}

# Start TLS server in background
echo "Starting TLS server on port $TLS_PORT..."
nghttpd $NGHTTPD_ARGS \
    --cert="$CERT_FILE" \
    --key="$KEY_FILE" \
    "$TLS_PORT" "$DOC_ROOT" 2>&1 | parse_frames &
TLS_PID=$!

# Start cleartext (h2c) server in background
echo "Starting H2C server on port $H2C_PORT..."
nghttpd $NGHTTPD_ARGS \
    --no-tls \
    "$H2C_PORT" "$DOC_ROOT" 2>&1 | parse_frames &
H2C_PID=$!

echo "nghttpd servers started (TLS PID: $TLS_PID, H2C PID: $H2C_PID)"

# Handle shutdown
cleanup() {
    echo "Shutting down nghttpd servers..."
    kill $TLS_PID $H2C_PID 2>/dev/null || true
    wait
    echo "Shutdown complete."
}
trap cleanup SIGTERM SIGINT

# Wait for either process to exit
wait -n
exit_code=$?

echo "A server process exited with code $exit_code"
cleanup
exit $exit_code
