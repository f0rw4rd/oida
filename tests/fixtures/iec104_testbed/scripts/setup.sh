#!/bin/bash
#
# IEC 104 Test Server Setup Script
#
# This script downloads and builds all dependencies, then builds the test server.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIB60870_DIR="$PROJECT_DIR/lib60870"
BUILD_DIR="$PROJECT_DIR/build"

echo "=========================================="
echo "IEC 104 Test Server Setup"
echo "=========================================="
echo ""

# Check for required tools
echo "[1/5] Checking prerequisites..."

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 is required but not installed."
        exit 1
    fi
}

check_command git
check_command cmake
check_command make
check_command gcc

echo "  - All prerequisites found"
echo ""

# Clone lib60870 if not present
echo "[2/5] Setting up lib60870..."

if [ -d "$LIB60870_DIR" ]; then
    echo "  - lib60870 already exists, updating..."
    cd "$LIB60870_DIR"
    git pull || true
else
    echo "  - Cloning lib60870..."
    git clone https://github.com/mz-automation/lib60870.git "$LIB60870_DIR"
fi
echo ""

# Build lib60870
echo "[3/5] Building lib60870..."

LIB60870_BUILD="$LIB60870_DIR/lib60870-C/build"
mkdir -p "$LIB60870_BUILD"
cd "$LIB60870_BUILD"

cmake ..
make -j$(nproc)

echo "  - lib60870 built successfully"
echo ""

# Build test server
echo "[4/5] Building test server..."

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$PROJECT_DIR"
make -j$(nproc)

echo "  - Test server built successfully"
echo ""

# Verify build
echo "[5/5] Verifying build..."

if [ -f "$BUILD_DIR/iec104_test_server" ]; then
    echo "  - Binary: $BUILD_DIR/iec104_test_server"
    echo ""
    echo "=========================================="
    echo "Setup complete!"
    echo "=========================================="
    echo ""
    echo "To run the test server:"
    echo "  cd $BUILD_DIR"
    echo "  ./iec104_test_server [port] [--verbose]"
    echo ""
    echo "Default port: 2404"
    echo ""
else
    echo "ERROR: Build failed - binary not found"
    exit 1
fi
