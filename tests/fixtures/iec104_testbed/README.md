# IEC 60870-5-104 Test Server

A comprehensive test server for developing and testing IEC 104 scanner functionality in OIDA.

## Features

### Supported Data Types (Monitoring)

| Type ID | Name | Description | IOA Range |
|---------|------|-------------|-----------|
| 1 | M_SP_NA_1 | Single point information | 100-119 |
| 3 | M_DP_NA_1 | Double point information | 200-209 |
| 5 | M_ST_NA_1 | Step position information | 300-304 |
| 7 | M_BO_NA_1 | Bitstring of 32 bits | 400-404 |
| 9 | M_ME_NA_1 | Measured value, normalized | 500-519 |
| 11 | M_ME_NB_1 | Measured value, scaled | 600-619 |
| 13 | M_ME_NC_1 | Measured value, short float | 700-719 |
| 15 | M_IT_NA_1 | Integrated totals | 800-809 |

### Supported Commands (Control)

| Type ID | Name | Description | Target IOA |
|---------|------|-------------|------------|
| 45 | C_SC_NA_1 | Single command | 100-119 |
| 46 | C_DC_NA_1 | Double command | 200-209 |
| 47 | C_RC_NA_1 | Regulating step command | 300-304 |
| 48 | C_SE_NA_1 | Set point, normalized | 500-519 |
| 49 | C_SE_NB_1 | Set point, scaled | 600-619 |
| 50 | C_SE_NC_1 | Set point, short float | 700-719 |
| 100 | C_IC_NA_1 | General interrogation | - |
| 101 | C_CI_NA_1 | Counter interrogation | - |
| 102 | C_RD_NA_1 | Read command | Any valid |
| 103 | C_CS_NA_1 | Clock synchronization | - |
| 104 | C_TS_NA_1 | Test command | - |
| 105 | C_RP_NA_1 | Reset process | - |

### File Transfer (Planned)

| IOA | File |
|-----|------|
| 10000 | File Directory |
| 10001 | config.xml |
| 10002 | events.log |
| 10003 | disturbance_001.comtrade |

## Quick Start

### Option 1: Using Setup Script (Recommended)

```bash
cd tests/iec104_testbed
./scripts/setup.sh
./build/iec104_test_server
```

### Option 2: Using Make

```bash
cd tests/iec104_testbed
make setup    # Download and build lib60870
make          # Build test server
make run      # Run server
```

### Option 3: Using CMake

```bash
cd tests/iec104_testbed

# Clone lib60870 first
git clone https://github.com/mz-automation/lib60870.git

# Build lib60870
cd lib60870/lib60870-C
mkdir build && cd build
cmake ..
make
cd ../../..

# Build test server
mkdir build && cd build
cmake ..
make
./iec104_test_server
```

## Usage

```bash
./iec104_test_server [port] [options]

Options:
  -v, --verbose    Enable verbose logging
  -h, --help       Show help message

Examples:
  ./iec104_test_server                  # Default port 2404
  ./iec104_test_server 2405             # Custom port
  ./iec104_test_server 2404 --verbose   # Verbose output
```

## Testing with OIDA

Once the server is running, you can test it with the IEC 104 scanner:

```bash
# Basic scan
oida iec104 127.0.0.1

# Full discovery
oida iec104 127.0.0.1 --scan-mode all --ioa-range 0-1000

# Test commands (caution!)
oida iec104 127.0.0.1 --scan-mode writes
```

## Server Behavior

### Data Simulation

- Values are initialized randomly on startup
- Measured values update every 5 seconds with random drift
- Single points toggle occasionally to simulate events
- Integrated totals increment periodically

### Command Handling

- **Single/Double Commands**: Toggle the corresponding data point
- **Step Commands**: Increment/decrement step position
- **Setpoint Commands**: Update measured value to setpoint
- **Reset Process**: Reinitialize all data values

### Interrogation Response

General interrogation (C_IC_NA_1) returns all data points grouped by type:
1. Single points (M_SP_NA_1)
2. Double points (M_DP_NA_1)
3. Step positions (M_ST_NA_1)
4. Bitstrings (M_BO_NA_1)
5. Measured normalized (M_ME_NA_1)
6. Measured scaled (M_ME_NB_1)
7. Measured float (M_ME_NC_1)
8. Integrated totals (M_IT_NA_1)

## Protocol Configuration

| Parameter | Value |
|-----------|-------|
| Common Address (CA) | 1 |
| Port | 2404 (default) |
| IOA Size | 3 bytes |
| COT Size | 2 bytes |
| Server Mode | Single Redundancy Group |

## Directory Structure

```
iec104_testbed/
├── CMakeLists.txt       # CMake build configuration
├── Makefile             # Alternative Make build
├── README.md            # This file
├── data/                # Test data files
│   ├── config.xml       # Sample configuration
│   ├── events.log       # Sample event log
│   ├── disturbance_001.cfg  # COMTRADE header
│   └── parameters.cfg   # RTU parameters
├── scripts/
│   └── setup.sh         # Automated setup script
└── src/
    └── iec104_test_server.c  # Main server source
```

## Dependencies

- **lib60870** - IEC 60870-5-104 protocol library
  - Repository: https://github.com/mz-automation/lib60870
  - License: GPLv3 / Commercial

## Troubleshooting

### "lib60870 not found"

Run `make setup` or `./scripts/setup.sh` to download and build lib60870.

### "Connection refused"

Ensure the server is running and the port is not blocked:
```bash
netstat -tlnp | grep 2404
```

### "Permission denied" on port 2404

Either run as root or use a port > 1024:
```bash
./iec104_test_server 12404
```

## License

This test server is part of OIDA and is licensed under MIT.
The lib60870 dependency is licensed under GPLv3 or commercial license.
