# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OIDA is an Industrial Control Systems (ICS) security testing framework that provides standalone utilities for penetration testing industrial networks. This is a **defensive security tool** designed for authorized security testing only.

## Key Commands

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/unit                                          # Unit tests only
pytest tests/integration                                   # Integration tests only
pytest tests/integration/common/test_cli_integration.py    # CLI integration tests
pytest tests/integration/pcap                              # PCAP listener tests
pytest tests/unit/test_modbus_scanner.py                   # Specific test module
```

### Development Setup
```bash
# Install in development mode with all dependencies
pip install -e .[dev,all]

# Install specific protocol dependencies
pip install -e .[modbus,opcua,ethercat,iec104,ads,knx]

# Install development tools only
pip install -e .[dev]
```

### Code Quality
```bash
# Format code (ruff, 100 char line length)
ruff format src/oida/ tests/

# Lint (with auto-fix)
ruff check --fix src/oida/ tests/

# Type checking
mypy src/oida/
```

### Mock Servers (for testing)
```bash
# Manage mock ICS services (Docker-based) via services.py
python services.py up [core|cve|all|<group>]   # Bring up mocks
python services.py status                       # Show which services are running/healthy
python services.py logs [service...]            # Follow container logs
python services.py down                         # Stop services
python services.py list                         # Show available service groups
python services.py ports                        # Show port mappings
```

Mock services provide safe targets for testing:
- Modbus (port 502), OPC UA (4840), IEC 104 (2404)
- ADS (48898), MMS (102), EtherNet/IP (44818)

### Application Usage
```bash
# Basic scans
oida modbus 192.168.1.100                        # Single target
oida opcua opc.tcp://192.168.1.100:4840          # OPC UA

# Multiple targets with threading
oida modbus 192.168.1.0/24 -t 20                 # CIDR notation
oida modbus 192.168.1.1-254 -t 10                # IP range
oida modbus targets.txt                          # From file

# Output options
oida modbus 192.168.1.100 -o results --format json
oida modbus 192.168.1.100 -o results --format all  # json, csv, xml

# Verbosity and debugging
oida modbus 192.168.1.100 -v                     # Verbose
oida modbus 192.168.1.100 -vvv --debug           # Maximum debug

# Protocol-specific options
oida modbus 192.168.1.100 --unit-id 1 --scan-range 0-100
oida opcua opc.tcp://host:4840 --browse --max-depth 3
oida ads 192.168.1.100 --target-ams 5.80.192.37.1.1
```

## Architecture

### Core Structure
- **src/oida/cli.py**: Main CLI entry point with argparse-based command structure
- **src/oida/connection.py**: NXC-style base class for callable protocols
- **src/oida/loader.py**: Dynamic protocol discovery and class loading
- **src/oida/targets.py**: Target parsing (CIDR, IP ranges, hostnames, files)
- **src/oida/protocols/**: Protocol implementations with optional `proto_args.py` submodules
- **src/oida/utils/base_scanner.py**: Abstract base class for traditional scanner pattern

### Protocol Scanner Architecture

The framework uses a **two-layer design**:

**Layer 1 - Scanner Classes** (traditional library usage):
- Inherit from `BaseScanner`, `NetworkScanner`, or `SerialScanner`
- Explicit `run_scan()` calls required
- Example: `ModbusScanner`, `OPCUAScanner`

**Layer 2 - NXC-Style Callable Classes** (auto-execute on instantiation):
- Inherit from `NetworkConnection` or `SerialConnection` in `connection.py`
- Scanning triggers automatically via `proto_flow()` in `__init__`
- Used by CLI and framework integrations
- Example: `modbus(args, db, host)` executes scan immediately

**BaseScanner Required Methods:**
- `get_protocol_name()`: Protocol identification
- `get_default_port()`: Default network port
- `check_dependencies()`: Verify required libraries
- `connect()`: Establish protocol connection
- `disconnect()`: Clean connection teardown
- `discover()`: Basic protocol discovery
- `run_scan()`: Main scanning logic

### Supported protocols (25 total)

Current registered set (run `oida` with no args for the live list, or
`python -c "from oida.loader import ProtocolLoader; print(sorted(ProtocolLoader('src/oida/protocols').get_protocols()))"`):

- **OT / industrial:** modbus, opcua, snap7 (s7), iec104, ads, ethernetip, dnp3,
  mms, tase2, goose, ethercat, profinet, hart, knx, bacnet, can
- **IoT / application:** mqtt, coap, ocpp, snmp
- **Healthcare:** hl7, fhir, dicom, astm
- **Discovery / passive:** discovery, pcap (passive listener pipeline,
  109 listeners)

LLDP, CDP, BBMD, mDNS, SSDP, CODESYS etc. live as sub-features under
`discovery` and `pcap`, not as top-level protocols.

### Key Utilities
- **src/oida/utils/base_scanner.py**: Base scanner class with NetworkScanner/SerialScanner variants
- **src/oida/utils/ics_logger.py**: NXC-style logging, legacy log() facade, debug utilities
- **src/oida/utils/cli.py**: Standalone CLI argument parser and run() dispatcher
- **src/oida/utils/protocol_registry.py**: Decorator-based protocol registration system
- **src/oida/utils/protocol_helpers.py**: ConnectionHelper, SecurityAnalyzer, ProtocolParser
- **src/oida/utils/common_types.py**: Data classes (DeviceInfo, ScanResults) and enums
- **src/oida/utils/exceptions.py**: Protocol-specific exception hierarchy
- **src/oida/utils/export_utils.py**: Output formatting (JSON, CSV, XML, console)

### Configuration and Data
- **src/oida/configs/**: YAML configuration files for complex scanning scenarios
- **src/oida/data/**: Protocol-specific data files (JSON, CSV)

## Testing Framework

The project uses a comprehensive test suite (25+ test files) with:
- **Unit tests**: Core functionality and protocol scanners
- **Integration tests**: End-to-end protocol testing with mock servers
- **CLI tests**: NXC-style CLI integration tests
- **Performance tests**: Load and timing analysis

Key test files:
- `test_cli_integration.py`: CLI command testing (NXC-style)
- `test_modbus_scanner.py`, `test_opcua_scanner.py`, etc.: Protocol-specific tests
- `test_standalone_types.py`: Core data types
- `test_security_analysis.py`: Security assessment features
- `test_integration.py`: Cross-component integration
- `test_mock_servers.py`: Mock server interactions

## Important Development Notes

### Protocol dependencies

Optional extras are declared in `pyproject.toml`. `pyproject.toml` is the
source of truth — do not edit version pins in this file. Install with:

```bash
pip install -e .[<extra>]    # one extra (e.g. modbus)
pip install -e .[all]        # every protocol
pip install -e .[dev,all]    # protocols + dev tooling
```

Notable extras: `modbus`, `opcua`, `iec104`, `snap7`, `ads`, `ethernetip`,
`dnp3`, `mms`, `tase2`, `goose`, `ethercat`, `profinet`, `hart`, `knx`,
`bacnet`, `can`, `mqtt`, `coap`, `ocpp`, `snmp`, `hl7`, `fhir`, `dicom`,
`discovery`, `pcap`, `fuzz`.

### Security Considerations
- This is a **defensive security tool** - all protocols default to read-only mode
- Requires explicit confirmation for potentially dangerous operations
- Comprehensive logging and audit trails are maintained
- Built-in safety mechanisms prevent accidental system disruption

### Code standards
- Python 3.10+
- Type hints where practical; mypy runs informationally (not a CI gate).
- Ruff formatting and linting (100 character line length).
- All scanners inherit from `BaseScanner` (Layer 1) and/or `NetworkConnection`/
  `SerialConnection` (Layer 2). See `docs/ARCHITECTURE.md` for the facade pattern.
- Protocol CLI arguments live in `src/oida/protocols/{name}/proto_args.py`.
- See `STYLE_GUIDE.md` for detailed coding standards.

### Pre-commit Hooks
- **pre-commit**: `ruff check --fix` (lint) + `ruff format` (format)
- **pre-push**: `vulture` (dead code detection, min-confidence 80) + `mypy` (type check, informational — prints summary but does not block)
- **commit-msg**: blocks `Co-Authored-By` lines mentioning Claude/Anthropic — do NOT add AI co-author trailers to commit messages