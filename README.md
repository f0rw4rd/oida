# OIDA: Industrial Control Systems Security Testing Framework

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI version](https://badge.fury.io/py/oida.svg)](https://badge.fury.io/py/oida)

A comprehensive security testing framework for Industrial Control Systems (ICS), SCADA, and healthcare protocols. OIDA provides standalone utilities for penetration testing and security assessment of industrial and critical infrastructure networks.

> **⚠️ LEGAL NOTICE**: This is a **defensive security tool** for **AUTHORIZED TESTING ONLY**.
> - You **MUST** have explicit written permission before testing any system
> - Unauthorized use is **illegal** and may result in criminal prosecution
> - See [DISCLAIMER.md](DISCLAIMER.md) for full legal terms and jurisdiction-specific information
> - By using this software, you accept all terms in the [LICENSE](LICENSE)

## What does "OIDA" mean?

**OIDA** (pronounced "oy-da") is Viennese/Austrian German slang - an incredibly versatile exclamation that can express surprise, frustration, acknowledgment, or simply serve as a conversation filler. Think of it as the Austrian equivalent of "dude", "man", or "whoa". When you discover an unauthenticated PLC on the network: *"Oida!"* When Modbus returns all registers readable without auth: *"Oida..."* It captures the mix of excitement and disbelief that comes with ICS security testing.

## 🔧 Supported Protocols

### Industrial Protocols

| Protocol | Description | Default Port | Type |
|----------|-------------|--------------|------|
| **Modbus** | Modbus TCP/RTU industrial protocol | 502 | Network/Serial |
| **OPC UA** | OPC Unified Architecture | 4840 | Network |
| **Siemens S7** | Siemens S7 communication (Snap7) | 102 | Network |
| **IEC 104** | IEC 60870-5-104 telecontrol | 2404 | Network |
| **Beckhoff ADS** | Automation Device Specification | 48898 | Network |
| **CODESYS** | CODESYS PLC runtime | 1217/2455 | Network |
| **EtherNet/IP** | Industrial Ethernet CIP protocol | 44818 | Network |
| **MMS** | IEC 61850 Manufacturing Message Spec | 102 | Network |
| **DNP3** | Distributed Network Protocol | 20000 | Network |
| **TASE.2** | ICCP/TASE.2 energy protocol | 102 | Network |
| **EtherCAT** | Ethernet Control Automation Technology | - | Raw Socket |
| **PROFINET** | PROFINET DCP discovery | - | Raw Socket |
| **HART-IP** | Highway Addressable Remote Transducer | 5094 | Network |
| **BACnet** | Building Automation and Control | 47808 | Network |
| **KNX/EIB** | Building automation protocol | 3671 | Network |
| **MQTT** | Message Queuing Telemetry Transport | 1883 | Network |

### Healthcare Protocols

| Protocol | Description | Default Port | Type |
|----------|-------------|--------------|------|
| **HL7** | Health Level 7 messaging | 2575 | Network |
| **DICOM** | Medical imaging protocol | 104 | Network |
| **ASTM** | Clinical laboratory protocol | 1234 | Network |

### Discovery

| Protocol | Description | Type |
|----------|-------------|------|
| **Discovery** | Multi-protocol network discovery | Broadcast |

## 🚀 Quick Start

### Installation

```bash
# Install core framework
pip install oida

# Install with all protocol dependencies
pip install oida[all]

# Install specific protocols
pip install oida[modbus,opcua,ethercat]

# Development installation
pip install -e .[dev,all]
```

### Basic Usage

```bash
# Simple syntax: oida <protocol> <target> [options]
oida modbus 192.168.1.100                        # Single target
oida opcua opc.tcp://192.168.1.100:4840          # OPC UA server
oida s7 192.168.1.10 --rack 0 --slot 2           # Siemens S7

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
oida iec104 192.168.1.100 --common-address 1
oida bacnet 192.168.1.255 --broadcast
```

## 📋 Core Features

### Security Testing Capabilities

- **Protocol Discovery**: Enumerate available services and endpoints
- **Authentication Testing**: Test for weak credentials and authentication bypass
- **Access Control Analysis**: Identify readable/writable registers and nodes
- **Vulnerability Assessment**: Built-in security analysis and reporting
- **Certificate Analysis**: SSL/TLS and OPC UA certificate validation
- **Configuration Analysis**: Deep inspection of device configurations

### Scanning Modes

- **Discovery**: Enumerate devices, endpoints, and basic information
- **Security**: Focus on security vulnerabilities and misconfigurations
- **Interactive**: Interactive command-line mode for manual testing
- **Comprehensive**: Deep analysis combining discovery and security assessment

### Export Formats

- **Console**: Human-readable colored output
- **JSON**: Structured data for programmatic analysis
- **CSV**: Tabular data for spreadsheet analysis
- **XML**: Hierarchical data representation

## 🛠️ Protocol-Specific Features

### Modbus
- Unit ID discovery and enumeration
- Register scanning (coils, discrete inputs, holding registers, input registers)
- Function code testing and validation
- Read/write access testing with safety controls
- Serial (RTU) and TCP support
- Device identification and fingerprinting

### OPC UA
- Endpoint discovery and security policy analysis
- Authentication method testing (Anonymous, Username, Certificate)
- Address space exploration and mapping
- Node attribute reading and monitoring
- Subscription capabilities testing
- Certificate-based security assessment
- Server capability enumeration

### EtherCAT
- Slave device discovery and enumeration
- EEPROM data extraction and analysis
- SDO (Service Data Object) information gathering
- Process data analysis and monitoring
- Network topology mapping
- Vendor-specific extensions support

### IEC 104
- Information Object Address (IOA) discovery
- ASDU address enumeration
- General interrogation capabilities
- Command execution testing (with safety controls)
- Data point analysis and monitoring
- Protocol conformance testing

### Beckhoff ADS
- Symbol table enumeration and analysis
- Variable read/write testing
- AMS routing analysis
- Memory access testing (read-only by default)
- Device information gathering
- TwinCAT integration testing

### KNX/EIB
- Group address discovery
- Device scanning and enumeration
- Bus topology analysis
- Communication testing
- Security policy assessment

### EtherNet/IP
- Device discovery via Common Industrial Protocol (CIP)
- Assembly object analysis
- Connection manager testing
- Identity object enumeration
- Explicit messaging capabilities

### MMS (IEC 61850)
- Logical device enumeration
- Data object discovery
- Report control block analysis
- GOOSE message monitoring
- Server capability assessment

## 🔒 Security & Safety Features

### Built-in Security Analysis
- Protocol-specific vulnerability checks
- Default credential detection
- Encryption capability assessment
- Access control evaluation
- Security policy analysis
- Certificate validation

### Safety Mechanisms
- **Read-only mode by default** - Prevents accidental writes
- Confirmation prompts for potentially dangerous operations
- Comprehensive logging and audit trails
- Error handling and graceful recovery
- Connection timeouts and rate limiting

## 📚 Usage Examples

### Modbus Scanning
```bash
# Basic scan
oida modbus 192.168.1.100

# Full register enumeration with output
oida modbus 192.168.1.100 \
  --unit-id 1 \
  --scan-range 0-1000 \
  -o modbus_results --format json

# Scan network range
oida modbus 192.168.1.0/24 -t 20 -o network_scan
```

### OPC UA Security Assessment
```bash
# Browse server anonymously
oida opcua opc.tcp://192.168.1.100:4840 --browse

# Deep node enumeration
oida opcua opc.tcp://192.168.1.100:4840 \
  --browse --max-depth 5 \
  -o opcua_results --format json
```

### Siemens S7 Scanning
```bash
# Scan S7-300/400
oida s7 192.168.1.10 --rack 0 --slot 2

# Scan S7-1200/1500
oida s7 192.168.1.10 --rack 0 --slot 1
```

### Healthcare Protocols
```bash
# HL7 server enumeration
oida hl7 192.168.1.50 --port 2575

# DICOM service discovery
oida dicom 192.168.1.51 --port 104
```

### Building Automation
```bash
# BACnet device discovery
oida bacnet 192.168.1.255 --broadcast

# KNX network scan
oida knx 192.168.1.100
```

## 🐍 Python API

## Funding

This research received no external funding.

## Conflicts of Interest

The authors declare no conflict of interest.


## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)
