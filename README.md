# OIDA — ICS Security Testing Framework

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI version](https://badge.fury.io/py/oida.svg)](https://badge.fury.io/py/oida)

OIDA is a CLI security-testing framework for industrial control systems, SCADA,
building automation, and healthcare protocols. It packages standalone scanners
for 26 protocols (16 industrial / 4 IoT / 4 healthcare / 2 discovery+passive)
behind one `oida <protocol> <target>` interface, with consistent flag
conventions, export formats, and safety guards on write operations.

> **⚠️ Legal notice.** This is a defensive tool for **authorized testing only**.
> Get explicit written permission before scanning any system you do not own.
> Unauthorized use may constitute a criminal offence in your jurisdiction.
> See [DISCLAIMER.md](DISCLAIMER.md) and [LICENSE](LICENSE).

The name "OIDA" (pronounced *oy-da*) is Viennese German slang — an exclamation
that fits most ICS findings: *"Oida!"* on an unauthenticated PLC, *"Oida..."*
on a Modbus register dump.

## Supported protocols

### Industrial / OT

| Protocol     | Port      | Notes |
| ------------ | --------- | ----- |
| Modbus       | 502       | TCP, RTU, RTU-over-TCP |
| OPC UA       | 4840      | with TLS / userauth / certificate analysis |
| Siemens S7   | 102       | Snap7 |
| IEC 60870-5-104 | 2404   | telecontrol |
| Beckhoff ADS | 48898     | TwinCAT |
| EtherNet/IP  | 44818     | CIP |
| DNP3         | 20000     | SCADA |
| MMS          | 102       | IEC 61850 |
| TASE.2 / ICCP | 102      | IEC 60870-6 |
| GOOSE        | L2        | IEC 61850, raw socket |
| EtherCAT     | L2        | raw socket |
| PROFINET DCP | L2        | raw socket |
| HART-IP      | 5094      | field devices |
| KNX / EIB    | 3671      | building automation |
| BACnet       | 47808     | building automation |
| CAN          | n/a       | SocketCAN / CANopen / UDS / XCP |

### IoT / Application

| Protocol | Port | Notes |
| -------- | ---- | ----- |
| MQTT     | 1883 | with Sparkplug B |
| CoAP     | 5683 | RFC 7252 |
| OCPP     | 9000 | EV charging stations (WebSocket) |
| SNMP     | 161  | v1/v2c/v3 |

### Healthcare

| Protocol | Port  | Notes |
| -------- | ----- | ----- |
| HL7 v2   | 2575  | MLLP |
| FHIR     | 443   | REST API |
| DICOM    | 104   | (11112 common alternative) |
| ASTM     | varies| lab analyzers |

### Discovery / passive

- `oida discovery <target>` — multi-protocol active and passive discovery
  (mDNS, SSDP, LLDP, CDP, BACnet, BBMD, CODESYS, ARP).
- `oida pcap <file.pcap>` — passive listener pipeline over a saved capture
  (109 listeners across ICS, IT, and credential-bearing protocols).

## Quick start

```bash
# Install with all protocol extras
pip install oida[all]

# Or pick the protocols you need
pip install oida[modbus,opcua,iec104]

# Development install (with test deps)
pip install -e .[dev,all]
```

### Basic syntax

```bash
oida <protocol> <target> [options]
```

Targets accept a single IP, hostname, CIDR (`192.168.1.0/24`), range
(`192.168.1.1-254`), or a file with one target per line. Use `-t N` to
control concurrent worker threads.

```bash
oida modbus 192.168.1.100                          # single host
oida modbus 192.168.1.0/24 -t 20                   # subnet
oida modbus targets.txt                            # from file
oida opcua opc.tcp://192.168.1.100:4840            # OPC UA URL
oida s7 192.168.1.10 --rack 0 --slot 2             # Siemens S7-300
```

### Output

```bash
oida modbus 192.168.1.100 -o results --format json
oida modbus 192.168.1.100 -o results --format csv,json   # comma-separated
```

Output formats: `console` (default), `json`, `csv`. XML is recognised by the
flag parser but not yet implemented per-protocol — use JSON.

### Verbosity

```bash
oida modbus 192.168.1.100 -v       # verbose
oida modbus 192.168.1.100 -vv      # more verbose
oida modbus 192.168.1.100 --debug  # full debug
```

## Per-protocol examples

```bash
# Modbus — register scan + identification
oida modbus 192.168.1.100 --unit-id 1 --scan-range 0-1000 -o modbus_scan --format json

# OPC UA — anonymous browse with depth limit
oida opcua opc.tcp://192.168.1.100:4840 --browse --max-depth 5

# Siemens S7 — discovery + SZL enumeration
oida s7 192.168.1.10 --rack 0 --slot 2 -i -L -E

# IEC 104 — common address scan
oida iec104 192.168.1.100 --common-address 1

# Beckhoff ADS — symbol enumeration with explicit target AMS Net ID
oida ads 192.168.1.100 --target-ams 5.80.192.37.1.1

# BACnet — local-broadcast device discovery
oida bacnet 192.168.1.255

# KNX — gateway discovery (multicast)
oida knx 224.0.23.12

# HL7 — connection + version fingerprint
oida hl7 192.168.1.50 --port 2575

# DICOM — service discovery
oida dicom 192.168.1.51

# Passive pcap analysis (all 109 listeners)
oida pcap capture.pcap
```

Each protocol has `--help` with its full flag set, examples, and which
operations require `--confirm` (any write or state-change action).

## Safety

Write operations and state-change operations across all ICS protocols are
gated behind an explicit `--confirm` flag. The defaults are read-only.
Examples that require `--confirm`:

- `oida modbus … --write-coil …`
- `oida dnp3 … --bo-direct 0 --confirm`
- `oida ethercat … --op-state --confirm`
- `oida iec104 … --write-single …`

See [DISCLAIMER.md](DISCLAIMER.md) for the full safety statement.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — class layering and refactor roadmap.
- [docs/new-protocol.md](docs/new-protocol.md) — how to add a new protocol scanner.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution policy (incl. AI usage policy).
- [STYLE_GUIDE.md](STYLE_GUIDE.md) — Python style and naming.
- [RELEASE_READINESS.md](RELEASE_READINESS.md) — known issues snapshot for 1.0.

## Support

If you find this useful, you can support development at
[ko-fi.com/f0rw4rd](https://ko-fi.com/f0rw4rd).
