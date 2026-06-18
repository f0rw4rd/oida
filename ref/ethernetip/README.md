# EtherNet/IP (CIP over Ethernet) - Reference Materials

## Protocol Overview

EtherNet/IP (Ethernet Industrial Protocol) uses CIP (Common Industrial Protocol) over standard Ethernet. It is the leading industrial Ethernet protocol in North America, managed by ODVA. Used in Rockwell Automation/Allen-Bradley PLCs, I/O modules, drives, and third-party devices.

- **Transport**: TCP port 44818 (explicit messaging), UDP port 2222 (implicit/IO messaging)
- **Encapsulation Layer**: EtherNet/IP encapsulation header with command codes
- **CIP Layer**: Service codes, class/instance/attribute path segments
- **Common Commands**: RegisterSession, UnregisterSession, SendRRData, SendUnitData, ListIdentity, ListServices

## Wireshark Dissectors

- **EtherNet/IP**: [packet-enip.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-enip.c) - Encapsulation layer
- **CIP**: [packet-cip.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cip.c) - Common Industrial Protocol
- **CIP Safety**: [packet-cipsafety.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cipsafety.c)
- **CIP Motion**: [packet-cipmotion.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cipmotion.c)

### Key dissector details:
- Encapsulation header: command (2), length (2), session handle (4), status (4), context (8), options (4)
- CPF (Common Packet Format) item parsing with type ID and length
- EPATH (encoded path) segment parsing: logical, data, network segments
- CIP service dispatch for standard objects (Identity, Message Router, Connection Manager)

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **pycomm3** | Python | Allen-Bradley PLC communication (CIP/EtherNet/IP) | [github.com/ottowayi/pycomm3](https://github.com/ottowayi/pycomm3) |
| **cpppo** | Python | CIP/EtherNet/IP protocol implementation | [github.com/pjkundert/cpppo](https://github.com/pjkundert/cpppo) |
| **EIPScanner** | C++ | EtherNet/IP scanner library | [github.com/nimbuscontrols/EIPScanner](https://github.com/nimbuscontrols/EIPScanner) |
| **Scapy** | Python | EtherNet/IP contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **OpENer** | C | Open-source EtherNet/IP adapter (ODVA reference) | [github.com/EIPStackGroup/OpENer](https://github.com/EIPStackGroup/OpENer) |
| **node-ethernet-ip** | JavaScript | EtherNet/IP client for Node.js | [github.com/cmseaton42/node-ethernet-ip](https://github.com/cmseaton42/node-ethernet-ip) |

## Common Parsing Vulnerabilities

### 1. Encapsulation Length Field
- Length field in encapsulation header indicates size of command-specific data
- Mismatch between stated length and TCP payload causes over/under-reads
- Zero-length encapsulation with non-empty commands

### 2. EPATH (Encoded Path) Parsing
- Segment types: logical (class/instance/attribute), data, network
- Padded vs. unpadded path segments based on segment type
- Path length in words (2 bytes) but content can be 1-byte or multi-byte segments
- Extended logical segments with variable sizes
- Deeply nested path segments can exhaust parser stack

### 3. Common Packet Format (CPF) Items
- Item count followed by type-ID + length pairs
- Null address items, connected/unconnected data items, sockaddr items
- Sequence count items in connected messaging
- Type ID values outside known range trigger undefined behavior

### 4. Session Management
- Session handle returned by RegisterSession used for all subsequent requests
- Handle validation varies - some accept any handle value
- UnregisterSession with invalid handle may cause UAF

### 5. Forward Open / Large Forward Open
- Connection establishment with complex parameter encoding
- Connection path routing through backplane/port segments
- T->O and O->T connection parameters with RPI, size, priority
- Large Forward Open extends size fields from 16-bit to 32-bit

### 6. CIP Service-Specific Issues
- Get_Attribute_All/Set_Attribute_All with malformed attribute data
- Multiple Service Packet wrapping multiple CIP services in one request
- CIP data type encoding (BOOL, INT, DINT, REAL, STRING, STRUCT)

## Notable Research

- **Claroty Team82** - Extensive EtherNet/IP and CIP vulnerability research
- **"Attacking CIP" presentations** - Various security conference talks
- **CISA ICS-CERT** - Rockwell Automation advisories (largest EtherNet/IP vendor)
- **"EtherNet/IP Cybersecurity"** - ODVA security specifications

## Fuzzing Tools

- [OpENer (with AFL)](https://github.com/EIPStackGroup/OpENer) -- The ODVA reference open-source EtherNet/IP adapter stack includes AFL fuzzing support. Multiple CVEs (CVE-2020-13556, CVE-2021-27478, CVE-2021-27482) were found by fuzzing this stack.
- [Fuzzowski](https://github.com/nccgroup/fuzzowski) -- Network protocol fuzzer (BooFuzz fork) with EtherNet/IP support for fuzzing encapsulation layer commands
- [Scapy EtherNet/IP dissector](https://github.com/secdev/scapy) -- Python library with ENIP/CIP protocol support for crafting arbitrary malformed packets; used in DoS exploitation research against Allen-Bradley MicroLogix PLCs
- **Allen-Bradley Fuzz Testing Research** (ACSAC 2017 workshop) -- Scapy-based custom fuzzer that uncovered unreported DoS vulnerability in Rockwell MicroLogix 1100 EtherNet/IP implementation

## Attack Surface Notes

- **CIP Forward Open / Large Forward Open**: The most complex and vulnerability-rich message type. Connection parameters (RPI, size, priority), connection path routing through backplane/port segments, and the signed-to-unsigned integer conversion in path length are all proven crash vectors (CVE-2021-27478, CVE-2025-11743)
- **CPF (Common Packet Format) item count**: The item count field in CPF structures has caused stack overflows in multiple implementations (CVE-2020-25159 in RTA, CVE-2020-13556 in OpENer). This is the very first parsing step after encapsulation header processing
- **Encapsulation header length field**: Mismatch between stated length and TCP payload is the most common entry point for fuzzing. Zero-length encapsulation with non-empty commands also triggers crashes
- **EPATH segment parsing**: Variable-length path segments with padded vs. unpadded encoding, extended logical segments, and deeply nested paths create complex parsing that frequently has bounds-checking errors
- **Supply chain risk**: RTA 499ES EtherNet/IP stack and OpENer are embedded in many third-party devices. A single vulnerability in these libraries (CVE-2020-25159, CVE-2020-13556) affects numerous vendor products
- **Rockwell ControlLogix**: Communication modules (1756-EN2*/EN3*/EN4*) are the most high-value targets. CVE-2023-3595 demonstrated APT-grade exploitation with firmware persistence and CIP routing for lateral movement. Detection via CIP class 0x342 and 0x351 monitoring
- **Multiple Service Packet**: The wrapping service that contains an offset table pointing to multiple embedded CIP services. Offsets pointing outside the buffer boundary are a known crash vector
- **Session handle state**: Operations with invalid/expired session handles after UnregisterSession can cause use-after-free in some implementations
