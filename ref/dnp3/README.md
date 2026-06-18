# DNP3 (Distributed Network Protocol 3) - Reference Materials

## Protocol Overview

DNP3 is a set of communication protocols used between components in process automation systems, primarily in electric and water utilities. Developed by Westronic (now GE Harris), it is standardized as IEEE 1815. DNP3 operates over TCP (port 20000), UDP, or serial links.

- **Transport**: TCP port 20000 (standard), or serial
- **Architecture**: Three-layer model: Data Link Layer, Transport Function, Application Layer
- **Data Link Layer**: Start bytes (0x0564), length, control, source/destination addresses, CRC-16 per block
- **Application Layer**: Function codes, Internal Indications (IIN), object headers with variation/qualifier

## Wireshark Dissectors

- **DNP3**: [packet-dnp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dnp.c)
- Handles TCP/UDP/Serial transport
- Parses all three DNP3 layers (data link, transport, application)
- Object group/variation parsing with qualifier codes
- CRC verification at data link layer

### Key dissector details:
- Data link frame parsing with 0x0564 start bytes
- Transport segment reassembly (FIR/FIN bits)
- Application layer function code dispatch (0x00-0x83)
- Object header parsing: group, variation, qualifier, range, data
- Unsolicited response handling

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **opendnp3** | C++ | Reference DNP3 implementation (master/outstation) | [github.com/dnp3/opendnp3](https://github.com/dnp3/opendnp3) |
| **dnp3-simulator** | Java | DNP3 master/outstation simulator | [github.com/automatak/dnp3-simulator](https://github.com/automatak/dnp3-simulator) |
| **Scapy** | Python | DNP3 layer in `scapy.contrib.scada.dnp3` | [github.com/secdev/scapy](https://github.com/secdev/scapy/blob/master/scapy/contrib/scada/) |
| **pydnp3** | Python | Python bindings for opendnp3 | [github.com/ChargePoint/pydnp3](https://github.com/ChargePoint/pydnp3) |
| **dnp3-parser (Rust)** | Rust | DNP3 protocol parser in Rust | [github.com/stepfunc/dnp3](https://github.com/stepfunc/dnp3) |
| **libiec61850** | C | Includes DNP3 parsing capabilities | [github.com/mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) |

## Common Parsing Vulnerabilities

### 1. Data Link Layer CRC Manipulation
- CRC-16 is calculated per 16-byte data block + 2-byte CRC
- Parsers that strip CRCs before validation can process corrupt frames
- Incorrect CRC block boundary calculation with non-standard frame sizes
- CRC bypass when length field indicates 0 data blocks

### 2. Transport Layer Reassembly
- FIR (First) and FIN (Final) bit manipulation allows injection of partial fragments
- Sequence number wrapping (0-63) can confuse reassembly state
- Overlapping fragment attacks when multiple transport segments have conflicting data
- Memory exhaustion from never-completed fragment chains (no FIN bit)

### 3. Application Layer Object Parsing
- Object groups with variable-length data (e.g., strings in Group 110/111) rely on qualifier-specified counts
- Qualifier codes determine how ranges are specified (1-byte start/stop, 2-byte, count-only, etc.)
- Mismatch between qualifier-indicated count and available data causes over-reads
- Prefixed object sizes (with length prefix) can specify sizes larger than remaining data

### 4. Function Code Handling (Outstation/Server-side)
- Direct Operate No Ack (FC 0x06) skips confirmation state validation on the outstation
- Write requests (FC 0x02) with unexpected object types cause parsing confusion
- File transfer function codes (0x19-0x1E) have complex sub-protocols within DNP3
- Authentication function codes (Secure Authentication v5) add significant parsing complexity
- Cold/Warm Restart (FC 0x0D/0x0E) handling varies widely across implementations

### 5. Multi-Fragment Request Processing (Outstation/Server-side)
- Application-layer requests can span multiple transport segments
- Incorrect reassembly buffer management leads to heap overflows
- Object headers spanning fragment boundaries
- Outstations must parse and validate multi-fragment write/select/operate sequences

### 6. Broadcast and Addressing
- Broadcast addresses (0xFFFC-0xFFFE) may bypass access controls
- Source address spoofing in data link layer (16-bit addresses)

## Notable Research

- **"A Taxonomy of Attacks and a Survey of Defence Mechanisms for DNP3"** - Comprehensive attack taxonomy
- **Adam Crain & Chris Sistrunk (Project Robus)** - Systematic DNP3 fuzzing that found vulnerabilities in 20+ implementations
- **Digital Bond's Basecamp** - Early ICS protocol security research including DNP3
- **"Riding the Lightning: Electric Grid Vulnerabilities"** (DEF CON presentations)
- **CISA DNP3 Protocol Analysis** - Multiple ICS-CERT advisories on DNP3 parsing flaws

## Fuzzing Tools

- [Aegis Fuzzer](https://www.automatak.com/aegis/) -- Smart fuzzing framework by Automatak (creators of opendnp3) with targeted test cases for DNP3 link, transport, and application layers; the tool that powered Project Robus and found vulnerabilities in 20+ DNP3 products
- [DNP3Crafter](https://github.com/ITI/ICS-Security-Tools/tree/master/protocols) -- Simple Python script using sockets to send precalculated DNP3 packets over TCP for targeted testing
- [AFLNET](https://github.com/aflnet/aflnet) -- Network-aware fuzzer built on AFL that can be configured for stateful DNP3 fuzzing with transport layer reassembly
- [LangSec DNP3 Parser/Proxy](http://langsec.org/dnp3/) -- Hammer-toolkit based validating parser/proxy for DNP3 that acts as an exhaustive inspection protocol-specific firewall; demonstrates the LangSec approach to DNP3 security

## Attack Surface Notes

- **Most dangerous function codes (outstation-side)**: Direct Operate (FC 0x03), Direct Operate No Ack (FC 0x06, skips confirmation), Write (FC 0x02), File Transfer operations (FC 0x19-0x1E), Cold/Warm Restart (FC 0x0D/0x0E)
- **Richest attack surface**: Application layer object header parsing -- variable-length objects with qualifier codes determine range encoding (1-byte, 2-byte, count-only), and mismatch between qualifier-indicated count and available data is the most common crash vector across all implementations
- **Transport layer reassembly**: FIR/FIN bit manipulation, sequence number wrapping (0-63), and never-completed fragment chains (memory exhaustion) are the second most productive fuzzing target
- **CRC block boundaries**: Data link layer CRC every 16 bytes -- malformed block boundaries when length field indicates non-standard frame sizes confuse many parsers
- **Secure Authentication (SA v5)**: Adds HMAC, challenge-response, and key management that dramatically increase parsing complexity and attack surface; rarely tested by vendors
- **Vendor-specific function codes (0x80+)**: Almost never receive security testing; found universally vulnerable by Project Robus
- **Supply chain risk**: Triangle MicroWorks DNP3 libraries are embedded in dozens of third-party products -- a single library vulnerability (CVE-2020-6996) affects the entire ecosystem
