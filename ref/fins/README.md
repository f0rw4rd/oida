# FINS (Factory Interface Network Service) - Reference Materials

## Protocol Overview

FINS is Omron's proprietary protocol for communication with Omron PLCs (CS, CJ, CP, NJ/NX series). It operates over UDP (FINS/UDP), TCP (FINS/TCP), and serial (Host Link). FINS provides memory area read/write, program upload/download, and device control operations.

- **Transport**: UDP port 9600 (FINS/UDP), TCP port 9600 (FINS/TCP with additional header)
- **FINS/TCP Header**: 4-byte magic "FINS" + Length (4) + Command (4) + Error Code (4)
- **FINS Header**: ICF (1), RSV (1), GCT (1), DNA (1), DA1 (1), DA2 (1), SNA (1), SA1 (1), SA2 (1), SID (1)
- **FINS Commands**: Memory Read (0x0101), Memory Write (0x0102), Controller Status Read (0x0601), Run/Stop (0x0401/0x0402)

## Wireshark Dissectors

- **FINS**: [packet-omron-fins.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-omron-fins.c)
- Handles both FINS/TCP and FINS/UDP framing
- FINS header parsing with addressing (DNA/DA1/DA2 destination, SNA/SA1/SA2 source)
- Command-specific response parsing

### Key dissector details:
- FINS/TCP handshake: Node address request/response (cmd 0/1)
- Command code dispatch (MR/MC/AR prefix, 2-byte code)
- Memory area codes with address/bit designator parsing
- End code (response status) interpretation

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **python-omron-fins** | Python | FINS/TCP client library | [github.com](https://github.com) (various implementations) |
| **fins-protocol** | JavaScript | Node.js FINS client | [github.com](https://github.com) |
| **omron-fins** | Python | Python FINS library | [pypi.org/project/omron-fins](https://pypi.org/project/omron-fins/) |
| **Scapy** | Python | No official FINS layer (community contributions) | [github.com/secdev/scapy](https://github.com/secdev/scapy) |

## Common Parsing Vulnerabilities

### 1. FINS/TCP Length Field
- 4-byte length field in FINS/TCP header
- Mismatch between stated length and actual TCP payload
- Length = 0 or extremely large values
- Multiple FINS messages in single TCP segment

### 2. Memory Area Read/Write
- Memory area code (1 byte) + beginning address (3 bytes) + number of items (2 bytes)
- Area code determines address space (DM, CIO, WR, HR, AR, etc.)
- Beginning address + count exceeding area boundaries
- Writing to program areas (EM) allows code injection

### 3. FINS Addressing (DNA/DA1/DA2)
- Network address (DNA), Node address (DA1), Unit address (DA2)
- Gateway forwarding based on DNA creates routing chains
- Node address 0 or broadcast (255) behavior
- Unit address 0 (CPU) vs. other units

### 4. Command-Specific Issues
- Memory Fill (0x0104) with large count and value
- Program Area Write (0x0307) allows arbitrary code upload
- Controller Stop (0x0402) without authentication
- Error Log Read/Clear (0x2101/0x2102) information leakage

### 5. Response Parsing
- End code (2 bytes) indicates success/error
- Response data format varies per command
- Error responses with unexpected data following end code
- Timeout handling when responses are delayed or lost

### 6. No Authentication
- FINS has zero authentication or access control
- Any network-accessible client can read/write PLC memory
- Controller stop/start commands are unauthenticated

## Notable Research

- **"Rogue7" style attacks** on Omron controllers
- **CISA ICS-CERT advisories** for Omron products
- **Positive Technologies** - Omron PLC security research
- **Pipedream/INCONTROLLER** - State-sponsored ICS malware (Chernovite/Russia) that weaponized Omron FINS for PLC manipulation (2022). BadOmen component uses CVE-2022-34151 for initial access then FINS for memory read/write.
- **Dragos** - Analysis of Pipedream runtime behavior and FINS protocol exploitation

## Fuzzing Tools

- [fuzzowski](https://github.com/nccgroup/fuzzowski) -- Network protocol fuzzer by NCC Group. Can be configured for FINS/TCP fuzzing with custom protocol definitions. Supports session-based fuzzing with state tracking.
- [Orange Cyberdefense awesome-industrial-protocols](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/fins.md) -- Security-oriented reference with FINS protocol details, known tools, and vulnerability references.
- No dedicated public FINS fuzzer exists. FINS/TCP can be fuzzed with generic TCP fuzzers (boofuzz, fuzzowski) by defining the FINS/TCP header structure (4-byte magic "FINS" + 4-byte length + 4-byte command + 4-byte error code) followed by the 10-byte FINS header.

## Attack Surface Notes

### Most Dangerous Commands (Function Codes)
- **Memory Write (0x0102)** -- Write arbitrary data to any PLC memory area (DM, CIO, WR, HR, AR, EM). No authentication. Can overwrite process variables, setpoints, and logic flags.
- **Program Area Write (0x0307)** -- Upload arbitrary PLC program code. Enables complete logic replacement -- the most critical FINS command for RCE.
- **Controller Stop (0x0402)** -- Halt PLC execution immediately. No authentication. Direct process disruption.
- **Controller Start (0x0401)** -- Restart PLC after logic modification.
- **Memory Fill (0x0104)** -- Fill memory range with a value. Large count parameter can cause resource issues in parser.
- **Clock Write (0x0702)** -- Set PLC clock. Can disrupt time-based logic and logging.
- **Error Log Clear (0x2102)** -- Erase forensic evidence of manipulation.

### Most Commonly Vulnerable Fields
- **FINS/TCP Length Field (4 bytes)** -- Classic overflow trigger. Zero, very large, or negative-equivalent values cause allocation/parsing issues.
- **Memory Area Code (1 byte)** -- Invalid or vendor-specific area codes trigger undefined behavior. Code + address exceeding area bounds causes over-read.
- **Number of Items (2 bytes)** -- In Memory Read/Write commands, item count exceeding area boundaries or causing very large responses.
- **FINS Header DNA/DA1/DA2** -- Routing fields that forward packets through gateways. Spoofed source addresses and broadcast (255) cause routing loops or reach unintended devices.

### Known Weak Implementations
- **Omron SYSMAC (CS/CJ/CP/NJ/NX)** -- FINS has zero authentication by design across ALL product lines (CVE-2023-27396). This is not a bug but a fundamental protocol weakness. Any FINS-capable tool is effectively an exploit against unprotected Omron PLCs.
- **Omron NJ/NX Series** -- Three CVEs (CVE-2022-34151/33208/33971) exploited by Pipedream/INCONTROLLER malware. Hardcoded credentials provide initial access, then FINS used for PLC manipulation. These controllers are used in critical infrastructure and manufacturing.
- **FINS Header Validation** -- CVE-2019-18269 shows that even the 10-byte FINS header is not fully validated, allowing access to unintended functionality via crafted routing fields.
