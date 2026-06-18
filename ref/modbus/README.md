# Modbus (TCP + RTU) - Reference Materials

## Protocol Overview

Modbus is a serial communication protocol originally published by Modicon (now Schneider Electric) in 1979. Modbus TCP encapsulates Modbus frames over TCP/IP (port 502), while Modbus RTU uses serial communication with CRC-16 error checking. It is the most widely deployed industrial protocol worldwide.

- **Modbus TCP**: TCP port 502, MBAP header (7 bytes) + PDU
- **Modbus RTU**: Serial, 1-byte address + PDU + 2-byte CRC16
- **Modbus ASCII**: Serial, ASCII-encoded, less common

## Wireshark Dissectors

- **Modbus TCP**: [packet-mbtcp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mbtcp.c)
- **Modbus RTU (serial)**: [packet-mbtcp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mbtcp.c) (same file handles both TCP and RTU variants)
- The dissector registers as `mbtcp` and `mbudp` for the TCP/UDP variants, and `mbrtu` for the serial variant.

### Key dissector details:
- MBAP header parsing: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
- Function code dispatch table for all standard function codes (1-24, 43)
- Exception response handling (function code | 0x80)
- Reassembly support for Modbus over TCP

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **pymodbus** | Python | Full Modbus TCP/RTU/ASCII client and server | [github.com/pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) |
| **Scapy** | Python | Modbus/TCP layer in `scapy.contrib.modbus` | [github.com/secdev/scapy](https://github.com/secdev/scapy/blob/master/scapy/contrib/modbus.py) |
| **libmodbus** | C | Reference C implementation, widely used | [github.com/stephane/libmodbus](https://github.com/stephane/libmodbus) |
| **modbus-tk** | Python | Lightweight Modbus implementation | [github.com/ljean/modbus-tk](https://github.com/ljean/modbus-tk) |
| **nmodbus** | C# | .NET Modbus library | [github.com/NModbus/NModbus](https://github.com/NModbus/NModbus) |
| **jamod** | Java | Java Modbus library | [github.com/steveohara/j2mod](https://github.com/steveohara/j2mod) |
| **ctmodbus** | Python | Modbus fuzzing/testing tool | [github.com/ControlThingsIO/ctmodbus](https://github.com/ControlThingsIO/ctmodbus) |

## Common Parsing Vulnerabilities

### 1. MBAP Length Field Mismatch
The MBAP header contains a `Length` field indicating the size of the remaining data. Parsers frequently:
- Trust the length field without validation against actual received bytes
- Allow length=0 or excessively large lengths causing buffer over-reads or allocations
- Fail to handle length values that don't match the function code's expected payload size

### 2. Function Code Confusion
- Exception responses (0x80 | FC) not properly handled, leading to negative array indexing or unexpected code paths
- Undocumented/reserved function codes (0x08 diagnostics sub-functions) cause unhandled exceptions
- MEI (Modbus Encapsulated Interface, FC 0x2B) sub-function dispatching is complex and error-prone

### 3. Coil/Register Count vs. Byte Count Discrepancy
- Write Multiple Coils (FC 15) and Write Multiple Registers (FC 16) have both a "quantity" field and a "byte count" field
- Parsers that trust one without cross-validating the other can read/write out of bounds
- quantity * 2 != byte_count is a classic trigger for buffer overflows

### 4. RTU Framing Issues
- CRC calculation on truncated frames
- Inter-frame gap timing detection failures leading to frame concatenation
- Address field (0-247) with broadcast (0) handling inconsistencies

### 5. Integer Overflows in Address Calculations
- Starting address + quantity > 65535 wraps around on 16-bit implementations
- Memory-mapped implementations directly use register addresses as offsets without bounds checking

### 6. Server State and Resource Exhaustion
- Unit ID routing to serial devices can overflow routing tables when gateway servers don't bound-check the Unit ID
- Concurrent transactions with duplicate Transaction IDs cause response buffer confusion on the server
- Servers that allocate per-transaction state without limits are vulnerable to resource exhaustion from rapid connection floods

## Notable Research

- **"Modbus: Tekniska Standarden" by Digital Bond** - Early Modbus security assessment methodology
- **ICS-CERT advisories** - Numerous advisories for Modbus implementations in PLCs
- **AEGIS (Anomaly dEtection for industrial control systems)** - Research on Modbus anomaly detection
- **"The Spear to Break the Security Wall of S7CommPlus"** (also covers Modbus comparisons)

## Fuzzing Tools

- [Modbus-Fuzzer](https://github.com/AlixAbbasi/Modbus-Fuzzer) -- Protocol grammar-based fuzzer supporting 15+ function codes with boundary value testing; uses protocol grammar rather than brute force
- [modbus-fuzz-note](https://github.com/M3m3M4n/modbus-fuzz-note) -- AFLNET-based network-aware fuzzer setup for fuzzing Modbus TCP server implementations
- [ctmodbus](https://github.com/ControlThingsIO/ctmodbus) -- Modbus fuzzing/testing tool by ControlThings for crafting and sending arbitrary Modbus frames
- [ModBusSploit](https://github.com/C4l1b4n/ModBusSploit) -- Python3 framework for Modbus TCP enumeration and exploitation, includes fuzzing capabilities
- [Fuzzowski](https://github.com/nccgroup/fuzzowski) -- Network protocol fuzzer (fork of BooFuzz/Sulley) with Modbus protocol support built-in

## Attack Surface Notes

- **Most dangerous function codes**: FC 15 (Write Multiple Coils), FC 16 (Write Multiple Registers), FC 23 (Read/Write Multiple Registers) -- these have the most complex parsing with both quantity and byte count fields that must be cross-validated
- **Most commonly vulnerable fields**: MBAP Length field (2 bytes, can specify sizes far exceeding actual payload), byte count fields in write operations, starting address + quantity combinations that wrap 16-bit integers
- **Vendor-specific weak spots**: Schneider Modicon controllers have a history of accepting malformed Modbus packets without proper validation on port 502 (CVE-2024-11737, CVE-2024-8938, CVE-2018-7843 series). libmodbus has had recurring buffer overflows in modbus_reply() (CVE-2022-0367, CVE-2024-10918)
- **MEI (FC 0x2B) sub-functions**: Device Identification (sub-function 0x0E) involves parsing variable-length object lists with object ID + length + value encoding -- a rich target for malformed data
- **Gateway/proxy servers**: Modbus gateways that route by Unit ID are vulnerable when Unit ID values exceed internal routing table bounds
