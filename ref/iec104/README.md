# IEC 60870-5-104 (IEC 104) - Reference Materials

## Protocol Overview

IEC 60870-5-104 is a telecontrol protocol used in electrical engineering and power system automation. It extends IEC 60870-5-101 (serial) to TCP/IP networks. Used extensively in European and Asian power grids for SCADA communication between control centers and substations.

- **Transport**: TCP port 2404
- **APCI (Application Protocol Control Information)**: 6-byte header with start byte (0x68), length, and control fields
- **APDU Types**: I-format (data), S-format (supervisory), U-format (unnumbered control)
- **ASDU (Application Service Data Unit)**: Type ID, cause of transmission, IOA (Information Object Address), data

## Wireshark Dissectors

- **IEC 104**: [packet-iec104.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-iec104.c)
- Also see: [packet-iec104.h](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-iec104.h) (if exists)
- Handles APCI parsing for all three frame types (I/S/U)
- ASDU type identification and information object parsing
- Sequence bit handling (SQ=0 individual addresses, SQ=1 sequential)

### Key dissector details:
- Start byte 0x68 detection and APDU length validation
- Control field parsing for I/S/U formats based on bit patterns
- Type ID dispatch for ~60 ASDU types (M_SP_NA_1 through F_SC_NB_1)
- Cause of transmission (COT) validation
- Information object address (IOA) parsing with 2 or 3 byte variants

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **lib60870** | C | Reference implementation by MZ Automation | [github.com/mz-automation/lib60870](https://github.com/mz-automation/lib60870) |
| **OpenMUC j60870** | Java | Java implementation of IEC 60870-5-104 | [github.com/gythialy/j60870](https://github.com/gythialy/j60870) |
| **iec104-python** | Python | Pure Python IEC 104 library | [github.com/Fraunhofer-FIT-DIEN/iec104-python](https://github.com/Fraunhofer-FIT-DIEN/iec104-python) |
| **Scapy** | Python | IEC 104 contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **QTester104** | C++/Qt | IEC 104 protocol tester | [github.com/riclolsen/qtester104](https://github.com/riclolsen/qtester104) |

## Common Parsing Vulnerabilities

### 1. APCI Length Field Exploitation
- APDU length byte (max 253 per spec) trusted without validation
- Length value 0 or excessively large lengths cause under/over-reads
- Length mismatched with ASDU content size allows buffer overflows

### 2. Control Field Type Confusion
- I-format (bit 0 = 0), S-format (bits 0-1 = 01), U-format (bits 0-1 = 11)
- Parsers that don't properly mask bits can misidentify frame types
- Sequence number overflow (15-bit send/receive sequence numbers, wraps at 32767)

### 3. ASDU Type ID and Object Parsing
- ~60 defined type IDs, each with different information object structures
- Variable-length objects (e.g., packed events, parameter types) require per-type size validation
- SQ (Sequence) bit changes addressing mode - SQ=1 with count > available data is a crash vector
- Number of objects field combined with SQ bit determines total ASDU size

### 4. Time Stamp Handling
- CP56Time2a (7-byte timestamps) can contain invalid dates
- CP24Time2a (3-byte) compact timestamps with millisecond resolution
- Parsers converting to system time types can overflow on malformed timestamps

### 5. Connection State Machine
- STARTDT/STOPDT/TESTFR U-format commands control connection state
- Out-of-sequence state transitions (data before STARTDT ACT) cause undefined behavior
- T1/T2/T3 timeout handling race conditions

### 6. Cause of Transmission (COT) Validation
- COT values 1-47 defined, but many implementations don't reject unknown values
- Negative acknowledgment (COT 44-47) handling differs between implementations

## Notable Research

- **"Security Analysis of IEC 60870-5-104"** - Multiple academic papers on protocol weaknesses
- **CISA ICS Advisories** - Numerous advisories for IEC 104 implementations in RTUs and gateways
- **"Attacking IEC 60870-5-104 SCADA Systems"** - Thomas Brandstetter (DEFCON/BlackHat presentations)

## Fuzzing Tools

- [EPF (Evolutionary Protocol Fuzzer)](https://github.com/fkie-cad/epf) -- Coverage-guided greybox network protocol fuzzer by Fraunhofer FKIE with a built-in cs104_server_no_threads example for IEC 104 fuzzing
- [Aegis Fuzzer](https://www.automatak.com/aegis/) -- Smart fuzzing framework with IEC 104 protocol support (in addition to DNP3 and Modbus)
- [Fuzzowski](https://github.com/nccgroup/fuzzowski) -- Network protocol fuzzer (BooFuzz fork) with IEC 104 support; launch via `python -m fuzzowski <target> 2404 -p tcp -f iec104`
- [ICPFuzzer](https://www.researchgate.net/publication/366456836_Fuzzing_Framework_for_IEC_60870-5-104_Protocol) -- Black-box fuzzing system for IEC 104 that automatically executes testing and reveals crash-inducing inputs; uses BooFuzz with parallel test instances via load balancing

## Attack Surface Notes

- **Most dangerous ASDU types**: Command types (C_SC_NA_1 single command through C_SE_TC_1 set-point with time tag) are the primary control plane; malformed command ASDUs with invalid IOA ranges or SQ bit manipulation are the highest-risk targets
- **APCI length byte**: Maximum 253 per spec, but many implementations do not enforce this upper bound. Values of 0, 1-5 (too small for any valid APDU), or >253 are immediate crash vectors
- **SQ bit + number of objects**: When SQ=1 (sequential addressing), the total ASDU size is computed from `number_of_objects * type_specific_size + 3-byte IOA`. Integer overflow in this calculation or mismatch with APDU length causes buffer over-reads
- **Connection state machine**: Sending I-format frames before STARTDT_ACT confirmation, or mixing U-format types (TESTFR during STOPDT), triggers undefined behavior in many implementations
- **Siemens EN100 module**: Repeatedly vulnerable on UDP port 50000 (CVE-2015-5374, CVE-2019-19279) -- even after patches, new crash vectors found. This module handles IEC 104, DNP3, and other protocols
- **Hitachi Energy RTU500**: Recurring buffer overflows in IEC 104 parsing (CVE-2022-2502, CVE-2023-6711), especially in the IEC 62351-5 authentication layer that adds complex parsing requirements
- **IEC 62351-5 secure authentication**: Adds TLS and authentication to IEC 104, but the added parsing complexity creates new buffer overflow opportunities that are rarely fuzz-tested by vendors
