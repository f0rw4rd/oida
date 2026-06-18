# MMS (Manufacturing Message Specification) / IEC 61850 - Reference Materials

## Protocol Overview

MMS (ISO 9506) is the messaging protocol underlying IEC 61850, the international standard for communication in electrical substations. MMS provides services for reading/writing variables, controlling devices, reporting events, and file transfer. In IEC 61850, MMS maps to ACSI (Abstract Communication Service Interface) services.

- **Transport**: TCP port 102 (ISO-TSAP over TPKT/COTP), also GOOSE/SV over Ethernet
- **Protocol Stack**: TPKT (RFC 1006) -> COTP (ISO 8073) -> Session (ISO 8327) -> Presentation (ISO 8823) -> MMS (ISO 9506)
- **MMS Services**: Initiate, Read, Write, GetNameList, GetVariableAccessAttributes, InformationReport, DefineNamedVariableList, etc.
- **IEC 61850 Mapping**: Logical Devices -> Logical Nodes -> Data Objects -> Data Attributes

## Wireshark Dissectors

- **MMS**: [packet-mms.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mms.c)
- **TPKT**: [packet-tpkt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-tpkt.c)
- **COTP**: [packet-cotp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cotp.c)
- **IEC 61850 GOOSE**: [packet-goose.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-goose.c)
- **IEC 61850 SV (Sampled Values)**: [packet-sv.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-sv.c)

### Key dissector details:
- MMS is ASN.1 BER encoded - all fields are TLV (Tag-Length-Value)
- TPKT header: version (1), reserved (1), length (2)
- COTP: TPDU type dispatch (CR, CC, DT, DR, etc.)
- MMS PDU types: Confirmed Request, Confirmed Response, Unconfirmed, etc.
- IEC 61850 specific: GOOSE uses EtherType 0x88B8, SV uses 0x88BA

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **libiec61850** | C | Complete IEC 61850 MMS/GOOSE/SV implementation | [github.com/mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) |
| **OpenIEC61850** | Java | Java IEC 61850 MMS client/server | [github.com/gythialy/openiec61850](https://github.com/gythialy/openiec61850) |
| **Scapy** | Python | GOOSE contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **libmms** | C | Lightweight MMS library | [github.com/karlp/libmms](https://github.com/karlp/libmms) |
| **rapid61850** | Java | IEC 61850 rapid prototyping tool | [github.com/stevenblair/rapid61850](https://github.com/stevenblair/rapid61850) |

## Common Parsing Vulnerabilities

### 1. ASN.1 BER Encoding Issues
- MMS is entirely ASN.1 BER encoded, making it extremely susceptible to TLV parsing bugs
- Indefinite-length encoding (0x80) requires finding end-of-content octets (0x00 0x00)
- Constructed types with nested indefinite lengths
- Long-form length encoding (multi-byte lengths) with values exceeding 2^31
- Tag class/number combinations outside defined schema

### 2. TPKT/COTP Layer Attacks
- TPKT length field (2 bytes) mismatch with TCP payload
- COTP connection parameters (TPDU size, src/dst reference) with edge values
- COTP segmentation/reassembly with malformed DT TPDU sequences
- Session layer negotiation with unexpected parameter values

### 3. MMS Variable Access
- ObjectName resolution with deeply nested domain/item paths
- VariableAccessSpecification with named vs. addressed variables
- AlternateAccess (array indexing) with out-of-bounds indices
- TypeSpecification for structured types with recursive definitions

### 4. IEC 61850 GOOSE Multicast
- GOOSE packets are Layer 2 (EtherType 0x88B8) with no authentication
- stNum/sqNum manipulation for replay/injection
- GOOSE dataset encoding with mismatched AllData entries
- TAL (Time Allowed to Live) manipulation for timing attacks

### 5. File Transfer Services
- ObtainFile, FileOpen, FileRead, FileClose with path traversal
- File directory listing with excessive entries
- File data blocks with incorrect size indicators

### 6. MMS Initiation
- InitiateRequest/Response negotiate capabilities (version, services, PDU size)
- Negotiated max PDU size then violated in subsequent messages
- Service supported bit string manipulation

## Notable Research

- **"Substation Security: GOOSE Injection Attacks"** - Multiple academic papers
- **"Hacking IEC 61850"** (S4/DEFCON presentations)
- **Fraunhofer SIT research** on IEC 61850 security
- **CISA ICS-CERT advisories** for Siemens SIPROTEC, ABB products
- **Claroty Team82** - Discovered 5 MMS protocol vulnerabilities in TMW and libiec61850 (2024)
- **ENCS** - Critical vulnerabilities in MZ Automation MMS Client (CVE-2024-45969/70/71)

## Fuzzing Tools

- [IEC61850-MMS-Fuzzer](https://github.com/Skill3t/IEC61850-MMS-Fuzzer) -- Mutation-based fuzzer for IEC 61850 MMS server IEDs. Takes recorded network traffic as input, splits into chunks, and mutates fields. Python-based.
- [fkie-cad/61850-fuzzing](https://github.com/fkie-cad/61850-fuzzing) -- Boofuzz-based fuzzing scripts for IEC 61850-8-1 protocols including MMS, GOOSE, and SV. Includes protocol grammar definitions for structured fuzzing.
- [iec61850_mms_scapy](https://github.com/rhelmke/iec61850_mms_scapy) -- Scapy definitions for a subset of IEC 61850-8-1 MMS messages. Useful for crafting and mutating MMS packets programmatically.
- [GooseStalker](https://github.com/cutaway-security/goosestalker) -- Python/Scapy tool to analyze and interact with IEC 61850 GOOSE traffic. Can be used for GOOSE injection and replay attacks.
- [Goose_Replay_Attack](https://github.com/FerdiGul/Goose_Replay_Attack) -- IEC 61850 GOOSE replay/injection attack tool.

## Attack Surface Notes

### Most Dangerous Message Types
- **MMS InitiateRequest/Response** -- First messages exchanged; association setup is where many NULL derefs and type confusion bugs live (CVE-2024-45969)
- **MMS Read/Write** -- Variable access with ASN.1-encoded ObjectNames; deeply nested names trigger parsing bugs
- **MMS FileDirResponse/FileRead** -- File transfer services have led to buffer overflows (CVE-2024-45970) and path traversal
- **MMS IdentifyResponse** -- Stack buffer overflows from unchecked string lengths (CVE-2024-45971)
- **GOOSE InformationReport** -- Layer 2, no authentication, stNum/sqNum injection for relay tripping

### Most Commonly Vulnerable Fields
- **ASN.1 BER length fields** -- The #1 fuzzing target. Every CVE in libiec61850 (2022, 2024) stems from unchecked lengths before memcpy
- **ASN.1 tag bytes** -- Wrong tag class (UNIVERSAL vs CONTEXT-SPECIFIC) causes type confusion (CVE-2022-2971)
- **TPKT length (2 bytes)** -- Mismatch with TCP payload triggers COTP/MMS parser state corruption
- **String fields** -- ObjectNames, domain names, file paths -- lengths not validated before stack buffer copies

### Known Weak Implementations
- **MZ Automation libiec61850** -- Most widely used open-source stack. 4 critical CVEs in 2022 (server), 3 critical CVEs in 2024 (client). Systemic missing bounds checks on ASN.1 decoded data.
- **Triangle MicroWorks TMW IEC 61850** -- Major commercial stack used by Siemens (SICAM/SITIPE). Buffer overflow from missing size check (CVE-2024-34057). Also affected ICCP/TASE.2 library.
- **SISCO MMS-EASE / SNAP Lite** -- Used in Siemens SIPROTEC 5. CPU consumption DoS (CVE-2015-6574).
- **Hitachi Energy IEC 61850 MMS-Server** -- Connection exhaustion DoS (CVE-2022-3353).
