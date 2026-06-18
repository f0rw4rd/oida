# SNMP (Simple Network Management Protocol) - Reference Materials

## Protocol Overview

SNMP is the standard protocol for network device management and monitoring. Three versions exist: SNMPv1 (RFC 1157), SNMPv2c (RFC 3416), and SNMPv3 (RFC 3414, with USM security). SNMP uses ASN.1 BER encoding for all message structures.

- **Transport**: UDP port 161 (agent), UDP port 162 (trap receiver)
- **Encoding**: ASN.1 BER (Basic Encoding Rules) throughout
- **SNMPv1/v2c**: Community string authentication (plaintext)
- **SNMPv3**: USM (User-based Security Model) with authentication (HMAC-MD5/SHA) and encryption (DES/AES)
- **PDU Types**: GetRequest, GetNextRequest, GetResponse, SetRequest, GetBulkRequest (v2c+), InformRequest (v2c+), Trap/SNMPv2-Trap

## Wireshark Dissectors

- **SNMP**: [packet-snmp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-snmp.c)
- ASN.1-generated dissector from SNMP MIB definitions
- Full SNMPv1/v2c/v3 support
- USM authentication/encryption handling
- OID resolution against loaded MIBs

### Key dissector details:
- BER SEQUENCE wrapper around entire message
- Version dispatch (0=v1, 1=v2c, 3=v3)
- Community string (v1/v2c) or msgSecurityParameters (v3)
- PDU type dispatch and variable binding list parsing
- OID encoding/decoding (subidentifier encoding)

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **Net-SNMP** | C | Reference SNMP implementation | [github.com/net-snmp/net-snmp](https://github.com/net-snmp/net-snmp) |
| **pysnmp** | Python | Pure Python SNMP library | [github.com/pysnmp/pysnmp](https://github.com/pysnmp/pysnmp) |
| **gosnmp** | Go | Go SNMP library | [github.com/gosnmp/gosnmp](https://github.com/gosnmp/gosnmp) |
| **Scapy** | Python | SNMP layer built-in | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **snmp4j** | Java | Java SNMP library | [snmp4j.org](https://www.snmp4j.org/) |
| **pyasn1** | Python | ASN.1 BER codec (used by pysnmp) | [github.com/pyasn1/pyasn1](https://github.com/pyasn1/pyasn1) |

## Common Parsing Vulnerabilities

### 1. ASN.1 BER Encoding (Primary Attack Surface)
- Tag-Length-Value format vulnerabilities apply to EVERY field
- Indefinite-length encoding (0x80 length byte)
- Multi-byte length encoding with extreme values
- Tag class/number mismatches
- SNMP is a rich target because the entire protocol is ASN.1 BER

### 2. OID (Object Identifier) Encoding
- OID subidentifiers: variable-length encoding (7 bits per byte, MSB continuation)
- First two components packed: first_byte = 40 * first_component + second_component
- Extremely long OIDs (many components)
- OID components with very large values (multi-byte subidentifiers)
- OID encoding overflow on 32-bit systems

### 3. Variable Binding Values
- VarBind list: SEQUENCE of SEQUENCE { OID, value }
- Value can be any ASN.1 type (INTEGER, OCTET STRING, NULL, OID, etc.)
- Type confusion: wrong ASN.1 type for expected MIB object
- Counter64 (SNMPv2c) handling on 32-bit systems
- OCTET STRING with very large or zero length

### 4. SNMPv3 USM Security
- msgAuthoritativeEngineID: variable-length with min/max constraints
- msgAuthoritativeEngineBoots/Time: integer overflow potential
- Authentication: HMAC computation with malformed parameters
- Encryption: scoped PDU decryption with wrong key/IV
- Discovery: engine ID exchange during initial handshake

### 5. Trap/Notification Processing
- SNMPv1 Trap: enterprise OID, generic/specific trap type, timestamp, variable bindings
- SNMPv2 Notification: timestamp OID + notification OID + additional VarBinds
- Trap-directed polling creates timing-based vulnerabilities

### 6. GetBulk Request
- max-repetitions field: large values causing massive response generation
- non-repeaters + max-repetitions combination with edge values
- Amplification: small GetBulk request -> large response

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **snmp-fuzzer** | Python | Random testing (fuzzing) tool for SNMP managers listening for traps | [github.com/LukasRypl/snmp-fuzzer](https://github.com/LukasRypl/snmp-fuzzer) |
| **snmp_fuzzer** | Python | SNMP fuzzer with OID scanning and SNMP SET fuzzing capabilities | [github.com/dark-lbp/snmp_fuzzer](https://github.com/dark-lbp/snmp_fuzzer) |
| **cisco-snmp-rce** | Python | Cisco IOS SNMP RCE PoC exploit for CVE-2017-6736 | [github.com/artkond/cisco-snmp-rce](https://github.com/artkond/cisco-snmp-rce) |
| **Net-SNMP fuzzer** | C | Built-in fuzzing harness (`testing/fuzzing/snmp_api_fuzzer.c`) for libfuzzer/AFL | [github.com/net-snmp/net-snmp](https://github.com/net-snmp/net-snmp/blob/master/testing/fuzzing/snmp_api_fuzzer.c) |
| **PrettyUp/Fuzzer** | Python | Multi-protocol fuzzer demo including SNMP fuzzer component | [github.com/PrettyUp/Fuzzer](https://github.com/PrettyUp/Fuzzer) |
| **Simple SNMP Fuzzer** | Python | Minimal SNMP fuzzer as GitHub Gist | [gist.github.com/nstarke/17a5ff6605c6e66be4e7b985d8e7cd8e](https://gist.github.com/nstarke/17a5ff6605c6e66be4e7b985d8e7cd8e) |

## Attack Surface Notes

### Server-Side (Agent/Trap Receiver) Parsing Targets
- **ASN.1 BER encoding**: Every field in every SNMP packet is ASN.1 BER encoded. The OUSPG PROTOS test suite (2002) found vulnerabilities in nearly every SNMP implementation by systematically fuzzing BER encoding. This remains the primary attack surface.
- **snmptrapd trap processing**: Critical buffer overflow in Net-SNMP snmptrapd (CVE-2025-68615, CVSS 9.8) -- no authentication required, network-accessible on UDP port 162
- **OID subidentifier encoding**: Variable-length encoding (7 bits per byte, MSB continuation) can overflow on 32-bit systems; malformed OIDs cause NULL pointer dereferences (CVE-2022-44792, CVE-2022-44793, CVE-2018-18066)
- **VACM MIB INDEX handling**: Buffer overflow in INDEX processing for VACM MIB (CVE-2022-24805)
- **Variable binding types**: Wrong ASN.1 type for expected MIB object causes type confusion; Counter64 on 32-bit systems

### Protocol-Level Attack Vectors
- **Unauthenticated access (v1/v2c)**: Community string "public" or "private" provides immediate access; once community is known, all OID-based attacks become trivial
- **GetBulk amplification**: Small GetBulk request with large max-repetitions generates massive response -- key DDoS amplification vector
- **Cisco IOS SNMP RCE**: With valid community string, crafted packets achieve RCE on Cisco routers (CVE-2017-6736 through CVE-2017-6738); public PoC available

### High-Value Fuzzing Strategies
- **ASN.1 BER mutations**: Fuzz tag class/number, indefinite-length encoding (0x80), multi-byte length values, and nested SEQUENCE structures
- **OID component fuzzing**: Very long OIDs, large subidentifier values, first-component packing edge cases (40*first + second)
- **Trap message fuzzing**: Target snmptrapd on UDP 162 with malformed trap PDUs -- CVE-2025-68615 proves this is still finding critical bugs
- **SNMPv3 USM parameters**: Fuzz EngineID length, EngineBoots/Time values, and HMAC digest sizes

## Notable Research

- **"SNMP Reflected Amplification DDoS"** - GetBulk amplification attacks
- **OUSPG PROTOS SNMP Test Suite (2002)** - One of the most impactful protocol fuzzing projects in history; found critical bugs in dozens of vendors
- **Google Project Zero Net-SNMP research** - ASN.1 parsing bugs
- **Cisco IOS SNMP RCE (2017)** - Nine CVEs for buffer overflows in Cisco IOS SNMP subsystem, exploited in the wild
- **CVE-2025-68615** - Critical Net-SNMP snmptrapd buffer overflow discovered via Trend Micro ZDI
- **"SNMP Security Analysis"** - Multiple academic papers
