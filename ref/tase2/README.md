# TASE.2 / ICCP (IEC 60870-6) - Reference Materials

## Protocol Overview

TASE.2 (Telecontrol Application Service Element, version 2), also known as ICCP (Inter-Control Center Communications Protocol), is defined in IEC 60870-6. It is used for real-time data exchange between electric utility control centers. TASE.2 runs over MMS (ISO 9506), sharing the same OSI protocol stack.

- **Transport**: TCP port 102 (same as MMS, via TPKT/COTP/Session/Presentation)
- **Base Protocol**: MMS (ISO 9506-1/2) with TASE.2-specific objects
- **Key Concepts**: Bilateral Tables (agreed data sets between peers), Data Values, Transfer Sets, Domains
- **Data Exchange**: Periodic/event-driven reporting, control operations, time synchronization

## Wireshark Dissectors

- **TASE.2/ICCP**: Parsed as MMS by [packet-mms.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mms.c)
- TASE.2 uses standard MMS services with specific object naming conventions
- Also see: [packet-tpkt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-tpkt.c) and [packet-cotp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cotp.c)
- No separate TASE.2-specific dissector exists; it relies on MMS dissection

### Key dissector details:
- TASE.2 objects are MMS named variables with specific naming patterns
- Bilateral table definitions use MMS NamedVariableList
- Transfer sets use MMS InformationReport for periodic data push
- Device/indication points mapped to MMS domain variables

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **libiec61850** | C | Includes TASE.2/ICCP support via MMS | [github.com/mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) |
| **libtase2** | C | Dedicated TASE.2 implementation by MZ Automation | [github.com/mz-automation/libtase2](https://github.com/mz-automation/libtase2) |
| **OpenICCP** | Java | Open-source ICCP implementation | Historical/academic implementations |

## Common Parsing Vulnerabilities

### 1. Inherited MMS/ASN.1 Vulnerabilities
- All MMS ASN.1 BER parsing vulnerabilities apply directly to TASE.2
- TPKT/COTP/Session/Presentation layer vulnerabilities are shared
- See the MMS reference for detailed ASN.1 attack patterns

### 2. Bilateral Table Manipulation
- Bilateral tables define which data points can be exchanged between peers
- Table definitions transmitted via MMS NamedVariableList services
- Crafted table entries with invalid data references
- Table size/count exceeding implementation limits

### 3. Transfer Set Issues
- Transfer set parameters (report interval, buffer time, integrity check)
- Very small report intervals causing flooding
- Transfer set conditions with contradictory flags
- Start/stop timing manipulation

### 4. Data Value Type Mismatches
- TASE.2 defines specific data types (DataValue, DataValuePair, etc.)
- Type confusion when ASN.1 encoding specifies wrong tag for data values
- Quality flag handling in data values with undefined bit combinations
- Timestamp objects with invalid time representations

### 5. Domain and Variable Naming
- TASE.2 uses hierarchical naming: domain/variableName
- Excessively long domain or variable names
- Special characters in names that break string handling
- Non-existent domain references in read/write operations

### 6. Authentication and Access Control
- TASE.2 relies on MMS ACSE authentication (association control)
- External mechanism (typically TLS) provides transport security
- Missing or weak authentication allows unauthorized bilateral table modification

## Notable Research

- **"Security Assessment of ICCP"** - Multiple utility security assessments
- **IEC 62351** - Security standards for TASE.2 (authentication, TLS)
- **INL (Idaho National Laboratory)** - ICCP security research for DOE
- **NERC CIP** - Regulatory framework covering ICCP/TASE.2 security
- **Hitachi Energy advisories** - Multiple SYS600 ICCP stack vulnerabilities (CVE-2022-2277)
- **Claroty Team82** - MMS protocol vulnerabilities affecting TASE.2 deployments (TMW library, 2024)
- **PcVue Security Bulletin 2022-5** - Demonstrates supply-chain risk of shared TASE.2 libraries

## Fuzzing Tools

- [fkie-cad/61850-fuzzing](https://github.com/fkie-cad/61850-fuzzing) -- Boofuzz-based IEC 61850 fuzzing scripts. Since TASE.2 runs over MMS, these MMS fuzzers directly apply to TASE.2 implementations. Includes protocol grammar for MMS PDU construction.
- [IEC61850-MMS-Fuzzer](https://github.com/Skill3t/IEC61850-MMS-Fuzzer) -- Mutation-based MMS fuzzer. TASE.2 traffic captured from bilateral table exchanges can be used as mutation seeds.
- [libtase2](https://github.com/mz-automation/libtase2) -- MZ Automation's dedicated TASE.2 library. Source code is available for building fuzz harnesses targeting TASE.2-specific parsing (bilateral tables, transfer sets, data values).
- [FreeTase2](https://github.com/aklira/FreeTase2) -- Free and open implementation of IEC 60870-6 TASE.2. Another target for fuzzing and a reference for protocol structure.
- No dedicated TASE.2 fuzzer exists publicly. The best approach is to fuzz the underlying MMS layer with TASE.2-specific object naming patterns and bilateral table structures.

## Attack Surface Notes

### Most Dangerous Message Types
- **MMS NamedVariableList (Bilateral Table Definition)** -- Defines which data points can be exchanged. Crafted table entries with invalid references, oversized tables, or circular references stress parsing.
- **MMS InformationReport (Transfer Set Data Push)** -- Periodic data delivery with data values and timestamps. Timestamps with extreme values crash the ICCP stack (CVE-2022-2277).
- **MMS InitiateRequest/Response** -- Association establishment. Malformed ACSE parameters and ASN.1 encoding bugs (inherited from MMS layer) crash servers during connection setup.
- **MMS Read/Write with TASE.2 Domain Variables** -- Hierarchical naming (domain/variableName) with excessively long names, special characters, or non-existent domain references.

### Most Commonly Vulnerable Fields
- **ASN.1 BER length fields** -- Inherited from MMS. Every MMS/ASN.1 parsing bug directly affects TASE.2 (CVE-2024-34057 TMW buffer overflow).
- **Timestamp values in DataValue objects** -- Timestamps too far in the future cause DoS (CVE-2022-2277). Negative timestamps, epoch overflows, and NaN time values are all fuzzing targets.
- **Bilateral table entry counts** -- Tables with zero entries, extremely large entry counts, or entries referencing non-existent data points.
- **Transfer set parameters** -- Report interval of 0ms, contradictory condition flags (integrity + change), extreme buffer times.
- **Quality flags** -- Undefined bit combinations in data value quality indicators can change parsing behavior unexpectedly.

### Known Weak Implementations
- **Triangle MicroWorks TMW 60870-6 Library** -- Uninitialized pointer vulnerability (pre-2013 advisory). Buffer overflow in MMS processing (CVE-2024-34057). TMW is the most widely used commercial TASE.2 library, deployed in utility control centers worldwide. Vulnerabilities propagate to all downstream vendors (PcVue, Siemens SICAM/SITIPE, others).
- **Hitachi Energy MicroSCADA SYS600** -- CVE-2022-2277: ICCP stack crashes on timestamps too far in future. Also CVE-2021-27196 (Relion 670/650): IEC 61850 MMS server input validation causing device reboot. Shows that Hitachi Energy's MMS/ICCP implementations have recurring input validation issues.
- **ARC Informatique PcVue** -- Security Bulletin 2022-5 confirms ICCP/TASE.2 interface vulnerabilities, likely inherited from TMW library dependencies. Demonstrates the supply-chain amplification effect in the TASE.2 ecosystem.
- **MZ Automation libtase2/libiec61850** -- The libiec61850 MMS stack (used by libtase2) had 4 critical CVEs in 2022 and 3 in 2024. Any TASE.2 deployment built on libiec61850 inherits these MMS parsing bugs.
