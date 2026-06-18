# TASE.2 / ICCP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in TASE.2/ICCP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-18326 | Siemens SPPA-T3000 MS3000 | Heap-based buffer overflow from crafted packets to port 5010/TCP | Heap Overflow / RCE | 9.8 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-451445.html) |
| CVE-2021-27196 | Hitachi Energy Relion 670/650/SAM600-IO | IEC 61850 MMS-server improper input validation causes device reboot | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-096-01) |

## Key Vulnerability Patterns for Fuzzing

1. **MMS/ASN.1 BER Encoding**: Malformed tag-length-value structures, indefinite length encoding, deeply nested constructs
2. **Bilateral Table Parsing**: Table definitions with invalid entries, oversized tables, circular references
3. **Transfer Set Parameters**: Edge-case timing values (0ms intervals), contradictory condition flags
4. **Data Value Encoding**: Type tags mismatched with data content, quality flags with undefined bits
5. **TPKT/COTP Layer**: Length field manipulation, COTP connection parameter abuse
6. **Association Establishment**: Malformed ACSE association parameters, unexpected PDU sequences
7. **Domain Name Handling**: Long strings, null bytes in names, deep nesting of domain references

## Notes

TASE.2 is essentially MMS with specific application-layer semantics. Most TASE.2 vulnerabilities are actually MMS parsing bugs triggered through TASE.2 usage patterns. When fuzzing TASE.2, focus on:
- The MMS layer (ASN.1 BER is the richest attack surface)
- TASE.2-specific object naming and bilateral table structures
- The COTP/Session layer connection establishment sequence

## Exploits and PoCs

### CVE-2022-2277
- **Product**: Hitachi Energy MicroSCADA X SYS600 v10.2 to v10.3.1
- **Type**: DoS (ICCP stack crash)
- **CVSS**: 7.5
- **Server-side**: Yes -- ICCP stack crashes when forwarding data items with timestamps too far in the future
- **Root cause**: Improper input validation in the ICCP stack's timestamp processing. When SYS600 is requested to forward data item updates with timestamps too distant in the future to a remote ICCP system, a validation flaw causes denial of service.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-22-272-01](https://www.cisa.gov/news-events/ics-advisories/icsa-22-272-01)
- **Analysis**: Demonstrates that TASE.2/ICCP-specific data types are a real attack surface beyond just MMS parsing. Timestamp validation is a classic fuzzing target -- sending extreme values (year 9999, negative timestamps, epoch overflow) in data item updates crashes the ICCP stack. This affects utility control center communications.

### CVE-2024-34057 (also affects TASE.2 deployments)
- **Product**: Triangle MicroWorks TMW IEC 61850 library < 12.2.0 (also ships as TMW 60870-6 ICCP/TASE.2 library)
- **Type**: Buffer Overflow / DoS
- **CVSS**: 8.8 (CVSS v4)
- **Server-side**: Yes -- missing buffer size check when processing received MMS messages
- **Root cause**: MMS message processing does not validate buffer sizes before copy, causing overflow. Since TASE.2 runs over MMS, all MMS parsing bugs in the TMW library directly affect TASE.2/ICCP implementations.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-24-256-16](https://www.cisa.gov/news-events/ics-advisories/icsa-24-256-16), [Siemens SSA-673996](https://cert-portal.siemens.com/productcert/html/ssa-673996.html)
- **Analysis**: TMW libraries are used in both IEC 61850 and ICCP/TASE.2 products. The buffer overflow affects the shared MMS parsing layer, meaning TASE.2 implementations using TMW are vulnerable to the same crafted MMS messages. Siemens SICAM and SITIPE products use this library.

### TMW ICCP/TASE.2 Uninitialized Pointer Vulnerability (CVE pre-2013)
- **Product**: Triangle MicroWorks 60870-6 (ICCP/TASE.2) C++ Library <= 4.4.3
- **Type**: DoS (uninitialized pointer dereference)
- **CVSS**: 7.5 (estimated)
- **Server-side**: Yes -- uninitialized pointers in ICCP protocol parsing code cause crashes
- **Root cause**: A small number of uninitialized pointers in the code are accessed during ICCP message processing, causing undefined behavior (typically crash)
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-13-240-01](https://www.cisa.gov/news-events/ics-advisories/icsa-13-240-01)
- **Analysis**: Uninitialized pointers are a classic fuzzing find. Memory sanitizers (ASAN) combined with fuzzing would detect these immediately. The TMW library is used by many SCADA vendors for ICCP/TASE.2 communication between control centers, meaning this affects multiple downstream products.

### PcVue ICCP/TASE.2 Vulnerability (2022)
- **Product**: ARC Informatique PcVue (IEC 61850 client driver and ICCP/TASE.2 interface)
- **Type**: DoS / Information Disclosure
- **CVSS**: Varies
- **Server-side**: Yes -- vulnerabilities in the ICCP/TASE.2 interface component
- **Root cause**: Security vulnerabilities in the PcVue IEC 61850 client driver and ICCP/TASE.2 interface, likely related to TMW library dependencies
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [PcVue Security Bulletin 2022-5](https://www.pcvue.com/helpcenter/knowledge-base/security-bulletin-2022-5-iec-61850-client-driver-and-iccp-tase2-interface-vulnerabilities/)
- **Analysis**: Demonstrates the supply-chain risk of ICCP/TASE.2 -- vulnerabilities in underlying libraries (likely TMW) propagate to downstream SCADA products like PcVue. Multiple vendors share the same TASE.2 library code.
