# EtherNet/IP (CIP) - Notable CVEs

CVEs related to parsing and processing vulnerabilities in EtherNet/IP/CIP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-3595 | Rockwell ControlLogix 1756-EN2*/EN3* | OOB write in CIP message parsing allows RCE; crafted CIP message larger than expected causes data written beyond buffer boundaries | OOB Write / RCE | 9.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01) |
| CVE-2023-3596 | Rockwell ControlLogix 1756-EN4* | Crafted CIP message causes OOB write resulting in DoS | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01) |
| CVE-2020-25159 | Real Time Automation (RTA) 499ES | Stack overflow in EtherNet/IP encapsulation parsing from crafted packet (large item count in CPF) | Stack Overflow / RCE | 9.8 | [Claroty Disclosure](https://claroty.com/team82/disclosure-dashboard/cve-2020-25159) |
| CVE-2022-1737 | Pyramid Solutions EtherNet/IP Adapter/Scanner DLL kits <= 4.4.0 | OOB write from crafted EtherNet/IP packet causes DoS or potentially RCE | OOB Write / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-144-01) |
| CVE-2012-6435 | Rockwell ControlLogix/CompactLogix/GuardLogix/MicroLogix | Valid CIP message to port 2222 or 44818 from unauthorized source causes CPU to stop logic execution and enter fault state | DoS | 7.8 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-13-011-03) |
| CVE-2020-13556 | OpENer (open-source) EtherNet/IP server 2.3 | OOB write in EtherNet/IP server from crafted network requests allows remote code execution | OOB Write / RCE | 9.8 | [Talos Advisory](https://talosintelligence.com/vulnerability_reports/TALOS-2020-1170) |
| CVE-2021-27478 | OpENer (open-source) <= 2.3 | Incorrect numeric type conversion in CIP connection path parsing (signed/unsigned cast of path length) causes DoS | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-105-02) |
| CVE-2021-27482 | OpENer (open-source) <= 2.3 | OOB read from crafted EtherNet/IP packet allows attacker to read arbitrary data | OOB Read | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-105-02) |

## Key Vulnerability Patterns for Fuzzing

1. **Encapsulation Header Length**: Length field not matching actual TCP payload - this is the most common entry point
2. **CPF Item Count/Length**: Manipulating item count in Common Packet Format to trigger allocation issues
3. **EPATH Segment Parsing**: Variable-length path segments with incorrect length prefixes
4. **Forward Open Parameters**: Connection parameters with edge-case RPI values, oversized connection sizes
5. **CIP Service Code + Path Combinations**: Valid service code with invalid path, or vice versa
6. **Multiple Service Packet**: Wrapping service that contains offset table - offsets pointing outside buffer
7. **Session Handle State**: Operations with invalid/expired session handles
8. **Large Forward Open vs. Forward Open**: Mixing 16-bit and 32-bit size fields
9. **Connection Manager Class 3**: Unconnected send with encapsulated CIP request containing another Forward Open

## Exploits and PoCs

### CVE-2023-3595
- **Product**: Rockwell Automation ControlLogix 1756-EN2*/EN3* Communication Modules
- **Type**: Out-of-bounds Write / RCE with Persistence
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- CIP message larger than expected causes data written beyond buffer boundaries, allowing firmware manipulation and persistent RCE
- **Root cause**: CIP message parsing does not validate message size against buffer allocation, allowing an oversized CIP message to write beyond buffer boundaries into firmware memory
- **PoC**: No public PoC -- associated with an unnamed APT group (unreleased exploit capability)
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-23-193-01](https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01)
- **Analysis**: This is comparable to the XENOTIME/TRISIS attack in severity. The exploit allows manipulation of firmware memory, RCE with persistence, and data exfiltration through the communication module. Exploitable over CIP routing for deep lateral movement across factory networks. Detection via Snort rules monitoring CIP class 0x342 (Socket Object) and class 0x351. Fixed in EN2* firmware v11.004. A fuzzer sending oversized CIP messages to different class/service combinations would find the underlying buffer overflow.

### CVE-2020-25159
- **Product**: Real Time Automation (RTA) 499ES EtherNet/IP Stack (all versions < v2.28)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- crafted EtherNet/IP encapsulation packet with large CPF item count overflows stack buffer
- **Root cause**: The EtherNet/IP encapsulation parser allocates a stack buffer based on the CPF (Common Packet Format) item count field without validating it against the actual packet size. An excessively large item count causes stack overflow.
- **PoC**: No public PoC (Claroty Team82 discovered and analyzed)
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-20-324-03](https://www.cisa.gov/news-events/ics-advisories/icsa-20-324-03), [Claroty Analysis](https://claroty.com/team82/research/rta-enip-stack-vulnerability)
- **Analysis**: The RTA 499ES stack is used by many third-party industrial device vendors, making this a supply-chain vulnerability. The bug is in the very first layer of parsing (encapsulation header CPF item count). A simple fuzzer mutating the item count field in the CPF structure triggers this.

### CVE-2020-13556
- **Product**: OpENer (open-source) EtherNet/IP Server v2.3 and commit 8c73bf3
- **Type**: Out-of-bounds Write / RCE
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- crafted network requests cause OOB write in EtherNet/IP server
- **Root cause**: In source/src/enet_encap/cpf.c, the function CreateCommonPacketFormatStructure contains an out-of-bounds write vulnerability when processing crafted CPF items
- **PoC**: No public exploit code (discovered by Martin Zeiser and Jared Rittle of Cisco Talos)
- **Metasploit**: N/A
- **Advisory**: [Talos Advisory TALOS-2020-1170](https://talosintelligence.com/vulnerability_reports/TALOS-2020-1170)
- **Analysis**: OpENer is the ODVA reference open-source EtherNet/IP adapter stack. The vulnerability is in CPF parsing, a fundamental parsing step for all EtherNet/IP communication. The exact file and function are documented, making this ideal for building a targeted fuzzing harness. A series of network requests (not just a single packet) triggers the OOB write.

### CVE-2021-27478
- **Product**: OpENer (open-source) EtherNet/IP Server <= v2.3
- **Type**: Incorrect Numeric Type Conversion / DoS
- **CVSS**: 8.2 (v3.1)
- **Server-side**: Yes -- Forward Open CIP connection path parsing uses signed/unsigned integer cast incorrectly, causing large path length
- **Root cause**: In the CIP Forward Open connection path parsing, a signed-to-unsigned integer conversion allows an attacker to bypass existing length checks and produce a huge connection path length value, causing denial of service
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-21-105-02](https://www.cisa.gov/news-events/ics-advisories/icsa-21-105-02)
- **Analysis**: Type confusion between signed and unsigned integers in path length calculation. A fuzzer sending Forward Open requests with path length values near the signed/unsigned boundary (e.g., 0x7F, 0x80, 0xFF) would trigger this. The fix adds explicit bounds checking after the conversion.

### CVE-2021-27482
- **Product**: OpENer (open-source) EtherNet/IP Server <= v2.3
- **Type**: Out-of-bounds Read / Information Disclosure
- **CVSS**: 7.5 (v3.1)
- **Server-side**: Yes -- crafted ENIP/CIP packet reads arbitrary data from process memory
- **Root cause**: No checks on the number of bytes read from the provided packet, allowing reads beyond the packet buffer into adjacent memory
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-21-105-02](https://www.cisa.gov/news-events/ics-advisories/icsa-21-105-02)
- **Analysis**: Information disclosure through OOB read. Since there are "no checks on the bytes read from the provided packet," essentially any CIP request with a length field exceeding the actual data triggers this. A fuzzer with AddressSanitizer would immediately flag this as a heap-buffer-overflow read.

### CVE-2025-11743
- **Product**: Rockwell Automation CompactLogix 5370
- **Type**: Improper Input Validation / DoS (major nonrecoverable fault)
- **CVSS**: 6.5 (v3.1)
- **Server-side**: Yes -- malformed CIP Forward Open message causes controller major nonrecoverable fault requiring manual restart
- **Root cause**: CWE-1284 (Improper Validation of Specified Quantity in Input) -- the controller does not safely handle a malformed CIP Forward Open message with invalid quantity fields
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-26-022-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-03)
- **Analysis**: Recent (2025) vulnerability in production Rockwell PLCs. CIP Forward Open is a primary target for fuzzing because it involves complex parameter encoding (connection parameters, RPI, size, priority, routing path). A fuzzer mutating the quantity/size fields in Forward Open requests would find this.

### CVE-2024-6242
- **Product**: Rockwell Automation ControlLogix
- **Type**: Authorization Bypass (Trusted Slot bypass)
- **CVSS**: 7.3 (v3.1)
- **Server-side**: Yes -- allows executing CIP commands that modify user projects and device configuration by bypassing the Trusted Slot feature
- **Root cause**: Insufficient enforcement of the Trusted Slot mechanism allows crafted CIP messages to bypass slot-based access controls
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Rockwell Advisory](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html)
- **Analysis**: Access control bypass through crafted CIP messages. While not a parsing crash, demonstrates how CIP message structure manipulation can subvert security mechanisms. A fuzzer testing CIP service/class/instance combinations with various path routing could discover similar bypasses.
