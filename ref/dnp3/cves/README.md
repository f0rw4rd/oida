# DNP3 - Notable CVEs

CVEs related to parsing and processing vulnerabilities in DNP3 implementations, relevant to fuzzing. Only server-side (outstation/slave/gateway) parsing vulnerabilities are included.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2013-2813 | Cooper Power Systems SMP 4/4DP/16 Gateway | DNP3 component improper input validation allows DoS (reboot or link outage) via crafted DNP3 TCP packet | DoS | 7.1 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-13-346-01) |
| CVE-2013-2788 | SUBNET Solutions SubSTATION Server | DNP3 Slave service unhandled exception and process crash from crafted input | DoS | 4.3 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-13-252-01) |
| CVE-2014-2345 | COPA-DATA zenon DNP3 Process Gateway | DNP3 outstation/master infinite loop and process crash from crafted DNP3 TCP packet | DoS | 7.1 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-14-154-01) |
| CVE-2014-5426 | MatrikonOPC Server for DNP3 | Unhandled C++ exception from crafted DNP3 message causes process crash (DoS loop) | DoS | 5.0 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-14-329-01) |
| CVE-2015-5374 | Siemens SIPROTEC 4/Compact EN100 Ethernet module | Crafted packets to port 50000/UDP cause device to become unresponsive (manual reboot required); affects all EN100 firmware variants including DNP3 TCP | DoS | 7.8 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-15-202-01) |
| CVE-2020-6996 | Triangle MicroWorks DNP3 Outstation Libraries | Stack-based buffer overflow from specially crafted message in DNP3 Outstation .NET and ANSI C libraries (v3.16.00-3.25.01) | Buffer Overflow / RCE | 9.8 (v3.1) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-20-105-02) |

## Key Vulnerability Patterns for Fuzzing

1. **Transport Layer Reassembly**: Fragment reassembly with FIR/FIN bits is a major attack surface - incomplete fragments, out-of-order sequence numbers, overlapping data
2. **Object Header Parsing**: Variable-length objects with qualifier-defined sizes are the most common crash vector
3. **CRC Block Boundaries**: Data link layer CRC blocks every 16 bytes - malformed block boundaries cause parsing confusion
4. **Application Layer Function Codes**: Vendor-specific function codes (0x80+) rarely receive security testing
5. **Unsolicited Response Handling**: Unsolicited messages arriving in unexpected states trigger null pointer dereferences
6. **Authentication Challenges**: Secure Authentication (SA v5) adds HMAC and challenge-response which dramatically increase attack surface
7. **File Transfer Operations**: DNP3 file transfer function codes are complex and rarely tested

## Project Robus (Adam Crain / Chris Sistrunk)

The most significant DNP3 fuzzing effort. Found parsing vulnerabilities in virtually every DNP3 implementation tested (20+ products). Key findings:
- Most implementations had no input validation at the data link layer
- Transport layer reassembly was universally broken
- Object header parsing was the richest attack surface
- Almost no implementation correctly handled all qualifier codes
- Resulted in the umbrella advisory [ICSA-13-291-01B](https://www.cisa.gov/news-events/ics-advisories/icsa-13-291-01b) covering 15+ vendors

## Exploits and PoCs

### CVE-2020-6996
- **Product**: Triangle MicroWorks DNP3 Outstation .NET and ANSI C Libraries v3.16.00 through v3.25.01
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- outstation library overflows stack buffer when parsing a specially crafted DNP3 message
- **Root cause**: Missing bounds checking on incoming DNP3 application layer message data allows stack buffer overflow in the outstation response path
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-20-105-02](https://www.cisa.gov/news-events/ics-advisories/icsa-20-105-02)
- **Analysis**: Discovered by Steven Seeley and Chris Anastasio (Incite Team) via Trend Micro ZDI. Triangle MicroWorks libraries are embedded in dozens of third-party DNP3 products, making this a supply-chain-level vulnerability. No authentication required. A fuzzer targeting application layer object parsing with oversized data fields would reproduce this.

### CVE-2015-5374
- **Product**: Siemens SIPROTEC 4/Compact with EN100 Ethernet Module (firmware < V4.25)
- **Type**: DoS (device becomes unresponsive, manual reboot required)
- **CVSS**: 7.8 (v2)
- **Server-side**: Yes -- EN100 module crashes on specially crafted packet to port 50000/UDP
- **Root cause**: Improper input validation of packets on port 50000/UDP causes device to enter unresponsive state requiring physical power cycle
- **PoC**: [GitHub PoC](https://github.com/can/CVE-2015-5374-DoS-PoC) -- Python script sending an 18-byte crafted payload
- **Metasploit**: `auxiliary/dos/scada/siemens_siprotec4`
- **Advisory**: [CISA Advisory ICSA-15-202-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-202-01)
- **Analysis**: Affects SIPROTEC devices running DNP3, IEC 104, and other firmware variants on the EN100 module. The exploit payload is only 18 bytes (`11 49 00 00 ...`). This is an extremely low-complexity attack -- a fuzzer would find it trivially by sending random short payloads to the UDP port. Also listed on Exploit-DB (#44103).

### CVE-2014-5426
- **Product**: MatrikonOPC Server for DNP3
- **Type**: Unhandled C++ Exception / DoS
- **CVSS**: 5.0 (v2)
- **Server-side**: Yes -- crafted DNP3 message causes unhandled exception and process crash
- **Root cause**: DNP3 parser does not catch exceptions for malformed messages, causing the server process to crash and enter a DoS restart loop
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-14-329-01](https://www.cisa.gov/news-events/ics-advisories/icsa-14-329-01)
- **Analysis**: Classic unhandled exception from malformed input. DNP3 application layer object parsing with invalid group/variation combinations triggers the crash.

### CVE-2014-2345
- **Product**: COPA-DATA zenon DNP3 Process Gateway
- **Type**: Infinite Loop / DoS
- **CVSS**: 7.1 (v2)
- **Server-side**: Yes -- crafted DNP3 TCP packet causes infinite loop and process crash in both outstation and master modes
- **Root cause**: Parsing logic enters infinite loop on specific malformed DNP3 data link or transport layer fields
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-14-154-01](https://www.cisa.gov/news-events/ics-advisories/icsa-14-154-01)
- **Analysis**: Infinite loops are a common fuzzing discovery in DNP3 transport layer reassembly. Malformed FIR/FIN bits or sequence numbers that create cycles in the reassembly state machine are the typical trigger.

### ICSA-14-006-01 (Schneider Electric SAGE RTU)
- **Product**: Schneider Electric Telvent SAGE RTU with DNP3 firmware
- **Type**: Improper Input Validation / DoS
- **CVSS**: N/A
- **Server-side**: Yes -- crafted DNP3 packets cause denial of service on the RTU
- **Root cause**: Insufficient validation of DNP3 input data on the outstation
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-14-006-01](https://www.cisa.gov/news-events/ics-advisories/icsa-14-006-01)
- **Analysis**: Part of the wave of DNP3 vulnerabilities uncovered by Project Robus fuzzing efforts.
