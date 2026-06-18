# Modbus - Notable CVEs

CVEs related to server-side parsing and processing vulnerabilities in Modbus implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2013-0662 | Schneider Electric Modbus Serial Driver (ModbusDrv.exe) | Multiple stack-based buffer overflows via large buffer-size value in Modbus Application Header | Buffer Overflow / RCE | 9.3 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-14-086-01) |
| CVE-2015-6490 | Rockwell Allen-Bradley MicroLogix 1100/1400 | Stack-based buffer overflow via crafted Modbus TCP packets causing crash or RCE | Buffer Overflow / RCE | 10.0 (v2) | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-15-300-03a) |
| CVE-2018-7843 | Schneider Electric Modicon M580/M340/Quantum/Premium | Out-of-bounds read when reading memory blocks with invalid data size or offset over Modbus, causing DoS | Out-of-bounds Read / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-19-136-01) |
| CVE-2018-7849 | Schneider Electric Modicon M580/M340/Quantum/Premium | Uncaught exception causing DoS due to improper data integrity check when sending files over Modbus | Uncaught Exception / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-19-136-01) |
| CVE-2019-6857 | Schneider Electric Modicon M580/M340/Quantum/Premium | DoS when reading specific memory blocks using Modbus TCP due to improper check for exceptional conditions | Improper Input Handling / DoS | 7.5 | [CISA Advisory](https://us-cert.cisa.gov/ics/advisories/icsa-20-016-01) |
| CVE-2022-0367 | libmodbus (before 3.1.7) | Heap-based buffer overflow in modbus_reply() when processing Modbus requests | Heap Overflow | 7.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-0367) |
| CVE-2024-10918 | libmodbus 3.1.10 | Stack-based buffer overflow when replying to a Modbus request with unexpected length | Buffer Overflow / RCE | 9.8 | [Nozomi Advisory](https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-10918) |

## Key Vulnerability Patterns for Fuzzing

1. **MBAP Length vs. PDU Length**: Mismatch between MBAP header length field and actual PDU payload size
2. **Function Code Boundaries**: Undocumented function codes (vendor-specific range 65-72, 100-110) often lack validation
3. **Register/Coil Quantity**: quantity fields exceeding physical register space
4. **Exception Response Parsing**: Malformed exception codes (values > 0x0B) cause array out-of-bounds
5. **Write Multiple operations**: byte_count field inconsistent with quantity field
6. **Zero-length PDUs**: Empty or near-empty Modbus frames
7. **Maximum ADU size**: Modbus spec limits ADU to 260 bytes (RTU) / 260 bytes (TCP), exceeding this crashes many implementations

## Exploits and PoCs

### CVE-2024-10918
- **Product**: libmodbus v3.1.10
- **Type**: Stack-based Buffer Overflow
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- modbus_reply() overflows the response buffer when processing a request with unexpected length
- **Root cause**: The reply function allocates a fixed-size stack buffer for the Modbus response but does not validate that the incoming request length fits within the expected bounds before constructing the reply, causing stack corruption
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Nozomi Advisory](https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-10918)
- **Analysis**: A fuzzer sending Modbus requests with lengths deviating from the function code's expected size directly triggers this overflow. Fixed in libmodbus v3.1.11.

### CVE-2022-0367
- **Product**: libmodbus before 3.1.7
- **Type**: Heap-based Buffer Overflow
- **CVSS**: 7.8 (v3.1)
- **Server-side**: Yes -- modbus_reply() in src/modbus.c overflows heap buffer when processing crafted Modbus requests
- **Root cause**: Insufficient validation of request data sizes in modbus_reply() allows writing beyond allocated heap buffer boundaries
- **PoC**: No public PoC (GitHub issue #614 contains fix details)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-0367)
- **Analysis**: Heap overflow in the most widely used C Modbus library. The fix commit on GitHub provides the precise code path. Fuzzers targeting modbus_reply() with variable-length requests reproduce this.

### CVE-2024-11737
- **Product**: Schneider Electric Modicon M241/M251/M258/LMC058
- **Type**: Improper Input Validation / DoS + Confidentiality + Integrity Loss
- **CVSS**: 9.8 (v3.1) / 9.3 (v4.0)
- **Server-side**: Yes -- controller accepts and processes unauthenticated crafted Modbus packets on port 502/TCP
- **Root cause**: Lack of input sanitization on Modbus packets allows denial of service, data exfiltration, and integrity compromise
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-24-352-04](https://www.cisa.gov/news-events/ics-advisories/icsa-24-352-04)
- **Analysis**: Critical vulnerability in production PLC firmware. Modbus port 502 accepts malicious packets without sanity-checking. A fuzzer generating malformed Modbus PDUs on an authenticated connection would trigger this.

### CVE-2024-8938
- **Product**: Schneider Electric Modicon M340 (< SV3.65), MC80, Momentum Unity M1E
- **Type**: Memory Buffer Overflow / RCE
- **CVSS**: 9.2 (v4.0)
- **Server-side**: Yes -- buffer overflow triggered by manipulating a Modbus function call, achievable after MitM
- **Root cause**: Missing bounds checking on Modbus function call parameters allows memory corruption leading to arbitrary code execution
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-24-326-04](https://www.cisa.gov/news-events/ics-advisories/icsa-24-326-04)
- **Analysis**: Requires MitM position but the underlying parsing flaw (buffer overflow from crafted Modbus function call) is a classic fuzzing target. Fixed in firmware SV3.65.

### ZScada Net 2.0 - Modbus Response Parsing Overflow
- **Product**: Z-Scada Net 2.0
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: N/A
- **Server-side**: Yes -- triggered when parsing a Modbus packet response
- **Root cause**: Stack-based buffer overflow from oversized Modbus response data
- **PoC**: [Exploit-DB #42691](https://www.exploit-db.com/exploits/42691)
- **Metasploit**: `exploit/windows/scada/modbus_zscada_bof` (historical)
- **Advisory**: [Exploit-DB](https://www.exploit-db.com/exploits/42691)
- **Analysis**: One of the few Modbus server-side exploits with a full Metasploit module. Demonstrates how oversized response data causes stack corruption.
