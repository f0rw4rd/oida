# MMS / IEC 61850 - Notable CVEs

CVEs related to parsing and processing vulnerabilities in MMS/IEC 61850 implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2022-2970 | MZ Automation libIEC61850 | MMS server stack-based buffer overflow from improper bounds checking before memcpy | Stack Overflow / RCE | 9.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01) |
| CVE-2022-2972 | MZ Automation libIEC61850 | MMS server stack-based buffer overflow allowing crash or remote code execution | Stack Overflow / RCE | 9.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01) |
| CVE-2022-2971 | MZ Automation libIEC61850 | MMS server type confusion vulnerability allowing server crash via malicious payload | Type Confusion / DoS | 8.6 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01) |
| CVE-2022-2973 | MZ Automation libIEC61850 | MMS server NULL pointer dereference allowing server crash | Null Deref / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01) |
| CVE-2015-6574 | SISCO MMS-EASE (used in Siemens SIPROTEC 5) | SNAP Lite component CPU consumption DoS via crafted MMS packet | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-349-14) |
| CVE-2022-3353 | Hitachi Energy IEC 61850 MMS-Server | Crafted MMS message sequence forces server to stop accepting new connections | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-23-089-01) |
| CVE-2024-34057 | Triangle MicroWorks TMW IEC 61850 library | MMS buffer overflow from missing buffer size check when processing received messages | Buffer Overflow / DoS | 8.2 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-249-01) |
| CVE-2020-15783 | Siemens SIMATIC S7-300 / TDC CPU555 / SINUMERIK 840D sl | Crafted packets to port 102 (TPKT/COTP/MMS stack) cause DoS, cold restart required | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-15783) |

## Key Vulnerability Patterns for Fuzzing

1. **ASN.1 BER Length Fields**: The single most productive fuzzing target - indefinite lengths, multi-byte lengths, lengths exceeding remaining data, zero lengths on constructed types
2. **TPKT Length vs TCP Payload**: 2-byte TPKT length mismatch with actual data received
3. **COTP Segmentation**: DT TPDUs with EOT flag manipulation, TPDU size negotiation violations
4. **MMS PDU Type Confusion**: Sending response PDUs as requests, mixing confirmed/unconfirmed
5. **Variable Name Resolution**: Deeply nested domain-specific names, excessively long item identifiers
6. **GOOSE Injection**: stNum/sqNum manipulation, dataset encoding mismatches (no authentication on Layer 2)
7. **ASN.1 Tag Numbers**: Using UNIVERSAL/APPLICATION/PRIVATE class tags where CONTEXT-SPECIFIC is expected
8. **File Transfer Path Traversal**: ObtainFile with ../ sequences

## Exploits and PoCs

### CVE-2015-5374
- **Product**: Siemens SIPROTEC 4 / SIPROTEC Compact EN100 Ethernet Module < V4.25
- **Type**: DoS (device crash, manual reboot required)
- **CVSS**: 7.8
- **Server-side**: Yes -- crafted packet to port 50000/UDP crashes the protection relay
- **Root cause**: Improper handling of specially crafted packet on EN100 module; firmware does not validate UDP payload before processing
- **PoC**: [github.com/can/CVE-2015-5374-DoS-PoC](https://github.com/can/CVE-2015-5374-DoS-PoC) (Python script + Metasploit module)
- **Metasploit**: `auxiliary/dos/scada/siemens_siprotec4`
- **Exploit-DB**: [44103](https://www.exploit-db.com/exploits/44103)
- **Advisory**: [CISA ICSA-15-202-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-202-01)
- **Analysis**: Weaponized by Industroyer/CrashOverride malware (Ukraine 2016 grid attack). Sends a single crafted UDP packet to kill SIPROTEC protection relays, disabling protective functions during power grid manipulation. A fuzzer targeting the EN100 UDP interface would trivially find this.

### CVE-2022-2970
- **Product**: MZ Automation libIEC61850 <= 1.4 (and 1.5 before commit a3b04b7)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- MMS server does not sanitize input before memcpy
- **Root cause**: Missing bounds check on ASN.1 BER-decoded field length before memcpy into fixed-size stack buffer
- **PoC**: No public PoC (vulnerability details in CISA advisory)
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-22-251-01](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01)
- **Analysis**: Classic stack buffer overflow in the most widely used open-source IEC 61850 library. A fuzzer mutating ASN.1 BER lengths in MMS messages would find this by triggering memcpy with attacker-controlled size into a fixed stack buffer.

### CVE-2022-2972
- **Product**: MZ Automation libIEC61850 <= 1.4 (and 1.5 before commit a3b04b7)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- second stack overflow in MMS server message processing
- **Root cause**: Another unchecked memcpy in a different MMS service handler path
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-22-251-01](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01)
- **Analysis**: Same root cause class as CVE-2022-2970 but in a different code path. Both found through the same audit, demonstrating that the library had systemic missing bounds checks across multiple MMS service handlers.

### CVE-2022-2971
- **Product**: MZ Automation libIEC61850 <= 1.4 (and 1.5 before commit a3b04b7)
- **Type**: Type Confusion / DoS
- **CVSS**: 8.6
- **Server-side**: Yes -- MMS server crashes on malicious payload with wrong ASN.1 type tag
- **Root cause**: Server processes ASN.1 value without verifying the tag matches the expected type, leading to type confusion when casting
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-22-251-01](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01)
- **Analysis**: ASN.1 tag confusion -- fuzzer sending wrong tag class/number for an expected MMS field triggers this. Grammar-aware ASN.1 fuzzers that mutate tags are ideal for finding this class of bug.

### CVE-2024-45971
- **Product**: MZ Automation libIEC61850 < 1.6.0 (MMS Client)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8 (estimated)
- **Server-side**: No -- affects MMS client parsing a malicious server response (IdentifyResponse)
- **Root cause**: Multiple buffer overflows when client parses MMS IdentifyResponse message from a rogue server; no bounds check on response field lengths before copy to stack buffer
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ENCS Advisory](https://encs.eu/news/critical-security-vulnerabilities-discovered-in-mz-automations-mms-client/)
- **Analysis**: Demonstrates that both client and server sides of MMS implementations have the same class of bugs. A rogue MMS server (or MitM) can crash or exploit clients connecting to it. Fuzzing the MMS client response parsing path is essential.

### CVE-2024-45970
- **Product**: MZ Automation libIEC61850 < 1.6.0 (MMS Client)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8 (estimated)
- **Server-side**: No -- affects MMS client parsing FileDirResponse
- **Root cause**: Missing buffer size check when processing MMS FileDirResponse message from server; field lengths from ASN.1 decoded data used directly as copy length
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ENCS Advisory](https://encs.eu/news/critical-security-vulnerabilities-discovered-in-mz-automations-mms-client/)
- **Analysis**: File transfer services in MMS are a rich attack surface. The FileDirResponse handler did not validate field lengths before stack buffer copies. Fuzzing MMS file service responses catches this.

### CVE-2024-45969
- **Product**: MZ Automation libIEC61850 < 1.6.0 (MMS Client)
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 7.5 (estimated)
- **Server-side**: No -- affects MMS client parsing InitiationResponse
- **Root cause**: Malicious MMS server sends crafted InitiateResponse that results in NULL pointer dereference during client-side processing
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ENCS Advisory](https://encs.eu/news/critical-security-vulnerabilities-discovered-in-mz-automations-mms-client/)
- **Analysis**: MMS Initiation is the first message exchange. Sending a malformed InitiateResponse crashes the client immediately. Fuzzing the association establishment sequence is high priority.

### CVE-2024-34057
- **Product**: Triangle MicroWorks TMW IEC 61850 library < 12.2.0
- **Type**: Buffer Overflow / DoS
- **CVSS**: 8.8 (CVSS v4)
- **Server-side**: Yes -- MMS server/client does not check buffer sizes when processing received MMS messages
- **Root cause**: Missing buffer size validation when copying data from received MMS messages into internal buffers
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-24-256-16](https://www.cisa.gov/news-events/ics-advisories/icsa-24-256-16), [Siemens SSA-673996](https://cert-portal.siemens.com/productcert/html/ssa-673996.html)
- **Analysis**: TMW library is used by Siemens in SICAM and SITIPE products. This is the same vulnerability class as the libiec61850 bugs -- missing length checks on ASN.1-decoded data before buffer copy. Affects a major commercial IEC 61850 stack used across many vendors.
