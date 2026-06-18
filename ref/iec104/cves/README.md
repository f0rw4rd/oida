# IEC 60870-5-104 - Notable CVEs

CVEs related to parsing and processing vulnerabilities in IEC 104 implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2015-5374 | Siemens SIPROTEC 4/Compact EN100 | Crafted packets to UDP port 50000 cause DoS on EN100 Ethernet module (IEC 104 firmware variant) | DoS | 7.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-15-202-01) |
| CVE-2019-19279 | Siemens SIPROTEC 4/Compact EN100 | Crafted packets to UDP port 50000 cause DoS, manual reboot required (EN100 with IEC 104 firmware) | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-20-042-12) |
| CVE-2022-2502 | Hitachi Energy RTU500 | Buffer overflow in HCI IEC 60870-5-104 function from missing input validation, causes CMU reboot | Buffer Overflow / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-235-07) |
| CVE-2023-6711 | Hitachi Energy RTU500 | Buffer overflow in SCI/HCI IEC 60870-5-104 from specially crafted messages, causes CMU reboot | Buffer Overflow / DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-24-354-01) |

## Key Vulnerability Patterns for Fuzzing

1. **APCI Length Field**: Length byte > 253 or mismatched with actual payload - most implementations don't validate properly
2. **I-Format Sequence Numbers**: 15-bit sequence number wrapping and desynchronization
3. **ASDU Type/SQ Combinations**: SQ bit + number of objects + type-specific sizes create complex size calculations that often overflow
4. **Information Object Address Range**: 3-byte IOA (0-16777215) with out-of-range values
5. **Cause of Transmission**: Undefined COT values (>47) trigger unhandled code paths
6. **Multiple ASDUs in Single APDU**: Some implementations support packing, creating nested parsing issues
7. **State Machine Violations**: Sending I-frames before STARTDT confirmation, or mixed U-frame types

## Exploits and PoCs

### CVE-2015-5374
- **Product**: Siemens SIPROTEC 4/Compact EN100 Ethernet Module (firmware < V4.25)
- **Type**: DoS (device unresponsive, requires manual power cycle)
- **CVSS**: 7.8 (v2)
- **Server-side**: Yes -- EN100 module with IEC 104 firmware crashes on crafted packet to port 50000/UDP
- **Root cause**: Improper validation of incoming packets on port 50000/UDP causes the EN100 module to enter an unrecoverable state
- **PoC**: [GitHub PoC](https://github.com/can/CVE-2015-5374-DoS-PoC) -- 18-byte crafted UDP payload
- **Metasploit**: `auxiliary/dos/scada/siemens_siprotec4`
- **Advisory**: [CISA Advisory ICSA-15-202-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-202-01)
- **Analysis**: Affects the EN100 module in IEC 104 firmware mode. The exploit is trivially simple -- an 18-byte payload sent to UDP port 50000 causes a permanent DoS requiring physical reboot. Any fuzzer would discover this within seconds. Also on Exploit-DB (#44103).

### CVE-2022-2502
- **Product**: Hitachi Energy RTU500 Series CMU
- **Type**: Buffer Overflow / DoS
- **CVSS**: 7.5 (v3.1)
- **Server-side**: Yes -- HCI IEC 60870-5-104 function overflows internal buffer from crafted message, causing CMU reboot
- **Root cause**: Missing input data validation in the HCI IEC 60870-5-104 implementation causes internal buffer overflow when processing specially crafted messages. Only exploitable when HCI 60870-5-104 is configured with IEC 62351-5 support and the CMU has the 'Advanced security' license feature.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-23-220-02](https://www.cisa.gov/news-events/ics-advisories/icsa-23-220-02)
- **Analysis**: Buffer overflow in a widely deployed RTU platform. The IEC 62351-5 authentication layer adds parsing complexity that was not adequately validated. A fuzzer targeting the authentication handshake with oversized fields would trigger this.

### CVE-2023-6711
- **Product**: Hitachi Energy RTU500 Series CMU
- **Type**: Buffer Overflow / DoS
- **CVSS**: 5.9 (v3.1)
- **Server-side**: Yes -- both SCI and HCI IEC 60870-5-104 components fail to validate specially crafted messages, causing buffer overflow and CMU reboot
- **Root cause**: Insufficient message validation in IEC 60870-5-104 parsing allows buffer overflow from crafted ASDU content
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-24-354-01](https://www.cisa.gov/news-events/ics-advisories/icsa-24-354-01)
- **Analysis**: Follow-up to CVE-2022-2502 in the same RTU500 product, this time affecting both SCI and HCI IEC 104 interfaces. Demonstrates that even after initial fixes, additional parsing paths remain vulnerable.

### CVE-2019-19279
- **Product**: Siemens SIPROTEC 4/Compact EN100 Ethernet Module (IEC 104 firmware)
- **Type**: DoS (device unresponsive, requires manual reboot)
- **CVSS**: 7.5 (v3.1)
- **Server-side**: Yes -- crafted packets to UDP port 50000 cause DoS on EN100 module with IEC 104 firmware
- **Root cause**: Similar to CVE-2015-5374; additional malformed packet patterns that bypass the original fix still cause the EN100 module to become unresponsive
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-20-042-12](https://www.cisa.gov/news-events/ics-advisories/icsa-20-042-12)
- **Analysis**: A patch bypass for CVE-2015-5374. The EN100 module on Siemens SIPROTEC remains a weak point -- despite fixes, new crash vectors continue to be found on the same UDP service.

### CVE-2024-9684
- **Product**: FreyrSCADA IEC-60870-5-104 Server v21.06.008
- **Type**: DoS (resource exhaustion / crash)
- **CVSS**: N/A
- **Server-side**: Yes -- remote unauthenticated attacker can cause DoS by sending specific message sequences
- **Root cause**: Server does not properly handle certain message sequences, leading to resource exhaustion or crash
- **PoC**: PoC exists (specific sequences disclosed)
- **Metasploit**: N/A
- **Advisory**: [RedPacket Security](https://www.redpacketsecurity.com/cve-alert-cve-2024-9684-freyrscada-iec-60870-5-104/)
- **Analysis**: Affects a commercial IEC 104 server implementation. Network-accessible OT server vulnerable to unauthenticated DoS. A stateful fuzzer sending specific IEC 104 message sequences (e.g., rapid STARTDT/STOPDT cycling, malformed I-frames) would trigger this.
