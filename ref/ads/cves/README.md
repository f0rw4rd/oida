# ADS (TwinCAT/Beckhoff) - Notable CVEs

CVEs related to parsing and processing vulnerabilities in ADS/TwinCAT implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-5636 | Beckhoff TwinCAT 2/3.1 | Malformed UDP packet causes ADS Discovery Service shutdown | DoS | 7.5 | [Rapid7 Blog](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/) |
| CVE-2019-5637 | Beckhoff TwinCAT 2/3.1 | Malformed UDP packet causes divide-by-zero crash when Profinet driver is configured | DoS | 7.5 | [Rapid7 Blog](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/) |

## Key Vulnerability Patterns for Fuzzing

1. **AMS/TCP Length Field**: 4-byte length value with no upper bound validation - classic buffer overflow trigger
2. **AMS NetID Routing**: Spoofed NetIDs to access devices behind AMS routers
3. **Index Group/Offset**: System index groups (0xF000+) with crafted offsets allow arbitrary memory read/write
4. **ReadWrite Length Mismatch**: Read length + write length + actual data size inconsistencies
5. **Notification Handle Abuse**: Invalid handles in Delete/Read notification commands
6. **State Changes**: WriteControl with invalid state transitions
7. **No Authentication**: ADS has no built-in authentication - all commands are accepted from any source
8. **Multi-Read/Write**: Index Group 0xF003 (batch operations) with malformed sub-request structures

## Exploits and PoCs

### CVE-2019-5636
- **Product**: Beckhoff TwinCAT 2 <= v2304, TwinCAT 3.1 <= v4204.0
- **Type**: DoS (ADS Discovery Service shutdown)
- **CVSS**: 5.3
- **Server-side**: Yes -- ADS Discovery Service crashes when processing empty UDP packet
- **Root cause**: Malformed UDP packet (empty payload) causes the ADS Discovery Service to remove its routing table and shut down. The service does not validate packet length before processing, and an empty packet triggers an error path that removes the AMS routing table.
- **PoC**: Discovered by Rapid7 researcher Andreas Galauner. Packets that trigger this are "typically sent out by nmap and possibly other network scanners" -- meaning routine network scanning can accidentally DoS the service.
- **Metasploit**: N/A
- **Advisory**: [Rapid7 Blog](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/), [Beckhoff Advisory 2019-004](https://download.beckhoff.com/download/document/product-security/Advisories/advisory-2020-003.pdf)
- **Analysis**: Remarkably, a standard nmap scan can crash the ADS Discovery Service. The service stays running but PLCs become undiscoverable on the network, disrupting commissioning and diagnostics. A fuzzer sending empty or minimal-length UDP packets to port 48898 finds this immediately. The fix added packet length validation.

### CVE-2019-5637
- **Product**: Beckhoff TwinCAT 2 <= v2304, TwinCAT 3.1 <= v4204.0 (with PROFINET driver configured)
- **Type**: DoS (divide-by-zero crash)
- **CVSS**: 7.5
- **Server-side**: Yes -- malformed UDP packet causes divide-by-zero in the TwinCAT runtime when PROFINET driver is active
- **Root cause**: A malformed UDP packet triggers a divide-by-zero error in the packet processing path when the PROFINET IO driver is configured. The parser uses a field value as a divisor without checking for zero.
- **PoC**: Discovered by Rapid7. No public exploit code, but the advisory describes the trigger conditions.
- **Metasploit**: N/A
- **Advisory**: [Rapid7 Blog](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/), [Beckhoff Advisory 2019-007]
- **Analysis**: Classic divide-by-zero from attacker-controlled input used as divisor. Only triggers when PROFINET driver is active (common in industrial setups). Device requires full restart after crash. A fuzzer targeting the UDP interface with zero-value fields would find this. Shows that cross-protocol interactions (ADS + PROFINET) create unique attack surfaces.

