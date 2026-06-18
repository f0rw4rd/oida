# PROFINET DCP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in PROFINET implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-13946 | Siemens PROFINET Devices (multiple) | PNIO stack resource exhaustion from multiple diagnostic requests to DCE-RPC interface | DoS | 7.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-349422.html) |
| CVE-2019-10936 | Siemens SIMATIC Controllers (multiple) | Crafted UDP packets cause denial of service via uncontrolled resource consumption | DoS | 7.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-349422.html) |
| CVE-2017-2681 | Siemens Industrial Products (wide impact) | PROFINET DCP crafted Ethernet frames cause DoS on SIMATIC products | DoS | 6.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-293562.html) |
| CVE-2017-2680 | Siemens Industrial Products (wide impact) | PROFINET DCP malformed broadcast frames cause DoS | DoS | 6.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-293562.html) |
| CVE-2020-28400 | Siemens Multiple Products | PROFINET DCP reset packet flooding causes resource exhaustion DoS | DoS | 7.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-599968.html) |
| CVE-2022-25622 | Siemens PROFINET Devices (multiple) | PNIO stack with Interniche IP stack improperly handles TCP segments with short headers | DoS | 7.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-446448.html) |
| CVE-2018-4843 | Siemens SIMATIC/SINUMERIK/Softnet | Crafted PROFINET DCP response causes denial of service on requesting system | DoS | 6.5 | [Siemens Advisory](https://cert-portal.siemens.com/productcert/html/ssa-348629.html) |

## Key Vulnerability Patterns for Fuzzing

1. **DCP Block Length**: Malformed block length values (0, exceeding frame, very large) are the top crash vector
2. **DCP Frame Flooding**: Multicast DCP Identify with no rate limiting
3. **Block Iteration**: Parsing loops that don't properly validate remaining data before reading next block
4. **Station Name Assignment**: DCP Set with crafted station names (no authentication required)
5. **IP Configuration**: DCP Set IP with invalid network configurations causing stack crashes
6. **Frame ID Ranges**: Frame IDs outside the DCP range (0xFEFC-0xFEFF) being processed as DCP
7. **Layer 2 Attacks**: Since PROFINET DCP is Layer 2, no IP-based firewalling is possible
8. **Multi-Block Frames**: Multiple DCP blocks in a single frame with conflicting information

## Exploits and PoCs

### CVE-2017-2681
- **Product**: Siemens SIMATIC, SCALANCE, SIMOTION, SINUMERIK (wide impact across Siemens industrial portfolio)
- **Type**: DoS (device unresponsive, manual recovery required)
- **CVSS**: 6.5
- **Server-side**: Yes -- device crashes when parsing specially crafted PROFINET DCP Ethernet frames
- **Root cause**: Improper handling of crafted DCP packets on Layer 2; the PROFINET stack fails to validate DCP frame structure before processing
- **PoC**: No public PoC (reported by NSFOCUS Security Team)
- **Metasploit**: N/A
- **Advisory**: [Siemens SSA-293562](https://cert-portal.siemens.com/productcert/html/ssa-293562.html), [CISA ICSA-17-129-02](https://ics-cert.us-cert.gov/advisories/ICSA-17-129-02)
- **Analysis**: One of the most impactful PROFINET DCP CVEs due to the enormous number of affected Siemens products. Crafted Ethernet frames on the local segment crash devices -- no IP stack needed. A Layer 2 fuzzer sending mutated DCP frames would find this. The advisory has been updated 22+ times (Update V) as more products were found affected.

### CVE-2017-2680
- **Product**: Siemens SIMATIC, SCALANCE, SIMOTION, SINUMERIK (same wide impact as CVE-2017-2681)
- **Type**: DoS (device unresponsive, manual recovery required)
- **CVSS**: 6.5
- **Server-side**: Yes -- device crashes on malformed DCP broadcast packets
- **Root cause**: Similar to CVE-2017-2681 but triggered specifically by broadcast DCP packets; the parser does not validate packet structure in broadcast handling path
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Siemens SSA-293562](https://cert-portal.siemens.com/productcert/html/ssa-293562.html)
- **Analysis**: Broadcast variant of CVE-2017-2681. Since DCP Identify uses multicast, a single malformed broadcast packet can crash every vulnerable device on the same Layer 2 segment simultaneously. Extremely high impact in flat industrial networks.

### CVE-2020-28400
- **Product**: Siemens Multiple Products (SIMATIC, SCALANCE, SINAMICS, SIMOCODE, SIMOTION, SIPLUS, SITOP)
- **Type**: DoS (resource exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- device enters DoS state from flood of DCP reset packets
- **Root cause**: No rate limiting on DCP reset packet processing; each reset packet consumes resources without bound, leading to exhaustion
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Siemens SSA-599968](https://cert-portal.siemens.com/productcert/html/ssa-599968.html), [CISA ICSA-21-194-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-194-03)
- **Analysis**: Simple flooding attack -- send DCP reset packets at high rate to overwhelm the target. A fuzzer with a "flood" mode sending DCP frames at maximum rate would trigger this. No authentication on Layer 2 means any device on the segment can attack.

### CVE-2025-32396
- **Product**: RT-Labs P-Net PROFINET Library <= 1.0.1
- **Type**: Heap-based Buffer Overflow / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- PROFINET IO device crashes when parsing crafted UDP RPC packet
- **Root cause**: Heap buffer overflow in UDP RPC parsing code; length field from packet used without validation
- **PoC**: No public PoC (discovered by Nozomi Networks Labs via fuzzing)
- **Metasploit**: N/A
- **Advisory**: [Nozomi Networks](https://www.nozominetworks.com/blog/fuzzing-the-p-net-profinet-implementation)
- **Analysis**: Found by fuzzing P-Net with libFuzzer. Part of a batch of 10 vulnerabilities discovered in the same fuzzing campaign. All affect the PROFINET UDP RPC interface which handles connection establishment (CONNECT, WRITE, CONTROL).

### CVE-2025-32399
- **Product**: RT-Labs P-Net PROFINET Library <= 1.0.1
- **Type**: Infinite Loop / DoS (100% CPU consumption)
- **CVSS**: 5.3
- **Server-side**: Yes -- malicious RPC packet causes infinite loop in IO device
- **Root cause**: Unchecked input used as loop condition; attacker-controlled value causes loop to never terminate, consuming 100% CPU
- **PoC**: No public PoC (discovered by Nozomi Networks Labs)
- **Metasploit**: N/A
- **Advisory**: [Nozomi Networks CVE-2025-32399](https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2025-32399)
- **Analysis**: A single crafted UDP packet permanently DoS the IO device by trapping the CPU in an infinite loop. Classic fuzzing find -- a value-dependent loop without bounds checking.

### CVE-2025-32405
- **Product**: RT-Labs P-Net PROFINET Library <= 1.0.1
- **Type**: Out-of-bounds Write / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- ArVendorBlock parsing writes beyond buffer bounds
- **Root cause**: When parsing ArVendorBlock in CONNECT requests, an incremented counter is used as array index without bounds check. Attacker-controlled data from UDP packet written past buffer end.
- **PoC**: No public PoC (discovered by Nozomi Networks Labs)
- **Metasploit**: N/A
- **Advisory**: [NVD CVE-2025-32405](https://nvd.nist.gov/vuln/detail/CVE-2025-32405)
- **Analysis**: The most severe of the P-Net batch. Writing beyond the AR context buffer corrupts memory and makes the device entirely unusable. Found by fuzzing the CONNECT RPC service with mutated ArVendorBlock structures.

### CVE-2025-32397, CVE-2025-32400, CVE-2025-32401, CVE-2025-32402, CVE-2025-32403, CVE-2025-32404
- **Product**: RT-Labs P-Net PROFINET Library <= 1.0.1
- **Type**: Heap Buffer Overflow / Out-of-bounds Write / NULL Pointer Dereference
- **CVSS**: 4.8 - 7.5
- **Server-side**: Yes -- various parsing flaws in UDP RPC handling
- **Root cause**: Multiple memory safety issues across the RPC message parsing code paths
- **PoC**: No public PoC (all discovered by Nozomi Networks Labs via libFuzzer)
- **Metasploit**: N/A
- **Advisory**: [Nozomi Networks Vulnerability Advisories](https://www.nozominetworks.com/vulnerability-advisories)
- **Analysis**: All 10 P-Net CVEs were found in a single fuzzing campaign targeting UDP RPC. After disclosure, RT-Labs integrated fuzz testing into their CI/CD pipeline. This batch demonstrates the high yield of fuzzing PROFINET RPC interfaces.
