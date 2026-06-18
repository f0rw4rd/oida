# HART / HART-IP / WirelessHART - Notable CVEs

CVEs related to parsing and processing vulnerabilities in HART, HART-IP, and WirelessHART implementations. Only server-side (or master-side) parsing bugs that a network/protocol fuzzer would find are included. Auth bypasses, credential issues, web UI bugs, and design-level weaknesses are excluded per the fuzzer test.

## Summary Table

| CVE ID | Affected Product | Type | CVSS | Fuzzer-Relevant |
|--------|-----------------|------|------|-----------------|
| CVE-2020-16209 | FieldComm Group hipserver (HART-IP reference SDK) | Stack-based Buffer Overflow | 9.8 | Yes -- oversized HART-IP message payload |
| CVE-2014-9191 | CodeWrights GmbH HART DTM (used by 24+ vendors) | Buffer Overflow / DoS | 2.1 (v2) | Yes -- crafted HART response packets on current loop |
| CVE-2015-3977 | Schneider Electric IMT25 Magnetic Flow DTM | Buffer Overflow / RCE | 7.7 (v2) | Yes -- crafted HART reply triggers memory corruption |
| CVE-2015-6463 | CodeWrights HART Comm DTM / Endress+Hauser FieldCare | XXE / Information Disclosure / DoS | 5.8 (v2) | Yes -- XML external entity in HART longtag response field |

## Key Vulnerability Patterns for Fuzzing

1. **HART-IP Byte Count**: Header byte count field mismatched with actual payload size (CVE-2020-16209)
2. **Command-Specific Lengths**: Each HART command expects specific data lengths -- sending wrong sizes triggers OOB reads
3. **Packed ASCII Unpacking**: 6-bit packed ASCII string parsing without proper bounds checking
4. **Device-Specific Commands**: Commands 128-253 are vendor-specific with no standard format validation
5. **Status Byte Manipulation**: Communication error bits that change parsing behavior
6. **Sequence Number Wrapping**: 2-byte sequence numbers rolling over
7. **Sub-Device Commands**: Cmd 77 encapsulating another command creates recursive parsing potential
8. **Longtag Field Injection**: XML/special characters in longtag response parsed by DTM (CVE-2015-6463)
9. **DTM Response Parsing**: Crafted HART response packets overflow buffers in master-side DTM libraries (CVE-2014-9191, CVE-2015-3977)

## Detailed CVE Entries

---

### CVE-2020-16209
- **Product**: FieldComm Group HART-IP Developer Kit v1.0.0.0 / hipserver v3.6.1
- **Type**: Stack-based Buffer Overflow (CWE-121)
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- hipserver overflows internal buffer when processing HART-IP messages with oversized payloads sent to TCP/UDP port 5094
- **Root cause**: Unchecked memory transfer (memcpy) in the IP interface. HART-IP message payload size from the ByteCount header field is not validated before copying into a fixed-size internal buffer. The C standard library functions memcpy, memset, strcpy, strncpy, and sprintf were used systemically without bounds checking throughout the codebase.
- **Trigger**: Send a HART-IP message to port 5094 with a ByteCount field value larger than the internal buffer size. The oversized payload is memcpy'd into a stack buffer without length validation.
- **PoC**: No public exploit PoC. The vulnerable source code is available on GitHub at [FieldCommGroup/hipserver](https://github.com/FieldCommGroup/hipserver). The fix in v3.7.0 replaced all unsafe C functions with Intel/Cisco [safestringlib](https://github.com/intel/safestringlib) alternatives, showing exactly which functions were vulnerable. The diff between v3.6.1 and v3.7.0 is essentially a roadmap of every exploitable call site.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-20-287-04](https://www.cisa.gov/news-events/ics-advisories/icsa-20-287-04), [FieldComm Group Support](https://support.fieldcommgroup.org/support/solutions/articles/8000088791-2020-10-06-vulnerability-in-hipserver-cve-2020-162090-)
- **NVD**: [nvd.nist.gov/vuln/detail/CVE-2020-16209](https://nvd.nist.gov/vuln/detail/CVE-2020-16209)
- **Analysis**: This is the reference implementation for all HART-IP devices. The hipserver component is used by any vendor building HART-IP products on the FieldComm Group SDK. A fuzzer sending HART-IP messages with progressively larger payloads would trivially trigger this overflow. The fix explicitly shows every unsafe C function call that was replaced -- memcpy, memset, strcpy, strncpy, sprintf -- meaning the codebase had systemic buffer safety issues. Since this is the reference SDK, any vendor that integrated hipserver before v3.7.0 likely inherits these vulnerabilities. A boofuzz script targeting the ByteCount field with values 0x0000 through 0xFFFF combined with matching payload sizes would reproduce this.

---

### CVE-2014-9191
- **Product**: CodeWrights GmbH HART Device Type Manager (DTM) library, versions before 1.4.181. Used by ABB, Emerson, Honeywell, Endress+Hauser, Yokogawa, GE, MACTek, Pepperl+Fuchs, Magnetrol, Schneider Electric, and other vendors.
- **Type**: Buffer Overflow / Denial of Service (CWE-399 per NVD; effectively CWE-119 improper bounds checking)
- **CVSS**: 2.1 (CVSS v2: AV:L/AC:L/Au:N/C:N/I:N/A:P) -- NVD score is low due to physical proximity requirement; however, from an adjacent network perspective CISA assigned AV:A/AC:H
- **Server-side**: Yes (master-side) -- the DTM runs on the engineering workstation/master station and parses HART response packets received from field devices. Crafted responses from a compromised or spoofed field device overflow the DTM buffer.
- **Root cause**: The CodeWrights DTM library does not properly validate the length and content of HART response packets before processing. Specially crafted response packets injected onto the 4-20mA current loop (or via HART-IP if the DTM is used with a HART-IP gateway) cause a buffer overflow in the DTM, crashing the FDT Frame Application.
- **Trigger**: Connect to the HART current loop (physically or via HART-IP gateway) and send a crafted HART response packet with malformed data fields. The DTM parses the response and overflows an internal buffer. Requires the Frame Application to be running and connected to a DTM-configured HART device.
- **PoC**: No public PoC. Alexander Bolshev and Svetlana Cherkasova of Digital Security (Russia) discovered this and presented findings at Black Hat Europe 2014, demonstrating exploitation against 32 DTM components from 24 vendors affecting 750+ devices. The HRTShield Arduino board ([scastlecombe/hrtshield](https://github.com/scastlecombe/hrtshield)) was built for this research and can inject crafted packets on the current loop.
- **Metasploit**: N/A (custom modules were demonstrated at S4x14 but not merged upstream)
- **Advisory**: This single vulnerability generated 10 separate CISA advisories as each vendor published their own:
  - CodeWrights GmbH: [ICSA-15-012-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-012-01)
  - Emerson: [ICSA-15-008-01A](https://www.cisa.gov/news-events/ics-advisories/icsa-15-008-01a)
  - Honeywell: [ICSA-15-029-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-029-01)
  - Magnetrol: [ICSA-15-027-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-027-01)
  - GE/MACTek: [ICSA-15-036-01A](https://www.cisa.gov/news-events/ics-advisories/icsa-15-036-01a)
  - Pepperl+Fuchs: [ICSA-15-036-02](https://www.cisa.gov/news-events/ics-advisories/icsa-15-036-02)
  - Yokogawa: [ICSA-15-048-03](https://www.cisa.gov/news-events/ics-advisories/icsa-15-048-03)
  - ABB: [ICSA-15-069-02](https://www.cisa.gov/news-events/ics-advisories/icsa-15-069-02)
  - Schneider Electric IMT25: [ICSA-15-223-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-223-01)
  - Endress+Hauser: [ICSA-15-237-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-237-01)
- **NVD**: [nvd.nist.gov/vuln/detail/CVE-2014-9191](https://nvd.nist.gov/vuln/detail/CVE-2014-9191)
- **Analysis**: This is the most significant HART ecosystem vulnerability ever discovered in terms of blast radius. A single buffer overflow in the CodeWrights DTM library propagated to every major HART device manufacturer. The bug is a classic parsing flaw -- the DTM trusts field lengths in HART response packets without validation, and crafted responses overflow stack/heap buffers. From a fuzzing perspective, this is what happens when you fuzz the master side by sending malformed responses back to the parser. The HRTShield hardware or a HART-IP gateway can be used as the injection point. The low CVSS score is misleading -- it reflects the physical proximity requirement of the 4-20mA loop, but via HART-IP the same packets can be delivered over the network.

---

### CVE-2015-3977
- **Product**: Schneider Electric IMT25 Magnetic Flow DTM, versions before 1.500.004
- **Type**: Buffer Overflow / Memory Corruption / RCE (CWE-119)
- **CVSS**: 7.7 (CVSS v2: AV:A/AC:L/Au:S/C:C/I:C/A:C) -- no CVSS v3 assigned (NVD deferred)
- **Server-side**: Yes (master-side) -- the DTM parses HART reply packets from IMT25 Magnetic Flow transmitters. A crafted HART reply overwrites a specific memory value causing memory corruption.
- **Root cause**: Buffer overflow in the DTM software when parsing HART protocol replies from the IMT25 field device. A specific memory value can be overwritten by sending a specially crafted reply to a HART command, causing denial of service or arbitrary code execution at the privilege level of the Frame Application.
- **Trigger**: Send a crafted HART reply packet from a compromised or spoofed IMT25 Magnetic Flow transmitter. The malformed reply causes the DTM to write beyond buffer boundaries, corrupting adjacent memory. Requires access to the adjacent HART network (current loop or HART-IP gateway).
- **PoC**: No public PoC.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-15-223-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-223-01), [Schneider Electric SEVD-2015-215-01](https://www.schneider-electric.com/en/download/document/SEVD-2015-215-01/)
- **NVD**: [nvd.nist.gov/vuln/detail/CVE-2015-3977](https://nvd.nist.gov/vuln/detail/CVE-2015-3977)
- **Analysis**: This is a separate vulnerability from CVE-2014-9191 (the CodeWrights library bug), specific to Schneider Electric's own DTM code for the IMT25 Magnetic Flow transmitter. The higher CVSS score (7.7 vs 2.1) reflects that this bug leads to actual code execution, not just a DoS. The attack vector is the same -- craft a malicious HART reply that the DTM parses incorrectly. A fuzzer targeting HART response packet fields (command data, status bytes, packed ASCII strings) for the IMT25 DTM would find this. Deployed in Chemical, Critical Manufacturing, Energy, and Water/Wastewater sectors.

---

### CVE-2015-6463
- **Product**: CodeWrights HART Comm DTM components, as used with Endress+Hauser FieldCare (all versions)
- **Type**: XML External Entity Injection (CWE-611)
- **CVSS**: 5.8 (CVSS v2: AV:A/AC:L/Au:N/C:P/I:P/A:P) -- no CVSS v3 assigned (NVD deferred)
- **Server-side**: Yes (master-side) -- the HART Comm DTM on the engineering workstation parses the longtag value from HART device responses, and the longtag field content is processed through an XML parser
- **Root cause**: The HART Comm DTM reads longtag values from HART Device DTM responses and passes them to an XML parser without sanitization. An attacker can inject an XML schema containing external entity declarations into the longtag response field. When the Comm DTM parses this, it processes the external entity references, enabling file read, SSRF, or denial of service.
- **Trigger**: Respond to a HART command with a longtag field containing XML external entity declarations (e.g., `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`). The Comm DTM's XML parser processes the entity, reading arbitrary files or making HTTP requests. Requires access to the HART network (current loop or gateway).
- **PoC**: No public PoC. Discovered by Alexander Bolshev of Digital Security.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-15-267-01](https://www.cisa.gov/news-events/ics-advisories/icsa-15-267-01)
- **NVD**: [nvd.nist.gov/vuln/detail/CVE-2015-6463](https://nvd.nist.gov/vuln/detail/CVE-2015-6463)
- **Analysis**: This is a particularly clever parsing bug. The HART protocol has a longtag field (up to 32 characters), and the CodeWrights Comm DTM processes this field through an XML parser. By crafting a HART response with XML entities in the longtag, an attacker on the HART bus (or via HART-IP) can achieve XXE on the engineering workstation. A protocol-aware fuzzer that injects XML payloads into HART string fields would find this. This also demonstrates that HART parsing code paths can be more complex than expected -- what looks like a simple string field actually passes through XML processing.

---

## Excluded CVEs (Failed Fuzzer Test)

The following HART/WirelessHART CVEs were evaluated but excluded because they are not parsing bugs that a protocol fuzzer would find:

| CVE ID | Product | Reason for Exclusion |
|--------|---------|---------------------|
| CVE-2020-12030 | Emerson WirelessHART Gateway 1410/1420/1552WU | Firewall disabled when VLAN enabled -- configuration/logic flaw, not parsing |
| CVE-2021-42539 | Emerson WirelessHART Gateway | Missing permission validation on backup restore -- auth bypass, not parsing |
| CVE-2021-38485 | Emerson WirelessHART Gateway | Improper input validation in restore file -- file replacement via web interface, not protocol parsing |
| CVE-2021-42542 | Emerson WirelessHART Gateway | Directory traversal in backup handling -- web app bug, not HART protocol parsing |
| CVE-2021-42540 | Emerson WirelessHART Gateway | Improper input validation in restore -- web interface, not protocol |
| CVE-2021-42538 | Emerson WirelessHART Gateway | Parameter injection via passphrase -- logic flaw |
| CVE-2021-42536 | Emerson WirelessHART Gateway | Information disclosure (global variables readable) -- access control flaw |
| CVE-2021-34565 | Pepperl+Fuchs WirelessHART-Gateway | Hard-coded SSH/telnet credentials -- default credential issue |
| CVE-2021-34562 | Pepperl+Fuchs WirelessHART-Gateway | Path traversal in filename parameter -- web app bug |
| CVE-2019-13923 | Siemens IE-WSN-PA Link WirelessHART Gateway | Cross-site scripting -- client-side web bug |
| CVE-2014-9206 | Schneider Electric Invensys SRD DTM | Stack overflow via malformed DLL file -- local file, requires user to load DLL, not network |

## Ecosystem Context

### The CodeWrights Supply Chain Problem

The HART ecosystem's most significant vulnerability pattern is the CodeWrights GmbH supply chain. CodeWrights produced the dominant DTM library (DTMStudio) used by the majority of HART device manufacturers. When Bolshev's team found a buffer overflow in this library (CVE-2014-9191), the single bug affected:

- **24+ vendors** (ABB, Emerson, Honeywell, Endress+Hauser, Yokogawa, GE, MACTek, Pepperl+Fuchs, Magnetrol, Schneider Electric, and more)
- **750+ device models** (flow meters, pressure transmitters, temperature transmitters, level sensors, valve positioners, etc.)
- **10 separate CISA advisories** published between January and August 2015

Any fuzzing effort targeting HART should consider that many implementations share common parsing code from CodeWrights, and bugs found in one vendor's DTM may exist identically in others.

### hipserver: The HART-IP Reference SDK

Similarly, the FieldComm Group's hipserver is the reference implementation for HART-IP. CVE-2020-16209 showed that the reference code had systemic unsafe memory operations. Any vendor that built their HART-IP product on hipserver v3.6.1 or earlier inherited these buffer overflow vulnerabilities. The fix in v3.7.0 replaced every unsafe C function call with safestringlib alternatives, which means the entire pre-fix codebase should be considered vulnerable.

### Attack Surface Summary

| Vector | Protocol | Port/Medium | Fuzzer Applicable |
|--------|----------|------------|-------------------|
| HART-IP server | HART-IP | TCP/UDP 5094 | Yes -- fuzz HART-IP header + command payloads |
| DTM response parsing | Classic HART / HART-IP | 4-20mA loop / via gateway | Yes -- fuzz HART response packets (requires man-on-the-bus or compromised device) |
| WirelessHART gateway | WirelessHART | 2.4 GHz 802.15.4 / management interface | Mixed -- protocol parsing yes, web UI no |
| Engineering workstation | FDT/DTM | Via HART responses | Yes -- fuzz from device side toward master |
