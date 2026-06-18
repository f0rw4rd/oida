# SNMP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in SNMP implementations (all versions), relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2022-44792 | Net-SNMP | NULL pointer dereference in handling malformed OID in GET-NEXT | DoS | 6.5 | [Net-SNMP Advisory](https://github.com/net-snmp/net-snmp/issues) |
| CVE-2022-44793 | Net-SNMP | NULL pointer dereference in handling malformed OID in GETBULK | DoS | 6.5 | [Net-SNMP Advisory](https://github.com/net-snmp/net-snmp/issues) |
| CVE-2022-24805 | Net-SNMP | Buffer overflow in handling of INDEX in NET-SNMP-VACM-MIB | Buffer Overflow | 8.8 | [GitHub Advisory](https://github.com/net-snmp/net-snmp/security) |
| CVE-2019-20892 | Net-SNMP | Use-after-free in usm_free_usmStateReference | UAF | 6.5 | [Net-SNMP Advisory](https://sourceforge.net/p/net-snmp/bugs/) |
| CVE-2020-15862 | Net-SNMP | Privilege escalation via EXTEND MIB | Privilege Escalation | 7.8 | [Net-SNMP Advisory](https://github.com/net-snmp/net-snmp/issues) |
| CVE-2018-18066 | Net-SNMP | NULL pointer dereference in snmp_oid_compare | DoS | 7.5 | [Net-SNMP Advisory](https://sourceforge.net/p/net-snmp/bugs/2923/) |
| CVE-2017-6736 | Cisco IOS/IOS XE | SNMP buffer overflow (multiple OID-related CVEs) | Buffer Overflow / RCE | 8.8 | [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp) |
| CVE-2017-6737 | Cisco IOS/IOS XE | SNMP subsystem buffer overflow in OID handling | Buffer Overflow / RCE | 8.8 | [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp) |
| CVE-2017-6738 | Cisco IOS/IOS XE | SNMP buffer overflow in BRIDGE-MIB | Buffer Overflow / RCE | 8.8 | [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp) |
| CVE-2002-0012 | Multiple SNMP implementations | OUSPG PROTOS ASN.1 BER trap parsing overflow | Buffer Overflow / RCE | 10.0 | [CERT/CC](https://www.kb.cert.org/vuls/id/854306/) |
| CVE-2002-0013 | Multiple SNMP implementations | OUSPG PROTOS ASN.1 BER request parsing overflow | Buffer Overflow / RCE | 10.0 | [CERT/CC](https://www.kb.cert.org/vuls/id/107186/) |
| CVE-2012-6151 | Net-SNMP | AgentX sub-agent integer overflow | DoS | 5.0 | [Net-SNMP Advisory](https://sourceforge.net/p/net-snmp/bugs/) |
| CVE-2023-44487 | pysnmp | ASN.1 BER decoding vulnerability from crafted packets | DoS | 7.5 | [GitHub Advisory](https://github.com/pysnmp/pysnmp/security) |

## Exploits and PoCs

### CVE-2025-68615
- **Product**: Net-SNMP snmptrapd (all versions before 5.9.5 / 5.10.pre2)
- **Type**: Buffer Overflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- snmptrapd daemon crashes or allows code execution when processing a specially crafted SNMP trap packet; no authentication required
- **Root cause**: Buffer overflow in trap message processing within snmptrapd; crafted packet data exceeds expected buffer boundaries during parsing
- **PoC**: No public PoC (discovered by Buddurid via Trend Micro Zero Day Initiative)
- **Metasploit**: N/A
- **Advisory**: [GitHub Advisory GHSA-4389-rwqf-q9gq](https://github.com/net-snmp/net-snmp/security/advisories/GHSA-4389-rwqf-q9gq)
- **Analysis**: A fuzzer sending crafted SNMP trap messages to the snmptrapd listener (UDP port 162) with malformed ASN.1 BER-encoded variable bindings would trigger this overflow. No authentication is needed.

### CVE-2022-24805
- **Product**: Net-SNMP
- **Type**: Buffer Overflow
- **CVSS**: 8.8
- **Server-side**: Yes -- buffer overflow in handling of INDEX in NET-SNMP-VACM-MIB
- **Root cause**: INDEX handling in the VACM (View-based Access Control Model) MIB does not properly bounds-check input, allowing heap corruption
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [GitHub Security](https://github.com/net-snmp/net-snmp/security)
- **Analysis**: Fuzzing SNMP SET requests targeting VACM MIB objects with oversized or malformed INDEX values would trigger the overflow.

### CVE-2022-44792
- **Product**: Net-SNMP
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 6.5
- **Server-side**: Yes -- NULL pointer dereference when handling malformed OID in GET-NEXT requests
- **Root cause**: OID parsing does not validate for NULL conditions before dereferencing, crashing the agent on malformed GET-NEXT with specific OID patterns
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [GitHub Issues](https://github.com/net-snmp/net-snmp/issues)
- **Analysis**: Fuzzing GET-NEXT requests with malformed OID encodings (empty OIDs, truncated subidentifiers, extreme component values) would trigger the NULL dereference.

### CVE-2017-6736
- **Product**: Cisco IOS/IOS XE (IOS 12.0-15.6, IOS XE 2.2-3.17)
- **Type**: Buffer Overflow / RCE
- **CVSS**: 8.8
- **Server-side**: Yes -- SNMP subsystem buffer overflow allows authenticated remote code execution via crafted SNMP packets
- **Root cause**: Buffer overflow in SNMP OID handling within the IOS SNMP subsystem; crafted GET/SET requests with specific OIDs overflow internal buffers
- **PoC**: [github.com/artkond/cisco-snmp-rce](https://github.com/artkond/cisco-snmp-rce) (RCE for Cisco ISR 2811), [Exploit-DB #43450](https://www.exploit-db.com/exploits/43450)
- **Metasploit**: N/A
- **Advisory**: [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp)
- **Analysis**: Requires SNMP community string (v2c) or user credentials (v3). The PoC demonstrates RCE on Cisco ISR 2811 running IOS 15.1(4)M12a by sending crafted SNMP packets targeting specific OIDs.

### CVE-2002-0012 / CVE-2002-0013 (OUSPG PROTOS)
- **Product**: Multiple SNMP implementations (Cisco, 3Com, HP, Sun, Microsoft, and dozens of others)
- **Type**: Buffer Overflow / RCE
- **CVSS**: 10.0
- **Server-side**: Yes -- ASN.1 BER encoding parsing overflows in SNMP trap handling (CVE-2002-0012) and SNMP request handling (CVE-2002-0013)
- **Root cause**: Systematic ASN.1 BER parsing failures: incorrect tag/length handling, multi-byte length overflow, subidentifier encoding overflow in OIDs, and type confusion in variable bindings
- **PoC**: OUSPG PROTOS SNMP test suite (original test cases available)
- **Metasploit**: N/A
- **Advisory**: [CERT/CC VU#854306](https://www.kb.cert.org/vuls/id/854306/), [CERT/CC VU#107186](https://www.kb.cert.org/vuls/id/107186/)
- **Analysis**: The PROTOS test suite systematically mutated ASN.1 BER encoding across all SNMP packet fields. It found vulnerabilities in nearly every SNMP implementation tested, establishing ASN.1 BER parsing as the primary SNMP attack surface.

### CVE-2018-18066
- **Product**: Net-SNMP
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- NULL pointer dereference in snmp_oid_compare when handling specially crafted SNMP packets
- **Root cause**: OID comparison function does not handle NULL OID pointers, causing crash when malformed packets trigger OID comparison with uninitialized data
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [SourceForge Bug #2923](https://sourceforge.net/p/net-snmp/bugs/2923/)
- **Analysis**: Fuzzing with SNMP packets containing empty or malformed OID fields in variable bindings would trigger the NULL pointer dereference during OID comparison.

## Key Vulnerability Patterns for Fuzzing

1. **ASN.1 BER Encoding**: The OUSPG PROTOS test suite (2002) found vulnerabilities in almost every SNMP implementation - ASN.1 BER remains the richest attack surface
2. **OID Encoding**: Subidentifier overflow, extremely long OIDs, first-component packing errors
3. **Variable Binding Types**: Wrong ASN.1 type for expected value (INTEGER where OCTET STRING expected)
4. **GetBulk max-repetitions**: Large values causing massive memory allocation or response amplification
5. **SNMPv3 USM Parameters**: EngineID, EngineBoots/Time with extreme values, HMAC with wrong digest sizes
6. **Community String Length**: Extremely long community strings in v1/v2c
7. **OID with Large Components**: Subidentifiers requiring many bytes of variable-length encoding
8. **Counter64 Values**: 64-bit counters on 32-bit systems causing truncation or overflow

## Historical Note: OUSPG PROTOS

The OUSPG PROTOS SNMP test suite (2002) was one of the most impactful protocol fuzzing projects in history. It systematically fuzzed ASN.1 BER encoding in SNMP and found critical vulnerabilities in implementations from Cisco, 3Com, HP, Sun, Microsoft, and dozens of others. This demonstrated the fundamental fragility of ASN.1 BER parsing and established protocol fuzzing as a critical security practice.
