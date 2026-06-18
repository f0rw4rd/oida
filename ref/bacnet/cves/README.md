# BACnet - Notable CVEs

CVEs related to parsing and processing vulnerabilities in BACnet implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-12480 | BACnet Stack (open source) through 0.8.6 | Segmentation fault in APDU layer from malformed DCC in AtomicWriteFile, AtomicReadFile, and DeviceCommunicationControl services (invalid read in bacdcode.c during tag number parsing) | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-12480) |
| CVE-2018-10238 | BACnet Stack (open source) 0.8.5 / 0.9.1 | Buffer overflow in bvlc.c BVLC forwarded NPDU handling due to lack of packet-size validation; bvlc_bdt_forward_npdu() copies request into stack frame and clobbers canary | Buffer Overflow | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-10238) |
| CVE-2026-26264 | BACnet Stack (open source) before 1.5.0rc4 / 1.4.3rc2 | Malformed WriteProperty request triggers length underflow in wp.c wp_decode_service_request when decoding optional priority context tag without validating apdu_size <= apdu_len, causing OOB read and crash | DoS / OOB Read | 7.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-26264) |
| CVE-2021-41545 | Siemens Desigo DXR2, PXC3, PXC4, PXC5 | Crafted BACnet protocol packet causes exception in BACnet communication function, leading to "out of work" state and potential factory reset | DoS | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-22-132-10) |

## Key Vulnerability Patterns for Fuzzing

1. **ASN.1 TLV Encoding**: Context-tagged values with wrong length/type combinations; extended tags (>14); deeply nested constructed types
2. **BVLL Length Mismatch**: BVLL length field != actual UDP payload size
3. **NPDU Routing Fields**: DLEN/SLEN combined with DNET/SNET create variable-size headers - incorrect lengths shift all subsequent parsing
4. **Segmentation Attacks**: Segmented APDUs with sequence gaps, overlapping segments, or never-completing sequences
5. **ReadPropertyMultiple**: Large numbers of property references in a single request exhaust memory
6. **Object ID Encoding**: 10-bit type + 22-bit instance packed in 4 bytes - bit manipulation errors at boundaries
7. **Priority Array Writes**: WritePriority values outside 1-16 range
8. **DeviceCommunicationControl**: Unauthenticated service can disable device communication

## Exploits and PoCs

### CVE-2019-12480
- **Product**: BACnet Protocol Stack (open source) through v0.8.6
- **Type**: Segmentation Fault / DoS
- **CVSS**: 7.5 (v3.1)
- **Server-side**: Yes -- malformed DCC (DeviceCommunicationControl) in AtomicWriteFile, AtomicReadFile, and DeviceCommunicationControl services causes segfault in APDU layer
- **Root cause**: Invalid read in bacdcode.c during parsing of alarm tag numbers. The ASN.1 tag number decoding does not validate that sufficient bytes remain in the APDU before reading, causing an out-of-bounds read and segfault
- **PoC**: [Exploit-DB #47148](https://www.exploit-db.com/exploits/47148) -- Python PoC by mmorillo
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-12480), [Analysis Blog](https://1modm.github.io/CVE-2019-12480.html)
- **Analysis**: This is a textbook fuzzing find -- malformed ASN.1 tags in BACnet services crash the bacserv daemon. The PoC is publicly available on Exploit-DB. Fixed in version 0.8.7.

### CVE-2018-10238
- **Product**: BACnet Protocol Stack (open source) bacserv v0.9.1 and v0.8.5
- **Type**: Stack-based Buffer Overflow
- **CVSS**: 9.8 (v3.1)
- **Server-side**: Yes -- BVLC forwarded NPDU handling overflows stack buffer due to lack of packet-size validation
- **Root cause**: In bvlc.c, the function bvlc_bdt_forward_npdu() calls bvlc_encode_forwarded_npdu() which copies content from the incoming request into a local buffer on the stack frame without checking the request size. Oversized requests clobber the stack canary and overwrite the return address.
- **PoC**: No public exploit code, but the vulnerability is well-documented with the exact functions and code paths identified
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-10238)
- **Analysis**: Classic stack buffer overflow from missing length validation. Requires BBMD (BACnet Broadcast Management Device) to be enabled. A fuzzer sending oversized BVLC Forwarded-NPDU packets directly triggers this. The attack vector requires the BACnet/IP device to have BBMD enabled and be connected to an IP network.

### CVE-2026-26264
- **Product**: BACnet Protocol Stack (open source) before v1.5.0rc4 / v1.4.3rc2
- **Type**: Length Underflow / OOB Read / DoS
- **CVSS**: 7.8
- **Server-side**: Yes -- malformed WriteProperty request triggers length underflow in wp.c during optional priority context tag decoding
- **Root cause**: In wp_decode_service_request(), when decoding the optional priority context tag, the code passes `apdu_len - apdu_size` to bacnet_unsigned_context_decode without validating that `apdu_size <= apdu_len`. If a truncated APDU reaches this path, the subtraction underflows (producing a very large unsigned value), leading to an out-of-bounds read and crash.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-26264)
- **Analysis**: Integer underflow in length calculation -- a very common bug class found by fuzzers. Sending WriteProperty requests with truncated APDUs that reach the priority tag parsing code path triggers this. Fixed in v1.5.0rc4 and v1.4.3rc2.

### CVE-2021-41545
- **Product**: Siemens Desigo DXR2, PXC3, PXC4, PXC5
- **Type**: Unhandled Exception / DoS
- **CVSS**: 7.5 (v3.1)
- **Server-side**: Yes -- crafted BACnet protocol packet causes exception in BACnet communication function, leading to "out of work" state and potential factory reset
- **Root cause**: BACnet communication function does not properly handle malformed packet structures, causing an unhandled exception that puts the device in an inoperable state
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-22-132-10](https://www.cisa.gov/news-events/ics-advisories/icsa-22-132-10)
- **Analysis**: Affects Siemens building automation controllers. A single malformed BACnet packet can render the device inoperable, potentially requiring factory reset. This demonstrates how BACnet parsing flaws in building automation can have severe operational impact.

### CVE-2025-40556
- **Product**: Siemens BACnet ATEC 550-440, 550-441, 550-445 (all versions)
- **Type**: Improper Input Validation / DoS
- **CVSS**: 6.5 (v3.1) / 7.1 (v4.0)
- **Server-side**: Yes -- specially crafted BACnet MSTP message causes device DoS requiring power cycle
- **Root cause**: Improper handling of specific incoming BACnet MSTP messages; the device does not validate MSTP frame content properly
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA Advisory ICSA-25-135-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-135-03), [Siemens SSA-828116](https://cert-portal.siemens.com/productcert/html/ssa-828116.html)
- **Analysis**: Recent (2025) vulnerability in BACnet MSTP devices. Requires attacker to be on the same BACnet network. MSTP framing validation is a less-tested attack surface compared to BACnet/IP.

### BACnet Test Server 1.01 (Exploit-DB #48860)
- **Product**: BACnet Test Server 1.01 (Windows)
- **Type**: Remote DoS
- **CVSS**: N/A
- **Server-side**: Yes -- crafted packet crashes the BACnet test server
- **Root cause**: Insufficient validation of incoming BACnet packets
- **PoC**: [Exploit-DB #48860](https://www.exploit-db.com/exploits/48860)
- **Metasploit**: N/A
- **Advisory**: [Zero Science Lab ZSL-2020-5597](https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5597.php)
- **Analysis**: While this is a test server rather than production firmware, the PoC demonstrates BACnet parsing weaknesses that commonly exist in production implementations.
