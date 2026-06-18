# mDNS - Notable CVEs

CVEs related to parsing and processing vulnerabilities in mDNS implementations, relevant to fuzzing.

## Summary Table

| CVE ID | Affected Product | Description | Type | CVSS | Fuzzer-Triggerable | Link |
|--------|-----------------|-------------|------|------|-------------------|------|
| CVE-2007-2386 | Apple mDNSResponder (Mac OS X 10.4-10.4.9) | Buffer overflow via crafted UPnP IGD Location header | Buffer Overflow / RCE | 9.4 | Yes (network) | [CERT/CC VU#221876](https://www.kb.cert.org/vuls/id/221876) |
| CVE-2008-5081 | Avahi (before 0.6.24) | Assertion failure on mDNS packet with source port 0 | DoS (Assertion) | 5.0 | Yes (network) | [ExploitDB 7520](https://www.exploit-db.com/exploits/7520) |
| CVE-2015-7987 | Apple mDNSResponder (before 625.41.2) | Multiple buffer overflows in DNS record parsing functions | Buffer Overflow / OOB R/W | 9.8 | Yes (network) | [CERT/CC VU#143335](https://www.kb.cert.org/vuls/id/143335) |
| CVE-2015-7988 | Apple mDNSResponder (before 625.41.2) | NULL pointer dereference in handle_regservice_request | NULL Deref / RCE | 9.8 | Yes (network) | [CERT/CC VU#143335](https://www.kb.cert.org/vuls/id/143335) |
| CVE-2021-1439 | Cisco Aironet Access Points | Buffer overflow in mDNS gateway from insufficient input validation | Buffer Overflow / DoS | 7.4 | Yes (network) | [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aironet-mdns-dos-E6KwYuMx) |
| CVE-2026-24401 | Avahi (through 0.9-rc2) | Stack exhaustion via self-referential CNAME in mDNS response | DoS (Stack Exhaustion) | 6.5 | Yes (network) | [GitHub Advisory](https://github.com/avahi/avahi/security/advisories/GHSA-h4vp-5m8j-f6w3) |
| CVE-2017-6519 | Avahi (through 0.6.32 and 0.7) | mDNS daemon responds to non-local IPv6 queries enabling amplification | DoS / Amplification | 9.1 | No (design flaw) | [Avahi Issue](https://github.com/lathiat/avahi/issues/203) |
| CVE-2023-38469 | Avahi | Reachable assertion in avahi_dns_packet_append_record via overly long TXT record | DoS (Assertion) | 5.5 | No (D-Bus only) | [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-38469) |
| CVE-2023-38470 | Avahi | Reachable assertion in avahi_escape_label via crafted label | DoS (Assertion) | 5.5 | No (D-Bus only) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-38470) |
| CVE-2023-38471 | Avahi | Reachable assertion in dbus_set_host_name via escaped dot hostname | DoS (Assertion) | 5.5 | No (D-Bus only) | [Ubuntu Advisory](https://ubuntu.com/security/CVE-2023-38471) |
| CVE-2023-38472 | Avahi | Reachable assertion in avahi_rdata_parse via empty record data | DoS (Assertion) | 5.5 | No (D-Bus only) | [Avahi Issue #452](https://github.com/avahi/avahi/issues/452) |
| CVE-2023-38473 | Avahi | Reachable assertion in avahi_alternative_host_name via crafted hostname | DoS (Assertion) | 5.5 | No (D-Bus only) | [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-38473) |
| CVE-2023-1981 | Avahi | Daemon crash via D-Bus call when service not found | DoS (Assertion) | 5.5 | No (D-Bus only) | [Avahi Issues](https://github.com/avahi/avahi/issues/503) |
| CVE-2024-52615 | Avahi | Wide-area DNS uses constant source port, enabling DNS spoofing | DNS Spoofing | 5.3 | No (design flaw) | [GitHub Advisory](https://github.com/avahi/avahi/security/advisories/GHSA-x6vp-f33h-h32g) |
| CVE-2024-52616 | Avahi | Sequential/predictable DNS transaction IDs, enabling DNS spoofing | DNS Spoofing | 5.3 | No (design flaw) | [GitHub Advisory](https://github.com/avahi/avahi/security/advisories/GHSA-r9j3-vjjh-p8vm) |

**Note on the 2023 Avahi assertion CVEs**: CVE-2023-38469 through CVE-2023-38473 and CVE-2023-1981 are all reachable assertion bugs triggered via the Avahi D-Bus interface by local unprivileged users (e.g., `avahi-publish`, `avahi-resolve`, `busctl`). They are NOT triggerable by sending crafted mDNS packets on the network wire. A network fuzzer sending multicast UDP to port 5353 will not reach these code paths. They are included in the table for completeness but excluded from the detailed writeups below.

**Note on CVE-2024-2699**: The original table listed CVE-2024-2699 for the Avahi CNAME recursion bug. This CVE ID does not exist on NVD. The correct identifier is CVE-2026-24401, assigned via the GitHub Security Advisory GHSA-h4vp-5m8j-f6w3.

---

## Detailed Writeups (Network-Triggerable Parsing Bugs)

### CVE-2007-2386
- **Product**: Apple mDNSResponder, Mac OS X 10.4 through 10.4.9
- **Type**: Buffer Overflow / RCE
- **CVSS**: 9.4 (CVSSv2, from NVD)
- **Server-side**: Yes -- mDNSResponder parses UPnP Internet Gateway Device (IGD) discovery responses received over the local network
- **Root cause**: The mDNSResponder daemon includes a UPnP IGD client that processes SSDP-style HTTP responses for automatic port mapping. The Location header value from a UPnP response is copied into a fixed-size buffer via `strlcpy` without adequate bounds checking. A crafted Location URL longer than the buffer (approximately 21,000 bytes of padding needed) overwrites adjacent heap/stack memory, including function pointers in the `mDNSStorage` structure. When `mDNSDaemonIdle()` later executes, it dereferences the corrupted pointer, redirecting control flow to attacker-supplied shellcode.
- **Trigger**: Send a UPnP SSDP-like response on the local network with `ST: urn:schemas-upnp-org:service:WANIPConnection:1` and an oversized `Location:` header containing approximately 21,000+ bytes. The overflow overwrites a magic value at offset 20 and a function pointer at offset 44 in the mDNSStorage structure. The exploit must maintain a TCP connection for the code path to complete.
- **PoC**: [ExploitDB 16871](https://www.exploit-db.com/exploits/16871) (Metasploit module mirror)
- **Metasploit**: `exploit/osx/mdns/upnp_location`
- **Advisory**: [CERT/CC VU#221876](https://www.kb.cert.org/vuls/id/221876), [Apple Security Update 2007-005](https://support.apple.com/en-us/102063)
- **Analysis**: This is a classic buffer overflow in an ancillary protocol handler embedded in the mDNS daemon. The key insight for fuzzers is that mDNS implementations often include non-obvious additional attack surface beyond pure DNS wire format parsing -- UPnP, DNS-SD browsing, and HTTP parsing for service metadata. A fuzzer targeting mDNSResponder should also fuzz UPnP/SSDP response parsing on the local network. Mutation strategy: oversized string values in HTTP-style headers, particularly the Location field. Long string mutations with embedded NUL bytes and pointer-width alignment are most effective.

### CVE-2008-5081
- **Product**: Avahi daemon, versions before 0.6.24
- **Type**: DoS (Assertion Failure)
- **CVSS**: 5.0 (CVSSv2, from NVD)
- **Server-side**: Yes -- avahi-daemon processes incoming mDNS packets on UDP port 5353 and checks the source port field
- **Root cause**: The function `originates_from_local_legacy_unicast_socket()` in `avahi-core/server.c` contains `assert(port > 0)` to validate the source port of incoming mDNS packets. When the daemon receives a UDP packet with source port 0, this assertion fails and the process calls `abort()`, terminating the daemon immediately. No bounds check or graceful error handling exists before the assertion; the code assumes all incoming UDP packets have a non-zero source port.
- **Trigger**: Send a single UDP packet to port 5353 (mDNS) with source port set to 0. The packet payload can be random bytes (1-32 bytes). The source IP can be anything, including 0.0.0.0. The Metasploit module uses raw sockets to craft a UDP packet with `udp_sport = 0` and random payload, which crashes the daemon in one shot.
- **PoC**: [ExploitDB 7520](https://www.exploit-db.com/exploits/7520) (C source, compile with `gcc cve-2008-5081.c -ldnet -o cve-2008-5081`)
- **Metasploit**: `auxiliary/dos/mdns/avahi_portzero`
- **Advisory**: [NVD CVE-2008-5081](https://nvd.nist.gov/vuln/detail/CVE-2008-5081)
- **Analysis**: A textbook example of a reachable assertion in network-facing code. The developer used `assert()` for a condition that can be controlled by external input (the UDP source port). Fuzzing strategy: mutate UDP header fields, specifically the source port. Setting source port to 0 is a trivial mutation that any transport-layer-aware fuzzer should try. This pattern recurs across many network daemons -- assertion statements that assume well-formed input in positions reachable from untrusted network data. A fuzzer that mutates transport-layer headers (not just application payload) would catch this instantly.

### CVE-2015-7987
- **Product**: Apple mDNSResponder, versions 379.27 through 625.41.1 (affects macOS, iOS, watchOS, AirPort firmware, and Android via Bonjour)
- **Type**: Buffer Overflow / OOB Read/Write
- **CVSS**: 9.8 CRITICAL (CVSSv3.1, from NVD)
- **Server-side**: Yes -- mDNSResponder parses incoming DNS resource records from network traffic in four distinct functions
- **Root cause**: Multiple buffer overflows exist in four DNS record parsing functions due to improper bounds checking (CWE-119): (1) `GetValueForIPv4Addr()` fails to validate the length of IPv4 address data before parsing, allowing reads/writes beyond the buffer; (2) `GetValueForMACAddr()` similarly trusts the length of MAC address data in DNS records; (3) `rfc3110_import()` processes DNSKEY records (RFC 3110 format) without verifying the public key data length against the buffer boundary; (4) `CopyNSEC3ResourceRecord()` copies NSEC3 record data without checking that the source data fits within the destination buffer. In all four cases, attacker-controlled length fields or record data sizes are trusted, allowing out-of-bounds memory access.
- **Trigger**: Send a DNS response (or mDNS multicast response) containing malformed resource records targeting any of the four vulnerable functions: (1) an A/AAAA record with a manipulated RDLENGTH larger than 4/16 bytes to overflow `GetValueForIPv4Addr`; (2) a TXT or custom record with MAC address data and incorrect length for `GetValueForMACAddr`; (3) a DNSKEY record with a crafted RFC 3110 public key where the exponent/modulus length exceeds the allocated buffer for `rfc3110_import`; (4) an NSEC3 record with oversized hash/bitmap data for `CopyNSEC3ResourceRecord`. The mDNSResponder daemon processes these records automatically when they arrive on the mDNS multicast address.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CERT/CC VU#143335](https://www.kb.cert.org/vuls/id/143335), [Apple HT205635](https://support.apple.com/en-us/HT205635)
- **Analysis**: This is a high-value target for DNS/mDNS fuzzers because it demonstrates that DNSSEC-related record types (DNSKEY, NSEC3) expand the attack surface of mDNS daemons significantly. Most mDNS fuzzing focuses on A, AAAA, PTR, SRV, and TXT records, but these overflows occur in less-tested record types. Mutation strategy: (1) mutate RDLENGTH fields to be larger than actual data; (2) generate DNS records with unusual types (DNSKEY type 48, NSEC3 type 50); (3) fuzz the internal structure of RDATA for these record types, particularly length-prefixed sub-fields within DNSKEY and NSEC3. Structure-aware fuzzing that understands DNS record type formats will find these bugs faster than purely random mutation.

### CVE-2015-7988
- **Product**: Apple mDNSResponder, versions before 625.41.2 (affects macOS, iOS, watchOS, AirPort firmware, and Android)
- **Type**: NULL Pointer Dereference / RCE
- **CVSS**: 9.8 CRITICAL (CVSSv3.0, from NVD)
- **Server-side**: Yes -- mDNSResponder processes incoming service registration requests from network peers
- **Root cause**: The `handle_regservice_request()` function in mDNSResponder does not properly validate input parameters before dereferencing pointers (CWE-476). When processing a service registration message with missing or malformed fields, the function dereferences a NULL pointer, leading to a crash. The NVD description indicates this can potentially be exploited for arbitrary code execution (not just DoS), suggesting the NULL dereference may be exploitable on certain platforms where NULL page mapping is possible, or that the condition leads to a more complex memory corruption scenario.
- **Trigger**: Send a crafted mDNS service registration request with missing or NULL fields that cause `handle_regservice_request()` to dereference a NULL pointer. The exact malformed fields are not publicly documented, but the function processes service name, type, domain, host, port, and TXT record data -- any of these being absent or malformed in the registration message could trigger the NULL deref.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CERT/CC VU#143335](https://www.kb.cert.org/vuls/id/143335), [Apple HT205635](https://support.apple.com/en-us/HT205635)
- **Analysis**: Found alongside CVE-2015-7987 in the same CERT/CC advisory, this NULL deref demonstrates that mDNSResponder's inter-process and inter-host service registration handling is poorly validated. Fuzzing strategy: send service registration messages (DNS-SD PTR/SRV/TXT update sequences) with systematically emptied or zeroed fields. Null-out each field one at a time: service name, service type, domain, hostname, port, TXT record. Also try zero-length strings and records with RDLENGTH=0 for each record type in the registration flow.

### CVE-2021-1439
- **Product**: Cisco Aironet Series Access Points Software (various versions)
- **Type**: Buffer Overflow / DoS
- **CVSS**: 7.4 HIGH (CVSSv3.1, from NVD)
- **Server-side**: Yes -- Cisco Aironet access points parse incoming mDNS traffic via the mDNS gateway feature
- **Root cause**: The mDNS gateway feature in Cisco Aironet access points performs insufficient input validation on incoming mDNS traffic (CWE-120, classic buffer overflow). When the access point receives a crafted mDNS packet through a wireless network configured in FlexConnect local switching mode (or through a wired network on a configured mDNS VLAN), the parser copies packet data into a fixed-size buffer without adequate length checks, causing a buffer overflow that crashes the access point and forces a reboot.
- **Trigger**: Send a crafted mDNS packet to a Cisco Aironet access point that has the mDNS gateway feature enabled, either via wireless (FlexConnect local switching mode) or via a wired mDNS VLAN. The specific malformed fields are not publicly disclosed by Cisco, but the CWE-120 classification indicates a classic "buffer copy without checking size of input" in mDNS packet parsing. Likely triggers include oversized DNS name labels, oversized RDATA sections, or record counts that cause the parser to read beyond buffer boundaries.
- **PoC**: No public PoC (found during Cisco internal security testing)
- **Metasploit**: N/A
- **Advisory**: [Cisco Security Advisory cisco-sa-aironet-mdns-dos-E6KwYuMx](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aironet-mdns-dos-E6KwYuMx)
- **Analysis**: Cisco networking equipment parsing mDNS traffic is a valuable target because access points act as mDNS gateways, bridging multicast traffic between VLANs. A buffer overflow in this path means any device on the wireless network can crash the access point by sending a single crafted mDNS packet to the multicast address 224.0.0.251:5353. Fuzzing strategy: standard DNS wire format mutations -- oversized labels (>63 bytes), names exceeding 255 bytes total, RDLENGTH values larger than available data, extremely large QDCOUNT/ANCOUNT values, and deeply nested name compression pointers. The FlexConnect local switching mode requirement suggests the bug is in the mDNS-to-unicast translation code path, so records that exercise the gateway's rewrite/forwarding logic are highest priority.

### CVE-2026-24401
- **Product**: Avahi daemon, versions 0.9-rc2 and earlier
- **Type**: DoS (Stack Exhaustion)
- **CVSS**: 6.5 MEDIUM (CVSSv3.1, from NVD)
- **Server-side**: Yes -- avahi-daemon processes unsolicited mDNS responses received on the multicast group and follows CNAME chains
- **Root cause**: The `lookup_handle_cname()` function in Avahi follows CNAME chains without detecting loops or enforcing recursion depth limits (CWE-674, Uncontrolled Recursion). When Avahi receives an mDNS response containing a CNAME record where the alias and canonical name are identical (e.g., "h.local" CNAME "h.local"), the lookup mechanism enters an infinite recursion cycle: `lookup_handle_cname()` calls `lookup_go()` calls `lookup_scan_cache()` which calls back into `lookup_handle_cname()`. This unbounded recursion exhausts the stack and crashes the daemon with a segmentation fault. The vulnerability affects record browsers where `AVAHI_LOOKUP_USE_MULTICAST` is set, including resolvers used by nss-mdns for system name resolution.
- **Trigger**: Send an unsolicited mDNS response (UDP to 224.0.0.251:5353) containing a CNAME resource record where the owner name and the RDATA (canonical name) are identical. For example: name="h.local", type=CNAME (5), class=IN, TTL=120, rdata="h.local". When a browser or resolver on the target system subsequently queries for "h.local", the cached self-referential CNAME triggers the infinite recursion. The attack requires the target to have an active record browser or resolver that processes the CNAME, which is the default configuration when nss-mdns is installed.
- **PoC**: Reproduction steps documented in [Avahi Issue #501](https://github.com/avahi/avahi/issues/501) with a test patch that injects the self-referential CNAME into the cache and triggers a host name resolver.
- **Metasploit**: N/A
- **Advisory**: [GitHub Advisory GHSA-h4vp-5m8j-f6w3](https://github.com/avahi/avahi/security/advisories/GHSA-h4vp-5m8j-f6w3), [NVD CVE-2026-24401](https://nvd.nist.gov/vuln/detail/CVE-2026-24401)
- **Analysis**: This is a classic recursion bomb via self-referential DNS records. The fix (commit 78eab31) adds recursion depth tracking. Fuzzing strategy: generate CNAME records with circular references -- A points to B, B points to A, or A points to itself. Also try longer CNAME chains (A->B->C->...->Z->A) to test depth limits. Any structure-aware DNS fuzzer should include CNAME chain generation as a mutation strategy. This pattern also applies to other record types that can cause indirect lookups (SRV, NAPTR, DNAME). A grammar-based fuzzer that understands DNS-SD service resolution chains (PTR->SRV->A/AAAA with CNAME indirection) would be most effective.

---

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2007-2386 | Metasploit module: `exploit/osx/mdns/upnp_location` (mDNSResponder UPnP overflow, RCE) | [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/osx/mdns/upnp_location/) |
| CVE-2007-2386 | ExploitDB mirror of Metasploit module | [ExploitDB 16871](https://www.exploit-db.com/exploits/16871) |
| CVE-2008-5081 | Metasploit auxiliary module: `auxiliary/dos/mdns/avahi_portzero` (source port 0 DoS) | [Rapid7 DB](https://www.rapid7.com/db/modules/auxiliary/dos/mdns/avahi_portzero/) |
| CVE-2008-5081 | C exploit source (requires libdnet) | [ExploitDB 7520](https://www.exploit-db.com/exploits/7520) |
| CVE-2026-24401 | Reproduction steps and test patch for CNAME recursion | [Avahi Issue #501](https://github.com/avahi/avahi/issues/501) |
| Avahi CVEs | Tracking issue for all unfixed Avahi CVEs since 2021 (slow patch cadence) | [Avahi Issue #503](https://github.com/avahi/avahi/issues/503) |

## Key Vulnerability Patterns for Fuzzing

1. **DNS Name Compression**: Pointer loops, pointers to invalid offsets, deeply nested compression chains. This is the single highest-value mutation target for mDNS -- the NAME:WRECK research (2021) found multiple RCE-grade bugs across four TCP/IP stacks in DNS name decompression alone.
2. **RDLENGTH Mismatches**: Record data length field inconsistent with actual record data size. CVE-2015-7987 demonstrates that mismatched RDLENGTH in DNSKEY and NSEC3 records leads to buffer overflows in mDNSResponder.
3. **Section Counts**: Header section counts (QDCOUNT, ANCOUNT, etc.) mismatched with actual records. Setting counts higher than actual records forces parsers to read past buffer boundaries.
4. **TXT Record Parsing**: Key=value pairs in TXT RDATA with length-prefixed strings, empty keys, oversized values. CVE-2023-38469 (D-Bus path) shows that oversized TXT records cause assertion failures in Avahi.
5. **CNAME Chain Recursion**: Self-referential CNAMEs and circular CNAME chains. CVE-2026-24401 demonstrates that Avahi lacks recursion depth limits when following CNAME chains from multicast responses.
6. **Unusual Record Types**: DNSKEY (48), NSEC3 (50), and other DNSSEC record types are parsed by mDNSResponder but rarely fuzzed. CVE-2015-7987 found four distinct buffer overflows in these less-tested code paths.
7. **Transport Header Mutations**: Source port 0, non-standard source addresses. CVE-2008-5081 shows that mutating UDP header fields (not just DNS payload) finds bugs that application-layer-only fuzzers miss.
8. **Service Name Encoding**: DNS-SD service names with special characters (_tcp, _udp suffixes)
9. **Cache Flush Bit**: Top bit of RRCLASS used as cache flush flag in mDNS (not in standard DNS)
10. **UPnP/SSDP Interaction**: mDNS daemons like mDNSResponder include UPnP IGD handlers. CVE-2007-2386 demonstrates that the attack surface extends beyond pure DNS parsing into HTTP-like protocol parsing embedded in the same daemon.

## Excluded CVEs (Fail Fuzzer Test)

The following CVEs from the original table are NOT network-wire-triggerable and would not be found by sending malformed mDNS packets:

- **CVE-2023-38469 through CVE-2023-38473, CVE-2023-1981**: All triggered via Avahi's local D-Bus interface (`busctl call`, `avahi-publish`, `avahi-resolve`), not via incoming mDNS multicast packets. These require local unprivileged access to the D-Bus socket.
- **CVE-2017-6519**: Design/configuration flaw -- Avahi responds to queries from non-link-local addresses. Not a parsing bug; the daemon correctly parses the packet, it just should not respond.
- **CVE-2024-52615, CVE-2024-52616**: Predictable source ports and transaction IDs. These are cryptographic/randomness weaknesses, not parsing bugs.
