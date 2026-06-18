# DHCP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in DHCP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2017-14493 | dnsmasq < 2.78 | DHCPv6 stack overflow via OPTION6_CLIENT_MAC unchecked memcpy | Stack Overflow / RCE | 9.8 | [Google Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html) |
| CVE-2017-14494 | dnsmasq < 2.78 | DHCPv6 relay OOB read leaks process memory | OOB Read / Info Disclosure | 5.9 | [Google Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html) |
| CVE-2018-5732 | ISC DHCP 4.1.0-4.4.0 (dhclient) | Buffer overflow in pretty_print_option() from crafted server response | Buffer Overflow | 7.5 | [ISC Advisory](https://kb.isc.org/docs/aa-01565) |
| CVE-2018-5733 | ISC DHCP | Reference counting overflow in lease handling | DoS | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2018-5733) |
| CVE-2021-25217 | ISC DHCP 4.1-ESV-R1 to 4.4.2 | Buffer overrun from encapsulated option parsing discrepancy (on-wire vs disk) | Buffer Overrun / DoS | 7.4 | [ISC Advisory](https://kb.isc.org/docs/cve-2021-25217) |
| CVE-2022-2928 | ISC DHCP 4.1-ESV-R1 to 4.4.3 | Option refcount overflow in add_option() during lease query responses | DoS (Integer Overflow) | 6.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2022-2928) |
| CVE-2022-2929 | ISC DHCP 1.0 to 4.4.3 | Memory leak in fqdn_universe_decode() from FQDN label > 63 bytes | DoS (Memory Leak) | 6.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2022-2929) |
| CVE-2020-7844 | Samsung SmartThings Hub | DHCPv4 option parsing stack overflow | Stack Overflow / RCE | 8.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-7844) |
| CVE-2019-6470 | ISC BIND/DHCP | Double-deletion in DHCPv6 mode via BIND library interaction | DoS | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2019-6470) |
| CVE-2023-4408 | ISC BIND 9 (not Kea) | DNS message parsing CPU exhaustion (DNS bug, not DHCP) | DoS | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2023-4408) |
| CVE-2020-25681 | dnsmasq < 2.83 | Heap overflow in sort_rrset() during DNSSEC validation (DNS bug, co-deployed with DHCP) | Heap Overflow / RCE | 8.1 | [JSOF DNSpooq](https://www.jsof-tech.com/disclosures/dnspooq/) |
| CVE-2011-0997 | ISC DHCP Client 3.0.x-4.2.x | Shell metacharacter injection in hostname option (logic flaw, not parsing) | RCE | 7.5 | [ISC Advisory](https://kb.isc.org/docs/aa-00455) |
| CVE-2025-40779 | ISC Kea 2.7.1-2.7.9, 3.0.0, 3.1.0 | Assertion failure when DHCPv4 client sends specific options and no subnet matches, single-packet crash | DoS (Assertion / NULL Deref) | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2025-40779) |
| CVE-2025-11232 | ISC Kea 3.0.1, 3.1.1-3.1.2 | Assertion failure during hostname sanitizing from crafted option content | DoS (Assertion) | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2025-11232) |
| CVE-2023-49441 | dnsmasq (2.9) | Integer overflow in forward_query function | Integer Overflow / DoS | 7.5 | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2023-49441/) |

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2017-14493 | Google Security Research PoC for dnsmasq DHCPv6 stack overflow | [github.com/google/security-research-pocs](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493.py) |
| CVE-2017-14494 | Google Security Research PoC for dnsmasq DHCPv6 info leak | [github.com/google/security-research-pocs](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14494.py) |
| CVE-2017-14493 | dnsmasq < 2.78 stack overflow exploit | [Exploit-DB #42943](https://www.exploit-db.com/exploits/42943) |
| CVE-2017-14494 | dnsmasq < 2.78 information leak exploit | [Exploit-DB #42944](https://www.exploit-db.com/exploits/42944) |
| CVE-2017-14491 | dnsmasq < 2.78 heap overflow exploit (DNS, related) | [Exploit-DB #42942](https://www.exploit-db.com/exploits/42942) |
| CVE-2017-14493 | Case study and detailed stack overflow analysis in dnsmasq 2.77 DHCPv6 | [NutCrackersSecurity](https://nutcrackerssecurity.github.io/posts/dnsmasq-buffer-overflow/) |
| Google Blog | Behind the Masq: dnsmasq DNS and DHCP vulnerability research by Google | [security.googleblog.com](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html) |

---

## Detailed Writeups

The following CVEs pass the fuzzer test: "Would sending malformed/crafted bytes on the wire trigger this bug?" Only server-side (or explicitly noted client-side) parsing bugs are included. Authentication bypasses, logic flaws, design issues, and DNS-only bugs are excluded.

### CVE-2017-14493
- **Product**: dnsmasq < 2.78
- **Type**: Stack Overflow / RCE
- **CVSS**: 9.8 (NVD CVSS:3.0)
- **Server-side**: Yes -- dnsmasq DHCPv6 server parses OPTION6_CLIENT_MAC (option 79) from a DHCPv6 relay-forward message without validating the option length against the destination stack buffer size
- **Root cause**: In `rfc3315.c` (around line 207-212), when processing a DHCP6RELAYFORW message, the code extracts OPTION6_CLIENT_MAC data via `opt6_find()`. It sets `state->mac_len = opt6_len(opt) - 2` and then calls `memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len)`. The destination buffer `state->mac` is declared as `char[DHCP_CHADDR_MAX]` which is only 16 bytes. The attacker controls `opt6_len(opt)` via the option length field, so any value larger than 18 causes a stack buffer overflow with attacker-controlled data.
- **Trigger**: Send a DHCPv6 RELAY-FORW (message type 12) packet to UDP port 547 containing OPTION6_CLIENT_MAC (type 79) with a length field exceeding 18 bytes. The excess bytes overflow the 16-byte `state->mac` stack buffer.
- **PoC**: [github.com/google/security-research-pocs -- CVE-2017-14493.py](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14493.py)
- **Metasploit**: N/A
- **Advisory**: [Google Security Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html), [Exploit-DB #42943](https://www.exploit-db.com/exploits/42943), [NutCrackersSecurity Analysis](https://nutcrackerssecurity.github.io/posts/dnsmasq-buffer-overflow/)
- **Analysis**: Classic unchecked length field before memcpy into a fixed-size stack buffer. A fuzzer mutating the length byte of DHCPv6 option 79 within a RELAY-FORW message will find this immediately. The mutation strategy is straightforward: take a valid DHCPv6 relay-forward packet, locate the TLV for option 79, and inflate the length field beyond 18 while appending arbitrary payload bytes. On embedded systems without ASLR or stack canaries (common for dnsmasq deployments on routers and IoT gateways), this is directly exploitable for code execution.

### CVE-2017-14494
- **Product**: dnsmasq < 2.78
- **Type**: OOB Read / Information Disclosure
- **CVSS**: 5.9 (NVD CVSS:3.0)
- **Server-side**: Yes -- dnsmasq DHCPv6 relay code forwards memory beyond the packet buffer boundary when constructing relay responses
- **Root cause**: When dnsmasq acts as a DHCPv6 relay and forwards client messages to an upstream DHCPv6 server, it constructs the relay-forward message using data from the received packet. A crafted DHCPv6 packet causes the relay code to read beyond the bounds of the received packet buffer when assembling the forwarded message. The forwarded packet then contains up to 32KB of dnsmasq process memory that follows the original packet buffer in memory.
- **Trigger**: Send a crafted DHCPv6 packet to dnsmasq configured as a DHCPv6 relay. The malformed packet causes the relay forwarding logic to include bytes from beyond the original packet buffer. The PoC creates a `response.bin` file containing approximately 32KB of leaked process memory starting at buffer+38.
- **PoC**: [github.com/google/security-research-pocs -- CVE-2017-14494.py](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14494.py), [Exploit-DB #42944](https://www.exploit-db.com/exploits/42944)
- **Metasploit**: N/A
- **Advisory**: [Google Security Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html)
- **Analysis**: This is a Heartbleed-style OOB read where the server trusts a length value from the packet and reads beyond buffer boundaries. When chained with CVE-2017-14493, the info leak defeats ASLR and enables reliable RCE. Fuzzing with sanitizers (ASan) catches this as a heap-buffer-overflow read. The mutation strategy is to corrupt length fields in DHCPv6 relay options so the computed forwarding size exceeds the actual received data. Both CVE-2017-14493 and CVE-2017-14494 were found by Google Project Zero through systematic analysis of dnsmasq's DHCPv6 relay code path.

### CVE-2021-25217
- **Product**: ISC DHCP 4.1-ESV-R1 through 4.1-ESV-R16, 4.4.0 through 4.4.2
- **Type**: Buffer Overrun / DoS
- **CVSS**: 7.4 (NVD CVSS:3.1, ISC CNA)
- **Server-side**: Yes -- affects both dhcpd (server) and dhclient (client); the server-side path is triggered when dhcpd reads a lease file containing a lease that was written from a malformed on-wire packet
- **Root cause**: A discrepancy exists between the code that handles encapsulated option information in leases received on the wire and the code that parses lease information after it has been serialized to disk. When a DHCP packet containing crafted encapsulated options is processed, the lease data is written to the lease file. When that lease file is later re-read (e.g., on server restart), the parsing code encounters hexadecimal option data exceeding 1024 octets and triggers a buffer overwrite. On 32-bit systems compiled with `-fstack-protection-strong`, this causes an immediate crash. On 64-bit systems or without stack protection, the overwritten lease and the following lease are silently deleted.
- **Trigger**: Send a DHCP packet (DISCOVER/REQUEST) to a dhcpd server where the options section contains crafted encapsulated option data that, when serialized to the lease file, produces a hexadecimal literal longer than 1024 octets. The crash occurs when dhcpd re-reads its lease file (on restart or lease rotation).
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2021-25217), [ISC Mailing List](https://lists.isc.org/pipermail/dhcp-announce/2021-May/000431.html)
- **Analysis**: This is a two-stage bug: malformed bytes on the wire cause a poisoned lease to be written to disk, and the crash happens on re-read. Fuzzing the DHCP option parser alone may not catch this because the crash is deferred. The most effective approach is to fuzz the lease file parser directly with corpus files containing long hexadecimal option values in encapsulated option sub-fields. For on-wire fuzzing, mutate encapsulated option (e.g., option 82 sub-options or vendor-specific options) to produce extremely long serialized representations. Architecture-aware fuzzing (testing on 32-bit builds with stack protection) increases the chance of observing the crash.

### CVE-2022-2929
- **Product**: ISC DHCP 1.0 through 4.4.3, 4.1-ESV-R1 through 4.1-ESV-R16-P1
- **Type**: DoS (Memory Leak)
- **CVSS**: 6.5 (NVD CVSS:3.1, ISC CNA)
- **Server-side**: Yes -- dhcpd server parses option 81 (FQDN) from incoming DHCP packets via `fqdn_universe_decode()` which leaks memory on malformed input
- **Root cause**: The function `fqdn_universe_decode()` allocates buffer space for the contents of DHCP option 81 (FQDN) data received in a DHCP packet. The function iterates over DNS labels in the FQDN value and checks that each label's length byte does not exceed 63 (the RFC maximum for DNS labels). If a label with length > 63 is found, the function returns early WITHOUT calling `free()` or dereferencing the previously allocated buffer. Each such malformed packet permanently leaks the allocated memory.
- **Trigger**: Send repeated DHCP packets (DISCOVER or REQUEST) to the dhcpd server where option 81 (FQDN) contains a DNS name with at least one label whose length byte is set to a value greater than 63 (e.g., 0xFF). Each packet leaks a small amount of memory. Sustained sending eventually exhausts server memory.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2022-2929)
- **Analysis**: This is a classic error-path resource leak: the happy path frees memory correctly, but the validation-failure path forgets to free. A fuzzer mutating option 81 FQDN label length bytes to values > 63 will trigger the leak. Running the target under a memory leak detector (LSan, Valgrind) while fuzzing makes this trivially detectable. The mutation strategy is to take valid DHCP packets with option 81 and set individual label length bytes to values in the range 64-255. Even a dumb fuzzer flipping bytes in the FQDN option region has a reasonable chance of hitting this.

### CVE-2025-40779
- **Product**: ISC Kea 2.7.1 through 2.7.9, 3.0.0, 3.1.0
- **Type**: DoS (Assertion Failure / NULL Dereference)
- **CVSS**: 7.5 (NVD CVSS:3.1)
- **Server-side**: Yes -- kea-dhcp4 server aborts with an assertion failure when processing a unicast DHCPv4 packet containing specific options and no matching subnet is found
- **Root cause**: When a DHCPv4 client sends a unicast request with specific option combinations and Kea's subnet selection logic fails to find a matching subnet for the client, the code reaches an assertion that assumes a valid subnet pointer exists. The NULL pointer dereference triggers `abort()`. Broadcast packets do not trigger the bug because they take a different code path that handles the no-subnet case gracefully. The CWE classification is CWE-476 (NULL Pointer Dereference).
- **Trigger**: Send a unicast (not broadcast) DHCPv4 DISCOVER or REQUEST packet directly to the Kea DHCPv4 server (UDP port 67) with specific DHCP options present, while ensuring the source IP/interface combination does not match any configured subnet. A single packet is sufficient to crash the server.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2025-40779), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-40779)
- **Analysis**: Single-packet assertion crash bugs are the highest-value targets for DHCP fuzzers because they provide instant, reliable DoS. The mutation strategy is to vary DHCP option combinations in unicast packets sent from IP addresses outside configured subnets. Fuzzing Kea with different subnet configurations (including the edge case of no subnets) is critical. This type of bug -- NULL dereference on an unexpected code path -- is exactly what state-aware fuzzers with configuration variation catch. Since Kea is C++, assertion failures terminate the process immediately with no recovery.

### CVE-2025-11232
- **Product**: ISC Kea 3.0.1, 3.1.1 through 3.1.2
- **Type**: DoS (Assertion Failure)
- **CVSS**: 7.5 (NVD CVSS:3.1)
- **Server-side**: Yes -- kea-dhcp4 server crashes during hostname sanitization when processing a DHCP packet with crafted option content containing invalid characters
- **Root cause**: When the Kea DHCPv4 server has `hostname-char-set` at its default value (`[^A-Za-z0-9.-]`), `hostname-char-replacement` set to empty (default), and `ddns-qualifying-suffix` configured with a non-empty value, the hostname sanitization code encounters an assertion failure when processing DHCP packets containing hostname option data with characters that match the character set regex but cannot be replaced with an empty string. DDNS does not need to be enabled for the crash to occur. The configuration requirements are narrow but the defaults make two of the three conditions true out of the box.
- **Trigger**: Send a DHCPv4 DISCOVER or REQUEST packet to the Kea server (UDP port 67) containing option 12 (hostname) or option 81 (FQDN) with characters that are invalid per the configured `hostname-char-set` regex (e.g., shell metacharacters, control characters, non-ASCII bytes). The server must have `ddns-qualifying-suffix` set to a non-empty value.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2025-11232), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11232)
- **Analysis**: This is a configuration-dependent assertion crash triggered by malformed hostname data in DHCP options. A fuzzer that mutates option 12 (hostname) and option 81 (FQDN) with non-ASCII bytes, control characters, and shell metacharacters will trigger this when the server has the right configuration. The fix is to set `hostname-char-replacement` to any non-empty value (e.g., "x"). This illustrates why fuzzing should test multiple server configurations, not just the default. Byte-level mutation of hostname option values is the simplest strategy to find this class of bug.

### CVE-2018-5732
- **Product**: ISC DHCP dhclient 4.1.0 through 4.1-ESV-R15, 4.2.0 through 4.2.8, 4.3.0 through 4.3.6, 4.4.0
- **Type**: Buffer Overflow (Stack)
- **CVSS**: 7.5 (NVD CVSS:3.1)
- **Server-side**: No -- this is a **client-side** bug in dhclient triggered by a malicious DHCP server response. Included here because it is a parsing bug triggered by malformed bytes on the wire, and a rogue DHCP server on an ICS network can exploit DHCP clients on PLCs, HMIs, and engineering workstations.
- **Root cause**: The `pretty_print_option()` function in dhclient does not properly bounds-check the buffer used for processing DHCP options received in server responses. A malicious DHCP server (or MITM) can send a DHCPOFFER or DHCPACK with a specially constructed options section that causes dhclient to write beyond the bounds of a stack buffer during option formatting/logging.
- **Trigger**: Set up a rogue DHCP server (or intercept DHCP traffic) and send a DHCPOFFER/DHCPACK response containing a crafted options section with length/data combinations that cause `pretty_print_option()` to overflow its internal buffer. The client crashes on receipt.
- **PoC**: No public PoC (reported by Felix Wilhelm, Google Security Team)
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/aa-01565), [FortiGuard IPS](https://fortiguard.com/encyclopedia/ips/45676/isc-dhcp-dhclient-pretty-print-option-stack-buffer-overflow)
- **Analysis**: While client-side, this is highly relevant to ICS/OT environments where DHCP clients run on embedded devices without ASLR. A rogue DHCP server on a flat OT network can target every device that sends DHCPDISCOVER. Fuzzing dhclient by sending mutated DHCPOFFER responses with corrupted option length fields and oversized option data is the direct approach. The function name `pretty_print_option` suggests the overflow occurs during option formatting for display/logging, meaning even options that are syntactically processed correctly can trigger the bug during the logging step.

---

## Key Vulnerability Patterns for Fuzzing

1. **Option Length vs. Available Data**: Option length byte exceeding remaining packet data (CVE-2017-14493, CVE-2017-14494, CVE-2018-5732)
2. **Nested Options**: Relay Agent Information (option 82) and DHCPv6 IA_NA sub-options with mismatched lengths
3. **Overload Field**: sname/file field repurposing for options (option 52) confusing parsers
4. **Client ID/DUID Sizes**: Zero-length, maximum-length, and type-mismatched DUIDs
5. **Hostname Strings**: Long hostnames, null bytes, non-ASCII characters in option 12/81 (CVE-2022-2929, CVE-2025-11232)
6. **DHCPv6 Message Types**: Relay-forward/relay-reply nesting creating deep option chains (CVE-2017-14493, CVE-2017-14494)
7. **Lease Management**: Rapid DISCOVER/DECLINE cycles exhausting address pools and triggering memory bugs
8. **Option 55 (Parameter Request List)**: Very long lists of requested options
9. **Encapsulated Options**: Vendor-specific and sub-option data that serializes to long hex literals on disk (CVE-2021-25217)
10. **Subnet Selection Edge Cases**: Unicast packets with option combinations that bypass normal subnet matching (CVE-2025-40779)
11. **Configuration-Dependent Assertions**: Hostname sanitization with specific config parameter combinations (CVE-2025-11232)
