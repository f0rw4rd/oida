# DNS - Notable CVEs

CVEs related to parsing and processing vulnerabilities in DNS server implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2020-1350 | Windows DNS Server | SigRed: integer overflow in SIG record parsing causes heap buffer overflow (wormable) | Heap Overflow / RCE | 10.0 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1350) |
| CVE-2023-50387 | BIND/Unbound/PowerDNS (KeyTrap) | DNSSEC validation CPU exhaustion from crafted zones with many DNSKEY and RRSIG records | DoS | 7.5 | [KeyTrap Paper](https://www.athene-center.de/en/keytrap) |
| CVE-2023-50868 | BIND/Unbound/PowerDNS (NSEC3) | NSEC3 closest encloser proof CPU exhaustion via SHA-1 hash iterations | DoS | 7.5 | [NLnet Labs Advisory](https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/) |
| CVE-2021-25216 | ISC BIND 9 | Buffer overflow in SPNEGO/GSSAPI (TKEY) negotiation | Buffer Overflow / RCE | 9.8 | [ISC Advisory](https://kb.isc.org/docs/cve-2021-25216) |
| CVE-2020-8617 | ISC BIND 9 | Assertion failure from crafted message exploiting TSIG validity checking logic | DoS | 5.9 | [ISC Advisory](https://kb.isc.org/docs/cve-2020-8617) |
| CVE-2020-8616 | ISC BIND 9 | NXNSAttack: delegation processing amplification via crafted referrals | DoS | 8.6 | [ISC Advisory](https://kb.isc.org/docs/cve-2020-8616) |
| CVE-2022-3736 | ISC BIND 9 | Assertion failure when processing RRSIG queries with stale cache enabled | DoS | 7.5 | [ISC Advisory](https://kb.isc.org/v1/docs/cve-2022-3736) |
| CVE-2019-6477 | ISC BIND 9 | TCP pipelining DoS: pipelined queries bypass tcp-clients limit causing resource exhaustion | DoS | 7.5 | [ISC Advisory](https://kb.isc.org/docs/cve-2019-6477) |
| CVE-2017-14491 | dnsmasq | Heap overflow in DNS response handling via crafted PTR record with long extracted name | Heap Overflow / RCE | 9.8 | [Google Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html) |
| CVE-2021-20322 | Linux Kernel | Side-channel in ICMP rate limiting allows DNS cache poisoning by inferring resolver ephemeral port | Cache Poisoning | 7.4 | [SAD DNS](https://www.saddns.net/) |

## Exploits and PoCs

### CVE-2025-40778
- **Product**: ISC BIND 9 (multiple versions before 9.18.41, 9.20.15, 9.21.14)
- **Type**: DNS Cache Poisoning
- **CVSS**: 8.6
- **Server-side**: Yes -- BIND resolver is too lenient when accepting records from DNS answers, allowing injection of forged records into the cache during query processing
- **Root cause**: Insufficient validation of DNS response records allows an attacker to include unsolicited answer records that get cached, redirecting future queries to attacker-controlled addresses
- **PoC**: Public PoC released October 28, 2025; over 706,000 vulnerable instances identified via Censys scanning
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2025-40778)
- **Analysis**: A fuzzer sending DNS responses with extra unsolicited answer records would test for this lax validation. The vulnerability is in response parsing, not request parsing.

### CVE-2023-4408
- **Product**: ISC BIND 9
- **Type**: DoS (CPU Exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- parsing large DNS messages causes excessive CPU load on the resolver
- **Root cause**: Inefficient parsing algorithm for large DNS messages with many records leads to quadratic or worse CPU consumption
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [ISC Advisory](https://kb.isc.org/docs/cve-2023-4408)
- **Analysis**: Fuzzing with DNS messages containing maximum record counts and deeply nested compression pointers would trigger the CPU exhaustion.

### CVE-2020-1350 (SigRed)
- **Product**: Windows DNS Server (all versions, Server 2003 through 2019)
- **Type**: Heap Buffer Overflow / RCE (Wormable)
- **CVSS**: 10.0
- **Server-side**: Yes -- integer overflow when parsing SIG record data causes heap buffer overflow in Windows DNS Server
- **Root cause**: The DNS server computes the size of a SIG record response by adding the name length and signature length. An integer overflow in this calculation results in a small allocation followed by a large copy, causing heap overflow.
- **PoC**: [github.com/tinkersec/cve-2020-1350](https://github.com/tinkersec/cve-2020-1350), [github.com/captainGeech42/CVE-2020-1350](https://github.com/captainGeech42/CVE-2020-1350), [github.com/maxpl0it/CVE-2020-1350-DoS](https://github.com/maxpl0it/CVE-2020-1350-DoS)
- **Metasploit**: N/A
- **Advisory**: [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1350)
- **Analysis**: A fuzzer generating SIG/RRSIG records with carefully chosen name and signature lengths that cause integer overflow in size computation would trigger this. The Google security research PoCs demonstrate both DoS and RCE paths.

### CVE-2017-14491
- **Product**: dnsmasq before 2.78
- **Type**: Heap Buffer Overflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- heap overflow when handling DNS responses with crafted PTR records containing long extracted names
- **Root cause**: DNS name extraction from response packets does not properly bounds-check the output buffer, allowing a crafted DNS response to overflow the heap-allocated cache entry
- **PoC**: [github.com/google/security-research-pocs](https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14491.py) (Google Project Zero)
- **Metasploit**: `exploit/linux/misc/dnsmasq_heap_overflow`
- **Advisory**: [Google Blog](https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html)
- **Analysis**: Fuzzing DNS response parsing with long PTR record names and deeply nested compression pointers triggers the overflow. The Google PoC provides a complete exploit chain.

### CVE-2020-25682 (DNSpooq)
- **Product**: dnsmasq before 2.83
- **Type**: Buffer Overflow / RCE
- **CVSS**: 8.1
- **Server-side**: Yes -- buffer overflow in DNS name extraction from packets before DNSSEC validation, allowing heap corruption via crafted DNS replies
- **Root cause**: When DNSSEC is enabled, dnsmasq extracts names from DNS packets before validation. The extraction does not properly bounds-check, allowing a crafted response to overflow heap memory.
- **PoC**: [github.com/knqyf263/dnspooq](https://github.com/knqyf263/dnspooq) (cache poisoning PoC; buffer overflow PoC not public)
- **Metasploit**: N/A
- **Advisory**: [CERT/CC VU#434904](https://www.kb.cert.org/vuls/id/434904)
- **Analysis**: Requires DNSSEC to be enabled. Fuzzing DNSSEC-related record types (RRSIG, DNSKEY) with oversized name fields would trigger the buffer overflow.

### CVE-2020-25681 (DNSpooq)
- **Product**: dnsmasq before 2.83
- **Type**: Heap Buffer Overflow / RCE
- **CVSS**: 8.1
- **Server-side**: Yes -- heap-based buffer overflow in the way dnsmasq sorts RRSets before DNSSEC validation
- **Root cause**: RRSet sorting algorithm does not validate buffer boundaries when comparing and reordering records, leading to heap corruption
- **PoC**: No public PoC for buffer overflow (cache poisoning PoC available)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/cve-2020-25681)
- **Analysis**: Fuzzing DNSSEC RRSet data with many records requiring sorting would trigger the heap overflow during validation.

### CVE-2023-49441
- **Product**: dnsmasq 2.9
- **Type**: Integer Overflow
- **CVSS**: N/A
- **Server-side**: Yes -- integer overflow in the `forward_query` function from improper handling of integer values
- **Root cause**: Arithmetic operations on integer values in forward_query can overflow, causing unexpected behavior in query forwarding
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2023-49441/)
- **Analysis**: A fuzzer sending many queries rapidly to trigger integer overflow in query tracking counters would find this.

### CVE-2024-12705
- **Product**: ISC BIND 9 (9.18.0 through 9.18.32, 9.20.0 through 9.20.4)
- **Type**: DoS (CPU/Memory Exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- DNS-over-HTTPS (DoH) clients can exhaust resolver CPU and memory by flooding with crafted valid or invalid HTTP/2 traffic
- **Root cause**: DoH handler does not properly rate-limit or bound resource consumption from HTTP/2 stream processing
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Snyk](https://security.snyk.io/vuln/SNYK-UBUNTU2004-BIND9-8674851)
- **Analysis**: Combines DNS and HTTP/2 attack surfaces; fuzzing the DoH endpoint with malformed HTTP/2 traffic would trigger resource exhaustion.

## Key Vulnerability Patterns for Fuzzing

1. **Name Compression Pointers**: Self-referencing pointers, pointer chains, pointers to packet boundaries
2. **RDLENGTH Mismatches**: Stated RR data length vs. actual data and vs. type-specific expectations
3. **Section Counts**: QDCOUNT/ANCOUNT values that don't match actual records in packet
4. **EDNS0 OPT Records**: Extended options with incorrect lengths, multiple OPT records
5. **DNSSEC Records**: RRSIG with wrong signature length, NSEC3 hash chain abuse
6. **TCP Length Prefix**: DNS over TCP 2-byte length vs. actual message
7. **Label Length**: Individual label > 63 bytes, total name > 255 bytes
8. **RR Type-Specific Data**: Each RR type has specific data format - wrong format for type
