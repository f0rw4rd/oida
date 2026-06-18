# DNS (Domain Name System) - Reference Materials

## Protocol Overview

DNS (RFC 1035) is the hierarchical naming system for translating domain names to IP addresses. DNS is a critical infrastructure protocol running on every network. The protocol uses a compact binary format with name compression via pointers.

- **Transport**: UDP port 53 (standard), TCP port 53 (zone transfers, large responses), DoT port 853, DoH port 443
- **Header**: ID (2) + Flags (2) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2) = 12 bytes
- **Sections**: Question, Answer, Authority, Additional
- **Record Types**: A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, PTR, DNSKEY, RRSIG, NSEC, etc.

## Wireshark Dissectors

- **DNS**: [packet-dns.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dns.c)
- Comprehensive RR type parsing (200+ types)
- Name compression (pointer) handling
- EDNS0 OPT record parsing
- DNSSEC record parsing

### Key dissector details:
- DNS name decompression with pointer loop detection
- RR type dispatch table for type-specific data parsing
- EDNS0 option parsing (client subnet, cookie, etc.)
- TCP length prefix handling for DNS over TCP
- Response code and flag interpretation

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **BIND9** | C | ISC BIND DNS server | [gitlab.isc.org/isc-projects/bind9](https://gitlab.isc.org/isc-projects/bind9) |
| **Unbound** | C | NLnet Labs recursive resolver | [github.com/NLnetLabs/unbound](https://github.com/NLnetLabs/unbound) |
| **dnspython** | Python | DNS toolkit for Python | [github.com/rthalley/dnspython](https://github.com/rthalley/dnspython) |
| **Scapy** | Python | DNS layer built-in | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **CoreDNS** | Go | Cloud-native DNS server | [github.com/coredns/coredns](https://github.com/coredns/coredns) |
| **trust-dns** | Rust | Rust DNS client/server | [github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) |
| **PowerDNS** | C++ | Authoritative DNS server | [github.com/PowerDNS/pdns](https://github.com/PowerDNS/pdns) |
| **ldns** | C | DNS library (NLnet Labs) | [github.com/NLnetLabs/ldns](https://github.com/NLnetLabs/ldns) |

## Common Parsing Vulnerabilities

### 1. Name Compression (Pointers)
- Compression pointer: 2 bytes, top 2 bits = 11, remaining 14 bits = offset
- Pointer loops (pointer pointing to itself or creating a cycle)
- Pointer to offset beyond packet boundary
- Pointer within pointer (nested compression)
- Maximum name length (255 bytes total, 63 bytes per label) violations

### 2. RR Data Length (RDLENGTH)
- 2-byte RDLENGTH field for each resource record
- RDLENGTH mismatch with actual RR-type-specific data
- RDLENGTH=0 for records requiring data
- RDLENGTH larger than remaining packet

### 3. Section Count Mismatches
- QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT vs. actual records present
- Very large counts causing allocation issues
- Count=0 with records present (or vice versa)

### 4. EDNS0 (RFC 6891)
- OPT record in Additional section with extended flags
- EDNS0 option code + length + data
- Multiple OPT records (should be exactly 0 or 1)
- Unknown option codes with large data
- UDP payload size field abuse for amplification

### 5. DNSSEC Records
- DNSKEY, RRSIG, NSEC/NSEC3, DS records with crypto data
- RRSIG signature length vs. algorithm expectations
- NSEC/NSEC3 type bitmap parsing
- DS digest length mismatches

### 6. TCP Message Framing
- 2-byte length prefix for DNS over TCP
- Length=0 or length not matching message content
- Multiple messages in single TCP connection
- Partial message handling

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **dns-fuzz-server** | C++ | Fuzzing tool for DNS full-resolvers (BIND, Unbound, PowerDNS, knot-resolver) by replying with crafted DNS messages | [github.com/sischkg/dns-fuzz-server](https://github.com/sischkg/dns-fuzz-server) |
| **dns-fuzzer** | Python | DNS fuzzer with crash detection and crash replay capability | [github.com/guyinatuxedo/dns-fuzzer](https://github.com/guyinatuxedo/dns-fuzzer) |
| **dns-fuzzing** | Binary | CZ-NIC repository of unique seed packets for DNS server fuzzing | [github.com/CZ-NIC/dns-fuzzing](https://github.com/CZ-NIC/dns-fuzzing) |
| **Metasploit DNS Fuzzer** | Ruby | DNS and DNSSEC protocol-level fuzzer module | [auxiliary/fuzzers/dns/dns_fuzzer](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/fuzzers/dns/dns_fuzzer.rb) |
| **Google security-research-pocs** | Python | PoCs for dnsmasq vulnerabilities (CVE-2017-14491 and related) | [github.com/google/security-research-pocs](https://github.com/google/security-research-pocs) |
| **dnspooq** | Python | PoC for dnsmasq cache poisoning (CVE-2020-25686, CVE-2020-25684, CVE-2020-25685) | [github.com/knqyf263/dnspooq](https://github.com/knqyf263/dnspooq) |

## Attack Surface Notes

### Server-Side Parsing Targets
- **Name compression pointers**: Self-referencing pointers, pointer chains, pointers beyond packet boundary -- fundamental attack surface for all DNS implementations
- **SIG/RRSIG record parsing**: Integer overflow in record size computation led to wormable RCE in Windows DNS (CVE-2020-1350, SigRed, CVSS 10.0)
- **DNSSEC validation**: RRSet sorting and name extraction before DNSSEC validation cause heap overflows in dnsmasq (DNSpooq CVE-2020-25681, CVE-2020-25682)
- **Response record validation**: BIND resolver too lenient in accepting unsolicited answer records, enabling cache poisoning (CVE-2025-40778, 706K+ instances vulnerable)
- **Large message parsing**: CPU exhaustion from parsing large DNS messages with many records (CVE-2023-4408)
- **DNS-over-HTTPS (DoH)**: Combines DNS and HTTP/2 attack surfaces; HTTP/2 floods exhaust DoH resolver (CVE-2024-12705)
- **PTR record name extraction**: Unbounded name extraction from PTR records causes heap overflow in dnsmasq (CVE-2017-14491)

### High-Value Fuzzing Strategies
- **Compression pointer mutations**: Generate responses with pointer loops, pointers to random offsets, and deeply nested pointer chains
- **RDLENGTH mismatches**: Set RDLENGTH to values different from actual RR data, especially for DNSSEC record types
- **Section count abuse**: QDCOUNT/ANCOUNT values that mismatch actual records present in the packet
- **DNSSEC record fuzzing**: Malformed RRSIG, DNSKEY, and NSEC/NSEC3 records trigger validation code paths with buffer handling bugs
- **Response injection**: Include extra unsolicited records in DNS responses to test caching behavior

## Notable Research

- **"DNS Cache Poisoning" (Kaminsky, 2008)** - Foundational DNS security research
- **"NXNSAttack"** - Delegation-based DDoS amplification
- **"SAD DNS"** - Side-channel DNS cache poisoning
- **"Behind the Masq" (Google Project Zero, 2017)** - Seven dnsmasq vulnerabilities including heap overflow RCE
- **"DNSpooq" (JSOF, 2021)** - Seven dnsmasq vulnerabilities: 4 buffer overflows + 3 cache poisoning
- **DNSViz** - DNSSEC validation visualization
- **CVE-2025-40778 research** - Modern cache poisoning via unsolicited answer records in BIND 9
