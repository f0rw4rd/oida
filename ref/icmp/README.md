# ICMP / ICMPv6 - Reference Materials

## Protocol Overview

ICMP (RFC 792) and ICMPv6 (RFC 4443) are control protocols for IP. ICMP provides error reporting, diagnostics (ping/traceroute), and path MTU discovery. ICMPv6 adds Neighbor Discovery, Router Advertisement, and is mandatory for IPv6 operation.

- **ICMPv4**: IP Protocol 1. Type (1) + Code (1) + Checksum (2) + Type-specific data (4+)
- **ICMPv6**: IP Protocol 58. Same format but many additional types for IPv6 operations
- **Key ICMPv4 Types**: Echo Request/Reply (8/0), Dest Unreachable (3), Redirect (5), Time Exceeded (11)
- **Key ICMPv6 Types**: Echo (128/129), Router Solicitation/Advertisement (133/134), Neighbor Solicitation/Advertisement (135/136)

## Wireshark Dissectors

- **ICMPv4**: [packet-icmp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-icmp.c)
- **ICMPv6**: [packet-icmpv6.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-icmpv6.c)

## Common Parsing Vulnerabilities

### ICMPv4
1. **Dest Unreachable with Embedded Packet**: Original IP header + 8 bytes of payload - malformed embedded header
2. **Redirect**: Gateway address pointing to attacker-controlled host
3. **Echo Data**: Very large echo payload (Ping of Death, historically)
4. **PMTUD**: Crafted "Fragmentation Needed" with small MTU values

### ICMPv6
1. **Router Advertisement Options**: RDNSS, DNSSL, Prefix Info with malformed TLV
2. **Neighbor Discovery**: NA/NS with crafted Target Link-Layer Address option
3. **"Bad Neighbor" (CVE-2020-16898)**: Router Advertisement with recursive DNS option length overflow
4. **Option TLV Parsing**: Length=0 causing infinite loop, length > remaining data

## Notable CVEs

| CVE ID | Product | Description | Type | CVSS |
|--------|---------|-------------|------|------|
| CVE-2020-16898 | Windows | ICMPv6 RA option heap overflow ("Bad Neighbor") | RCE | 9.8 |
| CVE-2020-16899 | Windows | ICMPv6 RA DoS | DoS | 7.5 |
| CVE-2018-4407 | Apple XNU | ICMP/TCP options heap overflow | RCE | 8.8 |
| CVE-2020-27618 | glibc | ICMP-related resolver processing issue | DoS | 5.5 |
| CVE-2021-20322 | Linux Kernel | ICMP rate limiting side channel for DNS poisoning | Info Disclosure | 7.4 |
| CVE-2023-23415 | Windows | ICMP parsing RCE via fragmented error packet with embedded IP header | RCE | 9.8 |
| CVE-2024-47678 | Linux Kernel | ICMP rate limiting bypass, host-wide limit before per-dest check | Side Channel | 5.5 |

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Scapy** | Full ICMP/ICMPv6 packet crafting including RA options, NDP, and error messages | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **THC-IPv6** | Includes ICMPv6 RA spoofing, NDP attacks, and flood tools | [github.com/vanhauser-thc/thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) |
| **ICMPFuzzer** | ISLa-based grammar fuzzer for ICMP protocol targeting ping implementations | [github.com/rindPHI/ICMPFuzzer](https://github.com/rindPHI/ICMPFuzzer) |
| **Fuzzowski** | NCC Group network protocol fuzzer with ICMP support | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |

## Attack Surface Notes

- **CVE-2023-23415 (Windows ICMP RCE, CVSS 9.8)**: Windows parses ICMP error messages containing embedded IP headers. When the embedded packet is fragmented, the parser reads past the end of the fragment buffer. Requires a raw TCP/IP socket listener on target (port sniffer, network monitor, etc.). No public PoC available yet, but the attack vector is well-understood.
- **ICMP rate limiting is a side channel**: Both Linux (CVE-2021-20322, CVE-2024-47678) rate limiting implementations leak information. The host-wide ICMP rate limit is checked before per-destination limits, allowing off-path attackers to infer connection state and poison DNS caches.
- **ICMPv6 Router Advertisements are mandatory attack surface**: IPv6 networks require RA processing. The "Bad Neighbor" bug (CVE-2020-16898) showed that a single malformed RA option (recursive DNS with crafted length) achieves RCE on Windows. Any ICMPv6 RA option TLV with length=0 can cause infinite loops in parsers.
- **PMTUD manipulation**: Crafted "Packet Too Big" / "Fragmentation Needed" messages with artificially small MTU values can force fragmentation of all traffic on a path, enabling fragment-based attacks or DoS.
- **Embedded headers in error messages**: ICMP Destination Unreachable, Time Exceeded, and Redirect all embed the original IP header + 8 bytes. Malformed embedded headers are a distinct parsing surface from normal packet processing.
