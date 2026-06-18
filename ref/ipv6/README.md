# IPv6 - Reference Materials

## Protocol Overview

IPv6 (RFC 8200) is the successor to IPv4 with 128-bit addresses and extension header chains.

- **Header**: 40 bytes fixed. Version (4) + Traffic Class (8) + Flow Label (20) + Payload Length (16) + Next Header (8) + Hop Limit (8) + Src (128) + Dst (128)
- **Extension Headers**: Hop-by-Hop, Routing, Fragment, Destination Options, AH, ESP
- **Extension Header Chain**: Next Header field in each header points to next

## Wireshark Dissectors

- **IPv6**: [packet-ipv6.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ipv6.c)

## Common Parsing Vulnerabilities

1. **Extension Header Chain**: Very long chains, loops, unknown next header values
2. **Fragment Header**: Same attacks as IPv4 fragmentation but with 32-bit identification
3. **Routing Header Type 0**: Deprecated due to amplification (RFC 5095), but some stacks still process
4. **Hop-by-Hop Options**: TLV options with length > remaining header, unknown option types with action bits
5. **Payload Length**: 0 (jumbogram) with Hop-by-Hop Jumbo Payload option, mismatch with actual data
6. **Destination Options**: Padding options with incorrect lengths

## Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS |
|--------|-----------------|-------------|------|------|
| CVE-2021-24086 | Windows TCP/IP | IPv6 fragment reassembly DoS | DoS | 7.5 |
| CVE-2020-16898 | Windows TCP/IP | "Bad Neighbor" ICMPv6 Router Advertisement option overflow | RCE | 9.8 |
| CVE-2020-16899 | Windows TCP/IP | ICMPv6 Router Advertisement DoS variant | DoS | 7.5 |
| CVE-2021-24074 | Windows TCP/IP | IPv6 extension header RCE | RCE | 9.8 |
| CVE-2023-0461 | Linux Kernel | ULP socket use-after-free via TLS context, local privilege escalation | UAF / LPE | 7.8 |
| CVE-2024-38063 | Windows TCP/IP (tcpip.sys) | Integer underflow in Ipv6pReceiveFragment, heap overflow via crafted fragments | RCE | 9.8 |
| CVE-2024-56644 | Linux Kernel | dst object leak in ip6_negative_advice() for expired IPv6 exception routes | Memory Leak | 4.7 |

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **THC-IPv6** | Comprehensive IPv6 attack toolkit including fuzz_ip6, alive6, and exploit modules | [github.com/vanhauser-thc/thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) |
| **Scapy** | Python packet crafting with full IPv6 extension header chain support | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **CVE-2024-38063 PoC** | Working exploit for Windows tcpip.sys IPv6 fragment processing RCE | [github.com/ynwarcs/CVE-2024-38063](https://github.com/ynwarcs/CVE-2024-38063) |
| **mitm6** | IPv6 MITM tool that exploits default Windows DHCPv6 configuration | [github.com/dirkjanm/mitm6](https://github.com/dirkjanm/mitm6) |

## Attack Surface Notes

- **CVE-2024-38063 is wormable**: The Windows tcpip.sys IPv6 fragment processing bug (CVSS 9.8) requires zero user interaction. Attacker sends crafted IPv6 packets, triggers integer underflow in fragment offset calculation leading to heap overflow. IPv6 is enabled by default on all Windows systems. Multiple working PoCs exist on GitHub.
- **Extension header chains are the prime target**: Windows has had 4+ critical bugs in extension header processing (CVE-2020-16898, CVE-2021-24074, CVE-2021-24086, CVE-2024-38063). The chain-walking logic is inherently complex and error-prone.
- **IPv6 is enabled by default everywhere**: Windows, Linux, and macOS all enable IPv6 by default. Many administrators are unaware it is active, creating a shadow attack surface.
- **THC-IPv6 toolkit** provides ready-made tools for IPv6 multicast probing, router advertisement spoofing, extension header fuzzing, and known exploit reproduction.
- **Linux kernel IPv6 code is actively churn**: 5,530 kernel CVEs in 2025 alone; the IPv6 stack sees constant refactoring, introducing regression bugs like CVE-2024-56644 (dst leak in negative advice path).
