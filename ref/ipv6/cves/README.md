# IPv6 - Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2024-38063 | Windows TCP/IP (tcpip.sys) | Integer underflow in Ipv6pReceiveFragment causes heap overflow via crafted fragment extension headers | RCE | 9.8 | [PoC](https://github.com/ynwarcs/CVE-2024-38063) |
| CVE-2021-24086 | Windows TCP/IP | IPv6 fragment reassembly DoS | DoS | 7.5 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24086) |
| CVE-2021-24074 | Windows TCP/IP | IPv6 extension header processing RCE | RCE | 9.8 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24074) |
| CVE-2020-16898 | Windows TCP/IP | "Bad Neighbor" - ICMPv6 Router Advertisement option heap overflow | RCE | 9.8 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-16898) |
| CVE-2020-16899 | Windows TCP/IP | ICMPv6 Router Advertisement DoS variant | DoS | 7.5 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-16899) |
| CVE-2024-56644 | Linux Kernel | dst object leak in ip6_negative_advice() for expired IPv6 exception routes | Memory Leak | 4.7 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-56644) |

## Key Fuzzing Targets

1. **Extension Header Chains**: Long chains, circular references via Next Header, mixing incompatible headers
2. **Fragment Reassembly**: 32-bit ID overlap, atomic fragments, overlapping fragments (RFC 5722 prohibits but some stacks allow)
3. **Routing Headers**: Type 0 (deprecated but sometimes accepted), Type 2 (Mobile IPv6), Type 3 (SRv6)
4. **Hop-by-Hop Options**: TLV with action bits (00=skip, 01=discard, 10=discard+ICMP, 11=discard+ICMP-if-not-multicast)
5. **Payload Length 0**: Jumbogram mode requiring Jumbo Payload option in Hop-by-Hop
6. **Fragment Extension Header Offset Math**: Integer underflow when calculating non-header data length from fragment offset field (CVE-2024-38063 pattern)
