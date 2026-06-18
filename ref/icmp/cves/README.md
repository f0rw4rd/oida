# ICMP / ICMPv6 - Notable CVEs

| CVE ID | Product | Description | Type | CVSS | Link |
|--------|---------|-------------|------|------|------|
| CVE-2020-16898 | Windows | ICMPv6 RA option heap overflow ("Bad Neighbor") | RCE | 9.8 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-16898) |
| CVE-2020-16899 | Windows | ICMPv6 RA DoS variant | DoS | 7.5 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-16899) |
| CVE-2018-4407 | Apple XNU | ICMP/TCP options heap overflow via malformed packet header | RCE | 8.8 | [Apple Security](https://support.apple.com/en-us/HT209193) |
| CVE-2021-20322 | Linux Kernel | ICMP rate limiting side channel enables off-path DNS cache poisoning | Info Disclosure | 7.4 | [Linux Kernel](https://git.kernel.org/) |
| CVE-2023-23415 | Windows | ICMP parsing RCE via fragmented error packet with embedded IP header | RCE | 9.8 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23415) |
| CVE-2024-47678 | Linux Kernel | ICMP rate limiting bypass - host-wide limit applied before per-destination check | Side Channel | 5.5 | [Vulert Advisory](https://vulert.com/vuln-db/debian-11-linux-172886) |

## Key Fuzzing Targets

1. **ICMPv6 Router Advertisement Options**: TLV with length=0 (infinite loop), RDNSS/DNSSL with crafted lengths
2. **Embedded IP Headers**: ICMP error messages contain original IP header - malformed embedded headers
3. **Echo Payload**: Oversized payloads, fragmented echo requests
4. **Redirect Gateway**: ICMP Redirect with gateway address manipulation
5. **PMTUD**: Fragmentation Needed/Packet Too Big with MTU values < minimum
6. **Neighbor Discovery**: Target addresses with special scope (link-local, multicast, loopback)
7. **Fragmented ICMP Error Packets**: ICMP error containing a fragmented IP packet reads past end of fragment buffer (CVE-2023-23415 pattern)
8. **Rate Limiting Side Channels**: ICMP rate limiting implementation leaks information about active connections (CVE-2021-20322, CVE-2024-47678)
