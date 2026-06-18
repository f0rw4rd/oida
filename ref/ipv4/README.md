# IPv4 - Reference Materials

## Protocol Overview

IPv4 (RFC 791) is the fourth version of the Internet Protocol, providing addressing and routing for the majority of internet traffic.

- **Header**: 20-60 bytes (IHL * 4 bytes), Version (4 bits) + IHL (4 bits) + DSCP/ECN + Total Length + ID + Flags/Fragment Offset + TTL + Protocol + Checksum + Src IP + Dst IP + Options
- **Fragmentation**: MF flag + Fragment Offset for reassembly
- **Options**: Variable-length options (Record Route, Timestamp, Loose/Strict Source Route, etc.)

## Wireshark Dissectors

- **IPv4**: [packet-ip.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ip.c)

## Open-Source Implementations

| Project | Language | Link |
|---------|----------|------|
| **Scapy** | Python | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **lwIP** | C | [savannah.nongnu.org/projects/lwip](https://savannah.nongnu.org/projects/lwip/) |

## Common Parsing Vulnerabilities

1. **IP Fragmentation**: Overlapping fragments, tiny fragments, fragment offset * 8 overflow, teardrop attack
2. **IHL Field**: IHL < 5 (minimum), IHL * 4 > Total Length, IHL indicating options beyond packet
3. **Total Length**: Total Length < IHL * 4, Total Length > actual packet
4. **IP Options**: Malformed options (Record Route, Source Route) with invalid length fields
5. **Protocol Field Dispatch**: Unknown protocol numbers, protocol vs. actual payload mismatch
6. **Checksum**: Valid checksum with corrupt data, checksum=0

## Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2020-11896 | Treck TCP/IP (Ripple20) | IP fragmentation handling RCE | RCE | 10.0 | [JSOF Ripple20](https://www.jsof-tech.com/disclosures/ripple20/) |
| CVE-2021-24086 | Windows TCP/IP | IPv4/IPv6 fragment reassembly DoS | DoS | 7.5 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24086) |
| CVE-2020-16898 | Windows TCP/IP | "Bad Neighbor" - ICMPv6/IPv6 option parsing RCE | RCE | 9.8 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-16898) |
| CVE-2018-5391 | Linux Kernel (FragmentSmack) | IP fragment reassembly CPU exhaustion | DoS | 7.5 | [Linux Kernel](https://git.kernel.org/) |
| CVE-1999-0016 | Multiple (Teardrop) | Overlapping IP fragments crash kernel | DoS | 5.0 | Historical |
| CVE-2024-20467 | Cisco IOS XE | IPv4 fragment reassembly resource mismanagement causes device reload | DoS | 8.6 | [PoC](https://github.com/saler-cve/PoC-Exploit-CVE-2024-20467) |

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Scapy** | Python packet crafting with full IPv4 support including fragment generation | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **Fragscapy** | Automated fragmentation and evasion testing via Scapy | [github.com/AMOSSYS/Fragscapy](https://github.com/AMOSSYS/Fragscapy) |
| **Fuzzowski** | Network protocol fuzzer from NCC Group, supports IP layer mutations | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |
| **EPF** | Evolutionary, coverage-guided greybox network protocol fuzzer | [github.com/fkie-cad/epf](https://github.com/fkie-cad/epf) |

## Attack Surface Notes

- **Fragment reassembly is the #1 target**: Nearly every major IP stack vulnerability (Ripple20, FragmentSmack, Teardrop, CVE-2024-20467) stems from fragment reassembly logic. Overlapping fragments, tiny fragments, and resource exhaustion during reassembly are the most productive fuzzing vectors.
- **Cisco VFR is a separate code path**: Cisco IOS XE Virtual Fragment Reassembly has its own bugs distinct from normal reassembly (CVE-2024-20467). PoC available on GitHub.
- **Embedded stacks are weakest**: Treck TCP/IP (Ripple20) showed that embedded/IoT IP stacks have far less hardened fragment handling than Linux/Windows kernels.
- **IP Options are rarely tested**: Source Route, Record Route, and Timestamp options are often parsed but rarely exercised in production, making them fertile fuzzing ground.
- **Checksum offloading creates edge cases**: When NIC handles checksums, the kernel may skip validation, allowing corrupt packets to reach upper layers in some configurations.
