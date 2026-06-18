# mDNS (Multicast DNS) - Reference Materials

## Protocol Overview

mDNS (RFC 6762) enables DNS-like name resolution on local networks without a central DNS server. Used for zero-configuration networking (Bonjour, Avahi). mDNS uses the same wire format as DNS but operates over multicast.

- **Transport**: UDP port 5353, multicast address 224.0.0.251 (IPv4) / ff02::fb (IPv6)
- **Wire Format**: Identical to standard DNS (RFC 1035)
- **Top-Level Domain**: `.local` (reserved for mDNS)
- **Service Discovery**: DNS-SD (RFC 6763) over mDNS for service browsing

## Wireshark Dissectors

- **mDNS**: Uses the same [packet-dns.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dns.c) dissector as DNS
- Registered on UDP port 5353
- Same parsing logic as standard DNS

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **Avahi** | C | Linux mDNS/DNS-SD daemon | [github.com/lathiat/avahi](https://github.com/lathiat/avahi) |
| **python-zeroconf** | Python | Pure Python mDNS/DNS-SD | [github.com/python-zeroconf/python-zeroconf](https://github.com/python-zeroconf/python-zeroconf) |
| **mdns (Go)** | Go | Go mDNS library | [github.com/hashicorp/mdns](https://github.com/hashicorp/mdns) |
| **dns-sd** | C | Apple mDNSResponder | [opensource.apple.com/source/mDNSResponder](https://opensource.apple.com/source/mDNSResponder/) |

## Common Parsing Vulnerabilities

All DNS parsing vulnerabilities apply to mDNS (same wire format). Additional mDNS-specific issues:

### 1. Multicast Source Validation
- mDNS responses from unexpected source IPs
- Spoofed multicast responses for cache poisoning
- Link-local vs. non-link-local source address handling

### 2. Known-Answer Suppression
- Large known-answer sections causing truncation
- TC (Truncated) flag handling with multicast follow-up
- Known-answer records with mismatched TTLs

### 3. Conflict Resolution
- Simultaneous probe responses with different data
- Probe tiebreaking with crafted lexicographic ordering
- Rapid probe/announce flooding

### 4. Continuous Querying
- Query rate limiting abuse
- Excessive QU (unicast response requested) queries
- Cache manipulation via crafted TTL values (including TTL=0 for cache flush)

See DNS reference for complete parsing vulnerability analysis - all DNS wire-format attacks work against mDNS.

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **dns-fuzz-server** | Fuzzing tool for DNS full-resolvers; applicable to mDNS since same wire format | [github.com/sischkg/dns-fuzz-server](https://github.com/sischkg/dns-fuzz-server) |
| **dns-fuzzer** | DNS fuzzer with crash detection and crash replay capabilities | [github.com/guyinatuxedo/dns-fuzzer](https://github.com/guyinatuxedo/dns-fuzzer) |
| **dns-fuzzing (CZ-NIC)** | Curated seed corpus for DNS/mDNS server fuzzing | [github.com/CZ-NIC/dns-fuzzing](https://github.com/CZ-NIC/dns-fuzzing) |
| **Metasploit DNS Fuzzer** | DNS/DNSSEC protocol-level fuzzer module (applicable to mDNS) | [Metasploit Framework](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/fuzzers/dns/dns_fuzzer.rb) |
| **ResolFuzz** | Differential fuzzing of DNS resolvers | [github.com/dns-differential-fuzzing](https://github.com/dns-differential-fuzzing/dns-differential-fuzzing) |
| **Fuzzowski** | Generic network protocol fuzzer applicable to UDP-based protocols | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |

## Attack Surface Notes

- **Avahi assertion bugs (2023)**: Five reachable assertion vulnerabilities (CVE-2023-38469 through CVE-2023-38473) were found in Avahi's core parsing functions: avahi_dns_packet_append_record, avahi_escape_label, avahi_rdata_parse, avahi_alternative_host_name, and dbus_set_host_name. These are all triggerable by sending crafted mDNS packets on the local network. The Avahi daemon crashes and stops all .local service discovery.
- **Slow patch cadence**: Avahi has historically been very slow to release fixes. Issue #503 on the Avahi GitHub tracks CVEs that went unfixed for years. This means discovered bugs remain exploitable for extended periods in deployed systems.
- **DNS name compression pointers**: mDNS uses the same DNS wire format, so all DNS name compression attacks apply. Pointer loops, pointers to invalid offsets, and deeply nested compression chains are the highest-value fuzzing targets (Apple mDNSResponder CVE-2015-7987 buffer overflows in name parsing).
- **CNAME recursion**: CVE-2024-2699 (Avahi) shows uncontrolled recursion when processing recursive CNAMEs, leading to stack exhaustion. Recursive record processing without depth limits is a common mDNS bug pattern.
- **Predictable identifiers**: CVE-2024-52615 (constant source port) and CVE-2024-52616 (sequential transaction IDs) in Avahi enable DNS spoofing. While not parsing bugs, they demonstrate that mDNS implementations often lack basic security hardening.
- **Multicast amplification**: CVE-2017-6519 shows Avahi responding to non-link-local queries, enabling traffic amplification. Any mDNS implementation that fails to validate source scope is an amplifier.
- **Apple mDNSResponder**: The UPnP IGD code path in mDNSResponder (CVE-2007-2386) demonstrates that mDNS daemons often include non-obvious additional protocol handlers (UPnP, DNS-SD browsing) that expand the attack surface beyond pure mDNS parsing.
