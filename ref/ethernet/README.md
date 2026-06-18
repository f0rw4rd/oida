# Ethernet (Layer 2) - Reference Materials

## Protocol Overview

Ethernet (IEEE 802.3) is the foundational Layer 2 networking protocol. Fuzzing Ethernet frames targets network stacks, drivers, and embedded devices that process raw frames.

- **Frame Format**: Preamble (7) + SFD (1) + Dst MAC (6) + Src MAC (6) + EtherType/Length (2) + Payload (46-1500) + FCS (4)
- **EtherTypes**: 0x0800 (IPv4), 0x0806 (ARP), 0x86DD (IPv6), 0x8100 (802.1Q VLAN), 0x88A8 (QinQ), 0x8892 (PROFINET), 0x88B8 (GOOSE), etc.
- **802.1Q VLAN**: 4-byte VLAN tag inserted between Src MAC and EtherType
- **Jumbo Frames**: Payload up to 9000 bytes

## Wireshark Dissectors

- **Ethernet**: [packet-eth.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-eth.c)
- **802.1Q**: [packet-vlan.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-vlan.c)
- **ARP**: [packet-arp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-arp.c)
- **LLC/SNAP**: [packet-llc.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-llc.c)

## Open-Source Implementations

| Project | Language | Link |
|---------|----------|------|
| **Scapy** | Python | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **libpcap** | C | [github.com/the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap) |
| **dpdk** | C | [github.com/DPDK/dpdk](https://github.com/DPDK/dpdk) |

## Common Parsing Vulnerabilities

1. **EtherType vs. Length Ambiguity**: Values < 1536 are IEEE 802.3 length, >= 1536 are EtherType
2. **VLAN Tag Stacking**: Double/triple VLAN tags (QinQ) causing tag-stripping bypass
3. **Frame Length**: Runt frames (< 64 bytes), jumbo frames, length field vs. actual payload
4. **MAC Address Processing**: Multicast bit, broadcast (FF:FF:FF:FF:FF:FF), locally-administered
5. **LLC/SNAP**: Length-field Ethernet with LLC header - DSAP/SSAP/Control field parsing
6. **ARP**: Malformed ARP with incorrect hardware/protocol sizes, ARP cache poisoning
7. **Etherleak (Frame Padding)**: NIC drivers or firewalls padding frames with uninitialized memory instead of nulls (CVE-2003-0001, CVE-2021-3031)
8. **A-MSDU / Frame Aggregation**: QoS header flags not authenticated, enabling frame injection in encrypted networks (FragAttacks)

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Scapy** | Python packet crafting, ideal for raw L2 frame generation and mutation | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **FragAttacks** | Wi-Fi fragmentation and aggregation attack PoC toolkit | [github.com/vanhoefm/fragattacks](https://github.com/vanhoefm/fragattacks) |
| **Fragscapy** | Scapy-based tool that generates fragroute-like tests for firewall/IDS evasion | [github.com/AMOSSYS/Fragscapy](https://github.com/AMOSSYS/Fragscapy) |
| **pcrappyfuzzer** | PCAP-based fuzzing with radamsa mutation and Scapy replay | [github.com/blazeinfosec/pcrappyfuzzer](https://github.com/blazeinfosec/pcrappyfuzzer) |

## Attack Surface Notes

- **Etherleak is still live**: Modern firewalls (Palo Alto PAN-OS through 2021) still ship with frame padding info leaks - worth checking any embedded Ethernet stack
- **VLAN tag stacking** bypasses many Layer 2 security controls; double-tagged 802.1Q (QinQ) frames can traverse VLAN boundaries
- **ARP is unauthenticated**: Gratuitous ARP, ARP cache poisoning, and malformed hardware/protocol size fields remain viable on any flat L2 network
- **Raw socket access on Linux** requires `CAP_NET_RAW` or root; embedded devices often run all code as root making L2 attacks trivial once on-network
