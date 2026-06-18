# DHCP (Dynamic Host Configuration Protocol) - Reference Materials

## Protocol Overview

DHCP (RFC 2131) automates IP address assignment and network configuration. DHCPv4 uses UDP (client port 68, server port 67) with a BOOTP-derived message format. DHCPv6 (RFC 8415) uses UDP (client port 546, server port 547) with a different message format.

- **DHCPv4 Transport**: UDP, client 68 -> server 67, broadcast/unicast
- **DHCPv6 Transport**: UDP, client 546 -> server 547, multicast ff02::1:2
- **DHCPv4 Message Format**: Fixed 236-byte header + magic cookie (0x63825363) + options (TLV)
- **DHCPv6 Message Format**: Message type (1) + Transaction ID (3) + options (type 2 + length 2 + data)
- **DORA**: Discover, Offer, Request, Acknowledge (DHCPv4 state machine)

## Wireshark Dissectors

- **DHCPv4**: [packet-dhcp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dhcp.c) (previously packet-bootp.c)
- **DHCPv6**: [packet-dhcpv6.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dhcpv6.c)

### Key dissector details:
- DHCPv4: Fixed header parsing, magic cookie validation, option TLV parsing
- Option 53 (message type) determines DHCP state
- Option 55 (parameter request list) processing
- DHCPv6: Message type dispatch, option chain parsing, IA_NA/IA_TA/IA_PD nested options
- Relay agent option (option 82) sub-option parsing

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **ISC DHCP** | C | ISC DHCP server/client (legacy) | [gitlab.isc.org/isc-projects/dhcp](https://gitlab.isc.org/isc-projects/dhcp) |
| **Kea** | C++ | ISC Kea DHCP server (modern) | [gitlab.isc.org/isc-projects/kea](https://gitlab.isc.org/isc-projects/kea) |
| **dnsmasq** | C | Lightweight DHCP/DNS server | [thekelleys.org.uk/dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) |
| **Scapy** | Python | DHCP/BOOTP layers built-in | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **dhcpkit** | Python | Python DHCPv6 framework | [github.com/sjm-steffann/dhcpkit](https://github.com/sjm-steffann/dhcpkit) |

## Common Parsing Vulnerabilities

### 1. DHCPv4 Option Parsing
- TLV format: Type (1) + Length (1) + Value (Length bytes)
- Option 0 (pad) and 255 (end) are special (no length byte)
- Option length exceeding remaining packet
- Overloading: sname/file fields used for options (option 52)
- Nested options: Relay Agent Information (option 82) contains sub-options

### 2. DHCPv6 Option Nesting
- IA_NA (option 3) contains IA Address (option 5) as sub-options
- IA_PD (option 25) contains IA Prefix (option 26)
- Recursive/deeply nested option chains
- Option length fields (2 bytes) vs. actual content

### 3. Client ID / DUID Handling
- Variable-length client identifiers (option 61 in DHCPv4, option 1 in DHCPv6)
- DUID types: DUID-LLT, DUID-EN, DUID-LL, DUID-UUID
- Oversized or zero-length client IDs
- DUID type field vs. actual DUID data format

### 4. Hostname/FQDN Processing
- Option 12 (hostname) and option 81 (FQDN) string handling
- DNS name encoding in FQDN option with compression
- Buffer overflows from long hostnames
- Null bytes in hostname strings

### 5. Lease Time Manipulation
- Option 51 (lease time) with extreme values (0, 0xFFFFFFFF)
- T1/T2 renewal/rebinding timers inconsistencies
- Infinite lease handling

### 6. Broadcast/Relay Attacks
- DHCP starvation (exhaust address pool)
- Rogue DHCP server responses
- Relay agent information injection/modification

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Fuzzowski** | Network protocol fuzzer with built-in DHCP fuzzer module | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |
| **Fuzzowski-ICS** | ICS-focused fork with DHCP support | [github.com/h0rac/fuzzowski-ics](https://github.com/h0rac/fuzzowski-ics) |
| **Fuzzotron** | TCP/UDP network daemon fuzzer applicable to DHCP servers | [github.com/denandz/fuzzotron](https://github.com/denandz/fuzzotron) |
| **Scapy** | Python packet crafting library with full DHCP/BOOTP layer support, 119 DHCP options implemented | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **AFLNet** | Greybox protocol fuzzer with state-feedback | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **NDFuzz / ZDHCP** | Coverage-guided fuzzer for virtualized network devices including DHCP | [Cybersecurity Journal](https://cybersecurity.springeropen.com/articles/10.1186/s42400-022-00120-1) |

## Attack Surface Notes

- **DHCPv6 relay messages (dnsmasq)**: The Google Project Zero dnsmasq research (CVE-2017-14493) found a stack overflow in DHCPv6 relay message handling. The relay-forward and relay-reply message types create nested option chains that many implementations parse recursively without depth limits.
- **Option length validation**: CVE-2018-5732 (ISC DHCP) and CVE-2021-25217 (ISC DHCP) both involve buffer overflow/overread when option length fields exceed remaining packet data. This is the most common DHCP parsing bug pattern.
- **Single-packet crashes in Kea**: CVE-2025-40779 shows that ISC Kea DHCP4 can be crashed by a single unicast packet with specific options when no matching subnet exists. Assertion failures in modern C++ DHCP servers are a DoS vector that fuzzers readily find.
- **DNSpooq (dnsmasq)**: JSOF discovered that dnsmasq's DNS component (often co-deployed with DHCP) had cache poisoning bugs (CVE-2020-25684/25685/25686) and the DHCP heap overflow (CVE-2020-25681). The DHCP and DNS components share memory allocators, so DHCP parsing bugs can be leveraged for DNS cache attacks.
- **ICS/embedded context**: dnsmasq is extremely common in embedded Linux routers, IoT gateways, and ICS network infrastructure. DHCP parsing bugs in these deployments often have no ASLR/stack canaries and can be reached from any device on the LAN segment.
- **Option 82 (Relay Agent Info)**: Sub-option parsing within Option 82 creates a second layer of TLV parsing that many implementations handle inconsistently.

## Notable Research

- **"DHCP Starvation Attack"** - Classic DoS attack
- **"DHCPwn"** - DHCP exhaustion tool
- **Google Project Zero dnsmasq research** - Multiple DHCP parsing bugs
