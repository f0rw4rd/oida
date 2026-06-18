# NTP (Network Time Protocol) - Reference Materials

## Protocol Overview

NTP (RFC 5905) synchronizes clocks across networked systems. NTPv4 is the current version. NTP is a critical infrastructure protocol - time accuracy affects authentication, logging, certificates, and industrial process synchronization.

- **Transport**: UDP port 123
- **Header**: LI (2 bits) + VN (3 bits) + Mode (3 bits) + Stratum (1) + Poll (1) + Precision (1) + Root Delay (4) + Root Dispersion (4) + Reference ID (4) + Reference/Origin/Receive/Transmit Timestamps (8 each) = 48 bytes
- **Modes**: 1 (symmetric active), 2 (symmetric passive), 3 (client), 4 (server), 5 (broadcast), 6 (control), 7 (private)
- **Extension Fields**: Type (2) + Length (2) + Value (variable) - used for NTS, Autokey

## Wireshark Dissectors

- **NTP**: [packet-ntp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ntp.c)
- Mode-based parsing dispatch
- Extension field chain parsing
- Control message (mode 6) and private message (mode 7) handling
- NTS (Network Time Security) extension support

### Key dissector details:
- 48-byte fixed header parsing
- Mode 6 (control): opcode, sequence, status, association ID, data
- Mode 7 (private/monlist): implementation, request code, data items
- Extension field: type + length + padding + MAC
- NTS: cookie, AEAD encrypted extension fields

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **ntpd** | C | Reference NTP implementation (ntp.org) | [github.com/ntp-project/ntp](https://github.com/ntp-project/ntp) |
| **chrony** | C | Modern NTP implementation | [chrony.tuxfamily.org](https://chrony.tuxfamily.org/) |
| **ntpsec** | C | Hardened fork of ntpd | [github.com/ntpsec/ntpsec](https://github.com/ntpsec/ntpsec) |
| **Scapy** | Python | NTP layer built-in | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **ntplib** | Python | Simple NTP client | [pypi.org/project/ntplib](https://pypi.org/project/ntplib/) |

## Common Parsing Vulnerabilities

### 1. Mode 6/7 (Control/Private) Messages
- Mode 6 control messages used for ntpq queries - complex data format
- Mode 7 private mode (monlist) - list of recent clients (DDoS amplification)
- Variable-length data payloads in control messages
- Fragmented control responses (more bit)

### 2. Extension Fields
- Extension field chain: type (2) + length (2) + value (length-4 bytes)
- Length must be multiple of 4 (padding)
- Extension field length exceeding remaining packet
- Unrecognized extension field types
- Empty extension fields (length = 4, no value)

### 3. Timestamp Manipulation
- NTP timestamps: 64-bit (32-bit seconds + 32-bit fraction since 1900)
- Timestamps in the future, in the past, or exactly 0
- Kiss-o'-Death (KoD) packets with specific Reference ID strings
- Leap indicator manipulation for time jumps

### 4. MAC/Authentication
- Symmetric key authentication: Key ID (4) + MAC (16-20 bytes)
- Autokey (deprecated): complex extension-based authentication
- MAC length ambiguity (MD5 vs. SHA-1)
- Key ID values referencing non-existent keys

### 5. Amplification Attacks
- Mode 7 monlist response much larger than request
- Mode 6 readvar/readlist amplification
- NTP as DDoS reflector/amplifier

### 6. Stratum/Reference ID
- Stratum 0 (unspecified), 1 (primary), 2-15 (secondary), 16 (unsynchronized)
- Reference ID meaning changes with stratum (IP for stratum 2+, ASCII for stratum 1)
- Loop detection via Reference ID

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **Metasploit NTP Protocol Fuzzer** | Ruby | Simplistic fuzzer sending all combinations of NTP versions/modes, invalid datagrams, full-size random datagrams, and all mode 6/7 control/private messages | [auxiliary/fuzzers/ntp/ntp_protocol_fuzzer](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/fuzzers/ntp/ntp_protocol_fuzzer.rb) |
| **Metasploit NTP Monlist Scanner** | Ruby | Scanner for mode 7 monlist amplification (CVE-2013-5211) | [auxiliary/scanner/ntp/ntp_monlist](https://www.rapid7.com/db/modules/auxiliary/scanner/ntp/ntp_monlist/) |

## Attack Surface Notes

### Server-Side (ntpd Daemon) Parsing Targets
- **Mode 6 control messages**: The richest attack surface. Variable-length data fields, fragmented responses with more-bit, opcode dispatch. Multiple buffer overflows (CVE-2014-9295), assertion failures (CVE-2015-7855), and NULL pointer dereferences (CVE-2016-7434, CVE-2019-8936) found here.
- **Mode 7 private messages**: Implementation-specific request codes with data item count/size. The monlist command (CVE-2013-5211) is the most widely exploited NTP vulnerability for DDoS amplification (556x factor).
- **Extension fields**: Type (2 bytes) + Length (2 bytes) + Value -- length must be multiple of 4; length exceeding remaining packet, zero-length, or unrecognized types can trigger parsing errors.
- **Crypto-NAK processing**: Buffer overflow in crypto-NAK handling (CVE-2014-9295) from malformed authentication data.
- **Reference clock data**: Buffer overflow in refclock_datum_receive() (CVE-2015-7853) from oversized reference clock input.

### Protocol-Level Attack Vectors
- **Mode 6/7 are the primary targets**: Almost all ntpd parsing vulnerabilities are in mode 6 (control) and mode 7 (private) message handling. Standard NTP client/server mode (mode 3/4) has a simple fixed-format header with minimal parsing.
- **Authentication ambiguity**: MAC length ambiguity between MD5 (16 bytes) and SHA-1 (20 bytes) plus Key ID (4 bytes) creates parsing confusion at end of packet.
- **chrony is more hardened**: chrony deliberately lacks mode 6 and mode 7 support, eliminating the most vulnerable attack surface. ntpsec also hardens mode 6/7 handling.

### High-Value Fuzzing Strategies
- **Mode 6 control message fuzzing**: Vary opcode, sequence, status, association ID, and data payload. Fragment responses with more-bit set. This is where most ntpd bugs are found.
- **Mode 7 private message fuzzing**: Vary implementation code, request code, data item count, and data item size. Target monlist, peer_stats, and other private commands.
- **Extension field chain fuzzing**: Send packets with multiple extension fields with varying lengths, especially non-aligned lengths and fields exceeding packet boundaries.
- **Timestamp edge cases**: Zero timestamps, far-future values, and timestamps that trigger KoD (Kiss-o'-Death) processing paths.

## Notable Research

- **"Attacking the NTP Protocol"** - Multiple conference presentations
- **NTP amplification DDoS** - Widely exploited in real-world attacks (CVE-2013-5211, up to 556x amplification)
- **"Delorean"** (NTP time-shifting attacks)
- **Cisco Talos NTP research** - Multiple vulnerability discoveries
- **NTP 4.2.8p15 mstolfp CVEs (2023)** - Four OOB write variants in ASCII timestamp parsing (CVE-2023-26551 through CVE-2023-26554)
- **ntpsec and chrony hardening** - Comparison of attack surface reduction by removing mode 6/7 support
