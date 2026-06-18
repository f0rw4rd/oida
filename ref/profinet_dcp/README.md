# PROFINET DCP (Discovery and Configuration Protocol) - Reference Materials

## Protocol Overview

PROFINET DCP is a Layer 2 protocol used for discovering and configuring PROFINET IO devices on a local network. It operates directly over Ethernet (no IP) using multicast. DCP handles device name assignment, IP configuration, identification, and basic device management.

- **Transport**: Raw Ethernet, EtherType 0x8892 (PROFINET)
- **Frame ID Range**: 0xFEFC-0xFEFF for DCP
- **Multicast**: 01:0E:CF:00:00:00 (DCP identify multicast)
- **Services**: Identify (multicast), Get, Set
- **Data Format**: Service ID + Service Type + Xid + Response Delay + Data Length + Blocks

## Wireshark Dissectors

- **PROFINET DCP**: [packet-pn-dcp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-dcp.c)
- **PROFINET IO**: [packet-pn-io.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-io.c)
- **PROFINET RT**: [packet-pn-rt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-rt.c)
- **PROFINET MRP**: [packet-pn-mrp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-mrp.c)
- **PROFINET PTCP**: [packet-pn-ptcp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-ptcp.c)

### Key dissector details:
- Frame ID dispatch to DCP, IO, RT sub-dissectors
- DCP block parsing: option (1), suboption (1), block length (2), data
- Block types: IP, Device Properties, DHCP, Control, All
- DCP Set service for name/IP assignment
- DCP Identify with filter options

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **profinet-py** | Python | PROFINET IO controller (DCP, RPC, cyclic) | Local project: /home/feb/pro/profinet-py |
| **Scapy** | Python | ProfinetIO contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio.py) |
| **p-net** | C | Open-source PROFINET device stack | [github.com/rtlabs-com/p-net](https://github.com/rtlabs-com/p-net) |
| **Profinet.jl** | Julia | PROFINET DCP implementation | [github.com](https://github.com) (various Julia implementations) |
| **profi-dcp** | Rust | Rust PROFINET DCP library | [crates.io/crates/profi-dcp](https://crates.io/crates/profi-dcp) |

## Common Parsing Vulnerabilities

### 1. DCP Block Length Field
- Block length (2 bytes) indicates remaining block data size
- Mismatch with actual remaining frame data causes over-reads
- Zero-length blocks with mandatory sub-fields
- Block padding alignment (blocks must be 2-byte aligned)

### 2. Block Option/Suboption Dispatch
- Option (1 byte) + Suboption (1 byte) determine block type
- Unknown option/suboption combinations often not handled
- Vendor-specific blocks (option 5) with arbitrary content
- Block iteration continues past end of DCP data

### 3. Device Name Handling
- Station name in DCP blocks is a string (max 240 characters per spec)
- No null terminator guaranteed in protocol
- Names with special characters, empty names, names exceeding max length
- Name comparison case sensitivity inconsistencies

### 4. IP Configuration Blocks
- IP address, subnet mask, gateway packed in 12 bytes
- Invalid IP addresses (0.0.0.0 subnet, multicast IPs as device address)
- Conflicting IP/subnet combinations

### 5. DCP Identify Multicast Flooding
- DCP Identify is multicast - all devices on segment respond
- No rate limiting in most implementations
- Response delay field manipulation (0-65535 * 10ms)
- Filter options in Identify request with contradictory criteria

### 6. Xid (Transaction ID) Handling
- 4-byte transaction ID for matching requests to responses
- Collision/reuse of Xid values across different services
- Xid=0 behavior varies between implementations

### 7. Service Type Confusion
- Service ID (1) + Service Type (1): Request, Response, Success, Error
- Sending Response frames to a device (which expects Requests)
- Error responses with undefined error codes

## Notable Research

- **PROFINET Security Class definitions** (PI International)
- **"Hacking PROFINET"** - Various industrial security conference talks
- **Siemens ProductCERT advisories** - Largest PROFINET vendor
- **Positive Technologies ICS research** - PROFINET protocol analysis
- **Nozomi Networks Labs** - Fuzzing P-Net: 10 vulnerabilities found in open-source PROFINET library (2025)
- **DIMVA 2019** - "No Need to Marry to Change Your Name! Attacking Profinet IO Automation Networks Using DCP" (Mehner & Koenig)

## Fuzzing Tools

- [ProFuzz](https://github.com/hcit/ProFuzz) -- Simple PROFINET fuzzer based on Scapy. Student project from University of Applied Sciences Augsburg, fuzzes various PROFINET frame types.
- [profinet_set_fuzzer.py](https://github.com/atimorin/scada-tools/blob/master/profinet_set_fuzzer.py) -- PROFINET DCP SET request fuzzer tested on S7-1200/1500 PLCs. Sends mutated DCP Set requests with preconfigured packets and options.
- [ProfinetIO-DoS-attack](https://github.com/smehner1/ProfinetIO-DoS-attack) -- Python/Scapy implementation of the DIMVA 2019 paper. Four-stage attack: topology exploration, port stealing, DCP reconfiguration, persistent DoS. Demonstrates full DCP attack chain.
- [ISF (Industrial Exploitation Framework)](https://github.com/dark-lbp/isf) -- Includes PROFINET DCP device scanner and IP configuration exploit module (`profinet_set_ip.py`).
- [Rapid7 Metasploit](https://www.rapid7.com/db/modules/auxiliary/scanner/scada/profinet_siemens/) -- `auxiliary/scanner/scada/profinet_siemens` module for PROFINET device discovery.

## Attack Surface Notes

### Most Dangerous Message Types
- **DCP Set (Service ID 0x04)** -- Unauthenticated device reconfiguration on Layer 2. Can change station name and IP address of any PROFINET device on the segment. Exploited in the DIMVA 2019 attack chain.
- **DCP Identify (Service ID 0x05)** -- Multicast discovery that all devices respond to. Flooding with Identify requests causes resource exhaustion (CVE-2020-28400). Malformed Identify frames crash devices (CVE-2017-2680/2681).
- **PROFINET IO CONNECT (RPC)** -- DCE/RPC connection establishment over UDP. ArVendorBlock parsing leads to out-of-bounds writes (CVE-2025-32405). 10 vulnerabilities found in P-Net library's RPC handling alone.
- **DCP Reset (via Set)** -- Factory reset via DCP Set with reset suboption. Flood of reset packets exhausts resources.

### Most Commonly Vulnerable Fields
- **DCP Block Length (2 bytes)** -- The #1 crash vector. Values of 0, exceeding frame size, or very large cause over-reads and buffer overflows in block parsing loops.
- **Block Option/Suboption** -- Unknown combinations not handled; vendor-specific blocks (option 5) with arbitrary content bypass validation.
- **Station Name string** -- No null terminator in protocol; names exceeding 240-byte spec maximum overflow fixed buffers. DCP Set can assign crafted names without authentication.
- **RPC ArVendorBlock** -- Counter-as-index without bounds check (CVE-2025-32405); multiple heap overflows in RPC argument parsing.

### Known Weak Implementations
- **Siemens PROFINET Stack** -- Largest deployment base. CVE-2017-2680/2681 affected nearly the entire Siemens industrial portfolio (SIMATIC, SCALANCE, SINAMICS, SIMOTION, SINUMERIK). The advisory was updated 22+ times over 5 years as more products were found affected. CVE-2020-28400 (DCP flooding DoS) similarly affected dozens of product families.
- **RT-Labs P-Net** -- Open-source C library for PROFINET IO devices. 10 memory safety vulnerabilities found in a single fuzzing campaign (2025). All in UDP RPC parsing. Fixed in v1.0.2, fuzz testing now integrated.
- **Siemens + Interniche IP Stack** -- CVE-2022-25622: PROFINET PNIO stack integrated with Interniche IP improperly handles short TCP headers. Cross-stack integration bugs are a rich target.
