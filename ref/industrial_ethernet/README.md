# Industrial Ethernet - Reference Materials

## Protocol Overview

Industrial Ethernet encompasses several real-time Ethernet protocols used in automation: PROFINET RT/IRT, EtherCAT, Sercos III, POWERLINK, and CC-Link IE. These protocols modify or extend standard Ethernet for deterministic real-time communication.

- **PROFINET RT**: EtherType 0x8892, Frame ID-based prioritization
- **EtherCAT**: EtherType 0x88A4, processing-on-the-fly with datagrams
- **POWERLINK**: EtherType 0x88AB, time-slotted cycle
- **Sercos III**: EtherType 0x88CD, real-time Ethernet ring
- **CC-Link IE**: EtherType 0x890F, Mitsubishi industrial Ethernet

## Wireshark Dissectors

- **PROFINET RT**: [packet-pn-rt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-pn-rt.c)
- **EtherCAT**: [packet-ethercat.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ethercat.c)
- **POWERLINK**: [packet-epl.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-epl.c)
- **Sercos III**: [packet-sercosiii.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-sercosiii.c)

## Open-Source Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **SOEM** | C | Simple Open EtherCAT Master | [github.com/OpenEtherCATsociety/SOEM](https://github.com/OpenEtherCATsociety/SOEM) |
| **openPOWERLINK** | C | POWERLINK protocol stack | [github.com/OpenAutomationTechnologies/openPOWERLINK_V2](https://github.com/OpenAutomationTechnologies/openPOWERLINK_V2) |
| **p-net** | C | PROFINET device stack | [github.com/rtlabs-com/p-net](https://github.com/rtlabs-com/p-net) |
| **Scapy** | Python | ProfinetIO contrib | [github.com/secdev/scapy](https://github.com/secdev/scapy) |

## Common Parsing Vulnerabilities

1. **Frame ID Dispatching**: PROFINET RT uses Frame ID (2 bytes) for message type - invalid IDs cause parsing confusion
2. **EtherCAT Datagram Chaining**: Multiple datagrams in single frame with length fields - chain walking off end of frame
3. **Real-Time Cycle Injection**: Injecting frames during wrong phase of RT cycle
4. **Cyclic Data Length Mismatch**: Expected IO data size vs. actual frame payload
5. **VLAN Priority Manipulation**: 802.1Q priority bits used for RT scheduling - priority inversion attacks
6. **Multicast Group Flooding**: RT multicast addresses for broadcast storms

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **profinet_set_fuzzer.py** | Scapy-based PROFINET DCP SET request fuzzer, tested on S7-1200/1500 | [github.com/atimorin/scada-tools](https://github.com/atimorin/scada-tools/blob/master/profinet_set_fuzzer.py) |
| **Scapy ProfinetIO** | ProfinetIO contrib layer for crafting PROFINET RT/DCP frames | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **ICS-Security-Tools** | Curated collection of ICS protocol tools including PROFINET and EtherCAT | [github.com/ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) |
| **ProfinetTools** | .NET tools for PROFINET analysis and configuration | [github.com/fbarresi/ProfinetTools](https://github.com/fbarresi/ProfinetTools) |
| **ICScanner** | Industrial control systems network scanner supporting PROFINET discovery | [github.com/0xICF/ICScanner](https://github.com/0xICF/ICScanner) |
| **Defensics** | Commercial fuzzer with PROFINET, EtherCAT, Modbus, and other ICS protocol support | [Synopsys Defensics](https://www.synopsys.com/software-integrity/security-testing/fuzz-testing.html) |

## Attack Surface Notes

- **All Layer 2, no IP firewall protection**: Industrial Ethernet protocols operate at Layer 2 (EtherType-based dispatch), meaning IP-based firewalls and ACLs provide zero protection. An attacker on the same broadcast domain has full access.
- **P-Net PROFINET library (10 CVEs in 2025)**: Nozomi Networks fuzzing campaign found 10 memory corruption bugs in the open-source P-Net PROFINET stack (CVE-2025-32396 through CVE-2025-32405). Heap overflows, NULL derefs, and OOB writes via malicious RPC packets. All found with basic libFuzzer harness.
- **EtherCAT monitoring tools also vulnerable**: The ICSNPP EtherCAT Zeek plugin had 3 OOB write/read bugs (CVE-2023-7242/7243/7244) - attacking the IDS, not just the device.
- **PROFINET DCP is broadcast and unauthenticated**: DCP SET requests can rename, re-IP, or factory-reset devices without any authentication. Resource exhaustion via DCP floods is a known attack (CVE-2020-28400).
- **Siemens has a long tail of PROFINET DoS bugs**: CVE-2017-2681, CVE-2019-13946, CVE-2019-10936, CVE-2020-28400, CVE-2022-25622 - all DoS via crafted frames against SIMATIC products.

## Notable CVEs

See `cves/README.md` for detailed listing.
