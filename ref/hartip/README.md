# HART / HART-IP / WirelessHART - Reference Materials

## Protocol Overview

HART (Highway Addressable Remote Transducer) is the most widely used communication protocol for intelligent field instruments in process industries, with over 40 million installed devices. Three variants exist:

### Classic HART (4-20mA)
- **Transport**: FSK (Frequency Shift Keying) digital signal superimposed on 4-20mA analog current loop
- **Physical layer**: Bell 202 modem, 1200 baud, half-duplex
- **Addressing**: Polling address 0-63 (short frame) or 38-bit unique identifier (long frame)
- **Frame format**: Preamble (5-20 bytes 0xFF) + Delimiter + Address + Command + Byte Count + Data + Checksum
- **Master/Slave**: Two masters allowed (primary = DCS/PLC, secondary = handheld configurator)

### HART-IP (IEC 62591)
- **Transport**: TCP port 5094 (commands), UDP port 5094 (publish/subscribe)
- **HART-IP Header**: Version (1 byte), Message Type (1), Message ID (1), Status (1), Sequence Number (2), Byte Count (2) = 8 bytes total
- **Message Types**: Request (0), Response (1), Publish (2), NAK (15)
- **Session management**: Session Initiate (Cmd 257), Session Close (Cmd 258), Keep-Alive (Cmd 259)

### WirelessHART (IEC 62591)
- **Transport**: IEEE 802.15.4 at 2.4 GHz, TDMA with channel hopping
- **Security**: AES-128 encryption with join key, session key, network key
- **Topology**: Mesh network with gateway as coordinator
- **Devices**: Field devices, adapters, gateway, network manager, security manager

### HART Commands (All Variants)
- **Universal Commands (0-30)**: Supported by all devices. Cmd 0 (Read Unique ID), Cmd 1 (Read PV), Cmd 3 (Read Dynamic Variables), Cmd 6 (Write Polling Address), Cmd 11 (Read Unique ID by Tag), Cmd 48 (Read Additional Status)
- **Common Practice Commands (32-126)**: Cmd 33 (Read Device Variable), Cmd 35 (Write Range Values), Cmd 38 (Reset Config Change Flag), Cmd 77 (Send Command to Sub-device)
- **Device-Specific Commands (128-253)**: Vendor-proprietary, no standard format

## Wireshark Dissectors

- **HART-IP**: [packet-hartip.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-hartip.c)
- Parses HART-IP header and encapsulated HART commands
- Command-specific data parsing for universal and common practice commands

### Key dissector details:
- HART-IP header validation (version, message type)
- HART command number dispatch
- Byte count validation against actual payload
- Status code interpretation (communication status + command-specific status)

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **hipserver** | C | Official FieldComm Group HART-IP server reference implementation | [github.com/FieldCommGroup/hipserver](https://github.com/FieldCommGroup/hipserver) |
| **hipflowapp** | C | HART-IP flow device example (Raspberry Pi) | [github.com/FieldCommGroup/hipflowapp](https://github.com/FieldCommGroup/hipflowapp) |
| **HART-IP-Developer-Kit** | C | Full HART-IP developer kit from FieldComm Group | [github.com/FieldCommGroup/HART-IP-Developer-Kit](https://github.com/FieldCommGroup/HART-IP-Developer-Kit) |
| **icsnpp-hart-ip** | Spicy/Zeek | CISA's Zeek HART-IP protocol parser plugin | [github.com/cisagov/icsnpp-hart-ip](https://github.com/cisagov/icsnpp-hart-ip) |
| **open-hart** | C | Community HART protocol implementation | [github.com/libin89/open-hart](https://github.com/libin89/open-hart) |
| **openHART** | C | Open source HART protocol implementation | [github.com/bruceschaller/openHART](https://github.com/bruceschaller/openHART) |
| **hart-protocol** | Python | Sans-IO Python HART protocol library | [github.com/yaq-project/hart-protocol](https://github.com/yaq-project/hart-protocol) |
| **Wireshark dissector** | C | packet-hartip.c in Wireshark source | [gitlab.com/wireshark](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-hartip.c) |

## Common Parsing Vulnerabilities

### 1. HART-IP Header Byte Count
- 2-byte byte count field indicates total message size
- Mismatch with actual TCP/UDP payload
- Byte count = 0 with non-empty command data
- Very large byte counts causing allocation issues
- This exact pattern caused CVE-2020-16209 (CVSS 9.8) in the reference implementation

### 2. HART Command Parsing
- Command number (1 byte) determines expected payload structure
- Each command has a specific expected byte count
- Response data length varies per command -- length not always explicitly specified
- Device-specific commands (128-253) have unknown/vendor-specific formats

### 3. Status Byte Interpretation
- Communication status byte: bit field with error flags
- Command-specific status byte: varies per command
- Parsers that use status bits for control flow without validation

### 4. Nested/Encapsulated Commands
- HART supports burst mode and multi-variable transmitters
- Command 77 (Send Command to Sub-device) encapsulates another HART command
- Recursive command parsing with no depth limit in most implementations

### 5. String Fields (Packed ASCII)
- HART packed ASCII: 4 characters packed into 3 bytes (6-bit encoding)
- Long tag (32 bytes), descriptor (16 bytes), message (32 bytes)
- Buffer overflows when unpacking HART packed ASCII without length checks
- The longtag field was also the injection point for CVE-2015-6463 (XXE)

### 6. HART Frame Checksum
- XOR checksum of all bytes from delimiter to last data byte
- Simple 1-byte XOR -- trivially computed by attackers
- No cryptographic integrity protection in classic HART or HART-IP

### 7. DTM (Device Type Manager) Response Parsing
- FDT/DTM architecture: Frame Application loads DTM plugins that parse device responses
- CodeWrights GmbH DTM library was the dominant implementation across 24+ vendors
- CVE-2014-9191 showed that crafted HART response packets overflow DTM buffers
- Affects the master/engineering workstation side of HART communication

### 8. Session Management (HART-IP)
- HART-IP session initiation (Cmd 257) and keep-alive
- Session handle used for subsequent communications
- Invalid session handles, session hijacking via sequence number prediction

## Notable Research

- **"HART as an Attack Vector"** (S4x14, 2014) -- Alexander Bolshev presented HART protocol attacks including man-in-the-middle on 4-20mA current loop, modifying range/span/engineering units/damping values for process manipulation. Built the HRTShield Arduino board for HART bus sniffing, injection, and jamming.
- **Black Hat Europe 2014** -- Bolshev and Cherbov presented DTM component security research. Found 32 vulnerable DTM components from 24 vendors using the CodeWrights library, affecting 750+ HART devices.
- **Black Hat USA 2014** -- Same researchers presented current loop vulnerability research.
- **"Getting to the HART of the Matter"** (CSET 2021) -- Laura Tinnel and Mike Cochrane evaluated real-world safety system OT/IT interfaces, attacks, and countermeasures for HART. [Paper](https://cset21.isi.edu/papers/cset21-8.pdf)
- **Formal Verification of WirelessHART** (ACSAC ICSS Workshop 2022) -- Verified all previously published WirelessHART attacks and demonstrated new re-keying denial of service attack. [Paper](https://www.acsac.org/2022/workshops/icss/2022-icss-gunnarsson.pdf)
- **Dragos safety instruments research** -- Testing safety instruments and spotting process attacks via HART passthrough. [Blog](https://www.dragos.com/blog/safety-instruments-testing-spotting-and-stopping-process-attacks)
- **LOGIIC Project 12** -- Safety Instrumentation Report examining HART in safety system contexts.
- **FieldComm Group HART-IP Security whitepaper** -- [PDF](https://www.fieldcommgroup.org/sites/default/files/imce_files/technology/documents/FCG_AG10197%7B2.0%7D_HART-IP_Security.pdf)
- **WirelessHART Security whitepaper** -- [PDF](https://www.fieldcommgroup.org/sites/default/files/imce_files/technology/documents/WirelessHART%20security%20v1.0.pdf)
- **DEF CON 25 ICS Village** (2017) -- Blake Johnson demonstrated industrial wireless implementation dissection.
- **DEF CON 25** (2018) -- Paternotte and van Ommeren covered wireless mesh network attacks.

## Fuzzing Tools and Resources

### Fuzz Targets (Server-side implementations)
- [FieldCommGroup/hipserver](https://github.com/FieldCommGroup/hipserver) -- The official open-source HART-IP server reference implementation in C. Source code is available for building a fuzz harness. The v3.6.1 codebase (pre-fix for CVE-2020-16209) shows exactly where the unsafe memcpy/strcpy calls were. Fixed in v3.7.0 with Intel/Cisco safestringlib.
- [FieldCommGroup/hipflowapp](https://github.com/FieldCommGroup/hipflowapp) -- Companion flow device application. Combined with hipserver, provides a complete fuzzable HART-IP stack on Raspberry Pi.
- [libin89/open-hart](https://github.com/libin89/open-hart) -- Community C implementation of HART protocol. Smaller codebase, easier to harness for fuzzing.
- [bruceschaller/openHART](https://github.com/bruceschaller/openHART) -- Another open source HART implementation.

### Protocol Analysis / Monitoring
- [cisagov/icsnpp-hart-ip](https://github.com/cisagov/icsnpp-hart-ip) -- CISA's Zeek HART-IP parser plugin (written in Spicy). Useful as a reference for HART-IP packet structure and for monitoring fuzzing traffic.
- [Orange-Cyberdefense/awesome-industrial-protocols](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/hart-ip.md) -- Security-oriented HART-IP protocol reference with links to tools and vulnerability information.

### Physical Layer Tools
- [scastlecombe/hrtshield](https://github.com/scastlecombe/hrtshield) -- Arduino HART shield (Eagle circuit/PCB) from the S4x14 research. Hardware for sniffing, injecting, and jamming 4-20mA current loops. Includes Python scripts and Arduino sketches.

### Fuzzing Strategy
No dedicated public HART-IP fuzzer exists. HART-IP has a simple 8-byte header (Version, MsgType, MsgID, Status, SeqNum, ByteCount) over TCP/UDP port 5094, making it straightforward to fuzz with boofuzz or custom scripts. Key mutation targets:
1. **ByteCount field** -- Overflow the 2-byte count to cause buffer overflows (CVE-2020-16209 pattern)
2. **Command number** -- Send all 256 possible values including device-specific range 128-253
3. **Command payload length** -- Mismatch between command-expected size and actual data
4. **Packed ASCII fields** -- Mutate longtag, descriptor, message fields with oversized or malformed 6-bit packed data
5. **Cmd 77 nesting** -- Deeply nested sub-device commands for stack exhaustion
6. **HART-IP session commands** -- Malformed session initiate (257), close (258), keep-alive (259)
7. **Status bytes** -- All 256 values for both communication status and command-specific status

## Attack Surface Notes

### Most Dangerous Message Types
- **HART Command 0 (Read Unique ID)** -- Reconnaissance command. Returns device manufacturer, device type, unique identifier. No authentication required.
- **HART Command 6 (Write Polling Address)** -- Changes device addressing. Can disrupt multi-drop configurations.
- **HART Command 77 (Send Command to Sub-Device)** -- Encapsulates another HART command inside, creating recursive parsing. Depth is not limited in most implementations, enabling parser confusion or stack exhaustion.
- **HART Command 257 (Session Initiate)** -- HART-IP specific session establishment. Invalid session handles and sequence number prediction enable session hijacking.
- **Device-Specific Commands (128-253)** -- Vendor-specific with no standard format. Each vendor's parsing code is unique and untested against malformed input.
- **Process Variable Write Commands** -- Modifying range, span, engineering units, and damping values can cause physical process manipulation without triggering alarms.

### Most Commonly Vulnerable Fields
- **Byte Count (2 bytes in HART-IP header)** -- The field that caused CVE-2020-16209 (CVSS 9.8). Mismatch between stated byte count and actual payload triggers buffer overflows in every implementation that trusts this field.
- **Packed ASCII strings** -- 6-bit packed ASCII (4 chars in 3 bytes) for Long Tag, Descriptor, Message fields. Unpacking without length validation overflows output buffers. The longtag field was also the XXE injection vector in CVE-2015-6463.
- **Command-specific data lengths** -- Each HART command expects a specific payload size. Sending wrong sizes causes parsers to read beyond buffer boundaries or misinterpret subsequent fields.
- **Status bytes** -- Bit fields that control parsing behavior. Undefined bit combinations can change code paths unexpectedly.

### Known Weak Implementations
- **FieldComm Group hipserver (reference SDK)** -- CVE-2020-16209 (CVSS 9.8). The reference implementation that all vendors build upon had systemic unsafe C function usage (memcpy, strcpy, sprintf without bounds). Fixed in v3.7.0 with safestringlib. Any vendor who integrated pre-v3.7.0 hipserver code inherits these vulnerabilities.
- **CodeWrights GmbH DTM Library** -- CVE-2014-9191. Buffer overflow from crafted HART response packets. This single library was used by 24+ vendors (ABB, Emerson, Honeywell, Endress+Hauser, Yokogawa, GE, MACTek, Pepperl+Fuchs, Magnetrol, Schneider Electric) affecting 750+ HART device DTMs.
- **CodeWrights HART Comm DTM** -- CVE-2015-6463. XXE injection via longtag response field.
- **Schneider Electric IMT25 DTM** -- CVE-2015-3977 (CVSS 7.7). Buffer overflow from crafted HART reply causing memory corruption and RCE.
- **General HART-IP ecosystem** -- HART-IP has essentially no native cybersecurity. No authentication, no encryption, no integrity checks. All commands accepted from any source on port 5094. The protocol relies entirely on network segmentation for security.

### Ecosystem Note: The CodeWrights Supply Chain
The most impactful HART vulnerability discovery was finding that CodeWrights GmbH produced the DTM library used by the majority of HART device manufacturers. A single buffer overflow bug (CVE-2014-9191) propagated across separate CISA advisories for: CodeWrights (ICSA-15-012-01), Emerson (ICSA-15-008-01), Honeywell (ICSA-15-029-01), Magnetrol (ICSA-15-027-01), GE/MACTek (ICSA-15-036-01), Pepperl+Fuchs (ICSA-15-036-02), Yokogawa (ICSA-15-048-03), ABB (ICSA-15-069-02), Schneider Electric (ICSA-15-223-01), and Endress+Hauser (ICSA-15-237-01). This makes it a textbook supply-chain vulnerability in ICS.
