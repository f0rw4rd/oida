# BACnet (Building Automation and Control Networks) - Reference Materials

## Protocol Overview

BACnet is a data communication protocol for building automation and control networks (ASHRAE 135). It defines services for monitoring and controlling HVAC, lighting, access control, fire detection, and other building systems.

- **Transport**: UDP port 47808 (0xBAC0), also supports MS/TP (serial), Ethernet, ARCNET
- **BACnet/IP**: BVLL (BACnet Virtual Link Layer) + NPDU + APDU
- **BVLL Types**: Original-Unicast-NPDU, Original-Broadcast-NPDU, Forwarded-NPDU, Register-Foreign-Device
- **APDU Types**: Confirmed/Unconfirmed Request, Simple/Complex ACK, Segment ACK, Error, Reject, Abort
- **Services**: ReadProperty, WriteProperty, WhoIs/IAm, COVNotification, etc.

## Wireshark Dissectors

- **BACnet**: [packet-bacnet.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-bacnet.c) - Network layer (NPDU)
- **BACnet APDU**: [packet-bacapp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-bacapp.c) - Application layer
- **BACnet MS/TP**: [packet-mstp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mstp.c) - MS/TP framing

### Key dissector details:
- BVLL header parsing (type, function, length)
- NPDU parsing with DNET/DLEN/DADR routing information
- APDU segmentation handling
- ASN.1 BER/CER tagged encoding for property values
- Object/property identifier decoding

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **bacpypes** | Python | Comprehensive BACnet protocol stack | [github.com/JoelBender/bacpypes](https://github.com/JoelBender/bacpypes) |
| **bacnet-stack** | C | Open-source BACnet protocol stack by Steve Karg | [github.com/bacnet-stack/bacnet-stack](https://github.com/bacnet-stack/bacnet-stack) |
| **Scapy** | Python | BACnet contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **node-bacnet** | JavaScript | BACnet client implementation for Node.js | [github.com/fh1ch/node-bacnet](https://github.com/fh1ch/node-bacnet) |
| **BACsharp** | C# | BACnet library for .NET | [github.com/ela-compil/BACnet](https://github.com/ela-compil/BACnet) |

## Common Parsing Vulnerabilities

### 1. ASN.1 Tag-Length-Value (TLV) Parsing
- BACnet uses context-tagged ASN.1 encoding extensively
- Length fields can be 1, 2, 3, or 5 bytes depending on value
- Extended tag numbers (tag > 14) use multi-byte tag encoding
- Recursive/nested constructed types can cause stack exhaustion
- Length values exceeding remaining packet data cause over-reads

### 2. NPDU Routing Information
- DNET/SNET (2 bytes), DLEN/SLEN (1 byte), DADR/SADR (variable)
- DLEN=0 means broadcast, but parsers may allocate 0-byte buffers
- Hop count (1 byte) decrement to 0 should be dropped but often isn't

### 3. APDU Segmentation
- Segmented messages use sequence numbers (0-255) and window size
- Missing segments, duplicate sequence numbers, or wrong more-follows flag
- Maximum APDU size negotiation violations
- Proposed window size vs. actual window size mismatches

### 4. Object and Property Identifiers
- Object ID: 10-bit type + 22-bit instance (packed in 4 bytes)
- Property IDs can be vendor-specific (>= 512)
- Array index values with special value 0 (array size) vs. out-of-bounds indices

### 5. BVLL Foreign Device Registration
- Register-Foreign-Device with crafted TTL values
- Forwarded-NPDU with spoofed original source addresses
- BBMD (BACnet Broadcast Management Device) table overflow

### 6. Service-Specific Issues
- ReadPropertyMultiple with excessive property references
- WritePropertyMultiple with type-mismatched values
- AtomicReadFile/AtomicWriteFile with out-of-range offsets
- DeviceCommunicationControl can disable device without authentication

## Notable Research

- **"BACnet Security: What You Need to Know"** - ASHRAE Journal articles
- **"Hacking Building Automation Systems"** - Various conference presentations
- **CVE research by Tridium** - Niagara Framework BACnet vulnerabilities
- **CISA ICS-CERT Advisories** - Multiple BACnet implementation flaws

## Fuzzing Tools

- [VDA-Labs BACnet-fuzzer](https://github.com/VDA-Labs/BACnet-fuzzer) -- Simple fuzzer using BooFuzz framework to target BACnet protocol services
- [Fuzzowski](https://github.com/nccgroup/fuzzowski) -- Network protocol fuzzer with BACnet support; launch via `python -m fuzzowski <target> 47808 -p udp -f bacnet -rt 0.5 -m BACnetMon`; generates PoCs for discovered faults
- [bacpypes](https://github.com/JoelBender/bacpypes) -- While primarily a BACnet library, bacpypes can be used to craft arbitrary malformed BACnet packets for targeted testing
- [Aegis Fuzzer](https://www.automatak.com/aegis/) -- Smart fuzzing framework with BACnet protocol support

## Attack Surface Notes

- **Most dangerous services**: DeviceCommunicationControl (can disable device without authentication), AtomicWriteFile/AtomicReadFile (file operations with offset and size parameters), WriteProperty/WritePropertyMultiple (property value encoding)
- **Most commonly vulnerable fields**: ASN.1 tag-length-value encoding (BACnet uses context-tagged ASN.1 extensively -- extended tags >14 use multi-byte encoding that is error-prone), BVLL length field (mismatch with UDP payload size), NPDU DLEN/SLEN routing fields
- **Open-source BACnet Stack**: The most widely targeted open-source implementation has a recurring pattern of vulnerabilities: stack overflow in BVLC forwarding (CVE-2018-10238), segfault in tag parsing (CVE-2019-12480), integer underflow in WriteProperty (CVE-2026-26264). The common thread is insufficient validation of lengths and sizes before memory operations.
- **BBMD (BACnet Broadcast Management Device)**: When enabled, BBMD adds the BVLC forwarding code path which has historically been vulnerable to buffer overflows from oversized forwarded NPDUs
- **BACnet MSTP (serial)**: Less commonly fuzz-tested than BACnet/IP, but MSTP framing has its own parsing surface (CVE-2025-40556 in Siemens ATEC devices)
- **Building automation impact**: Unlike industrial protocols, BACnet controls HVAC, lighting, fire detection, and access control. A parsing crash in a building controller can affect physical safety systems (fire detection, access control lockout)
