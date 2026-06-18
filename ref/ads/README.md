# ADS (Automation Device Specification) / TwinCAT - Reference Materials

## Protocol Overview

ADS (Automation Device Specification) is Beckhoff's proprietary protocol for TwinCAT automation systems. It runs over AMS (Automation Message Specification) which can be transported via TCP (port 48898/AmsNet) or UDP. ADS is the primary protocol for programming, diagnostics, and data exchange with Beckhoff PLCs.

- **Transport**: TCP port 48898 (AMS/TCP), also port 851 (TwinCAT system service)
- **AMS Header**: Source/Target NetID (6 bytes each) + Port (2 bytes each) + Command ID + State Flags + Data Length + Error Code + Invoke ID
- **AMS/TCP Header**: Reserved (2 bytes) + Length (4 bytes)
- **ADS Commands**: Read, Write, ReadState, WriteControl, AddDeviceNotification, DeleteDeviceNotification, DeviceNotification, ReadWrite

## Wireshark Dissectors

- **AMS/ADS**: [packet-ams.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ams.c)
- Parses AMS/TCP framing and AMS headers
- ADS command-specific data parsing
- AMS NetID and port resolution

### Key dissector details:
- AMS/TCP length field validation
- AMS header parsing with 32-byte fixed header
- Command ID dispatch (0x0001-0x0009)
- State flags: request/response, ADS command, UDP
- Index Group/Index Offset for Read/Write operations

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **pyads** | Python | Python wrapper for Beckhoff ADS communication | [github.com/stlehmann/pyads](https://github.com/stlehmann/pyads) |
| **ads-client** | JavaScript | Node.js ADS/AMS client | [github.com/jisotalo/ads-client](https://github.com/jisotalo/ads-client) |
| **TwinCAT.ADS** | C# | .NET ADS library (Beckhoff official) | [nuget.org/packages/Beckhoff.TwinCAT.Ads](https://www.nuget.org/packages/Beckhoff.TwinCAT.Ads) |
| **goADS** | Go | Go ADS client implementation | [github.com/stamp/goern](https://github.com/stamp/goern) |

## Common Parsing Vulnerabilities

### 1. AMS/TCP Length Field
- 4-byte length field indicates total AMS data size
- Values exceeding available memory or maximum PDU size
- Length=0 followed by data
- Length larger than TCP segment requiring reassembly with no bounds

### 2. AMS NetID/Port Routing
- AMS NetID is 6 bytes (usually formatted as x.x.x.x.x.x)
- AMS router forwards based on NetID - spoofed NetIDs can reach internal devices
- AMS port numbers map to TwinCAT runtime instances
- Port 0 or broadcast ports may trigger undefined behavior

### 3. Index Group / Index Offset Exploitation
- Read/Write commands use Index Group (4 bytes) + Index Offset (4 bytes) for addressing
- Special index groups: 0xF000-0xFFFF are system services
- Index Group 0xF003 (ReadWriteMulti) allows multiple operations in one request
- Out-of-bounds index offsets directly translate to memory addresses in some implementations

### 4. ReadWrite Command Abuse
- ReadWrite (cmd 0x0009) combines read and write in one operation
- Read length + Write length + Write data - mismatched sizes cause buffer issues
- The "read length" parameter determines response buffer allocation

### 5. Notification Attacks
- AddDeviceNotification creates server-initiated data push
- Large numbers of notifications exhaust resources
- Notification handles used without validation in DeleteDeviceNotification
- Cyclic notification with very small cycle times causes DoS

### 6. ADS State Machine
- ADS state transitions (Init, Config, Run, Stop, Error)
- WriteControl can change device state without authentication
- State-dependent command acceptance varies by implementation

## Notable Research

- **"Hacking Beckhoff TwinCAT"** - Conference presentations on ADS protocol weaknesses
- **Beckhoff Security Advisories** - Multiple TwinCAT/ADS related issues
- **"ICS Protocol Security"** by Positive Technologies - Includes ADS/AMS analysis
- **Rapid7 Research** - CVE-2019-5636/5637: DoS via malformed UDP packets, discovered that nmap scanning can accidentally crash ADS Discovery Service
- **Nozomi Networks Labs** - 4 vulnerabilities in TwinCAT/BSD (2024): authentication bypass, XSS, privilege escalation, DoS
- [Orange Cyberdefense awesome-industrial-protocols](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols) -- Security-oriented industrial protocol reference including ADS

## Fuzzing Tools

- [Beckhoff/ADS](https://github.com/Beckhoff/ADS) -- Official Beckhoff ADS library (C/C++). Source code for building fuzz harnesses targeting AMS/ADS message parsing. Includes ADS command-line tool for crafting requests.
- [pyads](https://github.com/stlehmann/pyads) -- Python wrapper for ADS communication. Can be used to script malformed ADS requests for testing. Supports Read, Write, ReadState, WriteControl, and notification operations.
- [ads-client](https://github.com/jisotalo/ads-client) -- Node.js ADS/AMS client. Full AMS/TCP implementation that can be modified for fuzzing.
- No dedicated public ADS fuzzer exists. ADS/AMS has a straightforward framing: AMS/TCP header (2 reserved + 4 length), followed by 32-byte AMS header (Source/Target NetID+Port, Command ID, State Flags, Data Length, Error Code, Invoke ID), followed by command-specific data. This structure is easy to fuzz with boofuzz or custom scripts.

## Attack Surface Notes

### Most Dangerous Commands
- **ReadWrite (cmd 0x0009)** -- Combines read and write. Read length parameter controls response buffer allocation; write data is attacker-controlled. Mismatched read length + write length + actual data size is the #1 buffer overflow trigger.
- **Write (cmd 0x0003) with Index Group 0xF003** -- Multi-Read/Write batch operation. Contains multiple sub-requests each with their own Index Group/Offset/Length fields. Malformed sub-request structures (wrong count, overlapping offsets, mismatched lengths) stress the parser.
- **WriteControl (cmd 0x0005)** -- Changes PLC state (Run/Stop/Config). No authentication required. Direct process disruption.
- **AddDeviceNotification (cmd 0x0006)** -- Creates server-initiated data push with configurable cycle time. Very small cycle times (1ms) cause resource exhaustion. Large notification counts exhaust memory.
- **Read (cmd 0x0002) with system Index Groups (0xF000+)** -- System services that provide access to symbol tables, data types, and runtime information. Index Group 0xF003 particularly dangerous for batch operations.

### Most Commonly Vulnerable Fields
- **AMS/TCP Length (4 bytes)** -- Classic overflow trigger. No upper bound validation in many implementations (CVE-2019-5636 showed even empty packets crash the service). Zero length, maximum uint32, and values requiring TCP reassembly are all crash triggers.
- **Index Group / Index Offset (4+4 bytes)** -- These directly map to memory addresses in some implementations. System Index Groups (0xF000-0xFFFF) access internal data structures. Out-of-bounds offsets translate to arbitrary memory read/write.
- **AMS NetID (6 bytes)** -- Routing identifier. Spoofed NetIDs can reach devices behind AMS routers. NetID 0.0.0.0.0.0 and broadcast NetIDs trigger undefined behavior.
- **Data Length (4 bytes in AMS header)** -- Mismatch between stated data length and actual payload. Combined with Read/Write lengths for triple-validation failure potential.

### Known Weak Implementations
- **Beckhoff TwinCAT 2/3.1 ADS Discovery Service** -- CVE-2019-5636: Empty UDP packet removes routing table and shuts down the service. Routine nmap scanning can accidentally trigger this. CVE-2019-5637: Divide-by-zero crash from malformed UDP when PROFINET driver is active. Both show that the UDP interface has minimal input validation.
- **Beckhoff TwinCAT/BSD** -- Four CVEs in 2024 (Nozomi Networks): authentication bypass (CVE-2024-41173), XSS (CVE-2024-41174), DoS (CVE-2024-41175), command injection (CVE-2024-8934). The web management interface layered on top of ADS provides an additional attack surface. Auth bypass gives full PLC control.
- **ADS Protocol Design** -- Like FINS, ADS has zero built-in authentication. All ADS commands (Read, Write, WriteControl, state changes) are accepted from any source with a valid AMS route. The security model relies entirely on AMS routing tables and network segmentation, both of which can be subverted.
