# DICOM (Digital Imaging and Communications in Medicine) - Reference Materials

## Protocol Overview

DICOM is the standard for medical imaging communication. It defines both a file format and a network protocol for transmitting medical images and associated data between devices (CT scanners, MRI, PACS, viewers). The network protocol uses a complex association negotiation and service-oriented architecture.

- **Transport**: TCP port 104 (default), also 11112 (common alternative)
- **Association**: A-ASSOCIATE-RQ/AC/RJ for connection establishment with negotiation
- **DIMSE Services**: C-STORE, C-FIND, C-MOVE, C-GET, C-ECHO, N-CREATE, N-SET, N-GET, N-DELETE, N-ACTION, N-EVENT-REPORT
- **Transfer Syntaxes**: Implicit VR Little Endian, Explicit VR Little Endian, JPEG, JPEG2000, etc.
- **PDU Types**: A-ASSOCIATE-RQ (01), A-ASSOCIATE-AC (02), A-ASSOCIATE-RJ (03), P-DATA-TF (04), A-RELEASE-RQ (05), A-RELEASE-RP (06), A-ABORT (07)

## Wireshark Dissectors

- **DICOM**: [packet-dcm.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dcm.c)
- Association negotiation parsing
- DIMSE message decoding
- Data element (tag, VR, length, value) parsing
- Transfer syntax-aware value interpretation

### Key dissector details:
- PDU header: type (1), reserved (1), length (4)
- Association items: type (1), reserved (1), length (2), data
- Presentation context negotiation (abstract/transfer syntax)
- Data element parsing: group (2), element (2), VR (2), length (2/4), value
- Implicit vs Explicit VR handling

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **pydicom** | Python | Python DICOM library | [github.com/pydicom/pydicom](https://github.com/pydicom/pydicom) |
| **DCMTK** | C++ | OFFIS DICOM Toolkit (reference implementation) | [github.com/DCMTK/dcmtk](https://github.com/DCMTK/dcmtk) |
| **fo-dicom** | C# | .NET DICOM library | [github.com/fo-dicom/fo-dicom](https://github.com/fo-dicom/fo-dicom) |
| **Orthanc** | C++ | DICOM server | [github.com/jodogne/OrthancMirror](https://github.com/jodogne/OrthancMirror) |
| **dcm4che** | Java | Java DICOM library | [github.com/dcm4che/dcm4che](https://github.com/dcm4che/dcm4che) |
| **GDCM** | C++ | Grassroots DICOM library | [github.com/malaterre/GDCM](https://github.com/malaterre/GDCM) |

## Common Parsing Vulnerabilities

### 1. PDU Length Field
- 4-byte PDU length field (maximum ~4GB per PDU)
- Length exceeding available memory
- Length=0 for PDUs requiring data
- P-DATA-TF PDUs with mismatched PDV (Presentation Data Value) lengths

### 2. Association Negotiation
- Presentation contexts with unknown abstract syntaxes or transfer syntaxes
- Excessive number of proposed presentation contexts
- Role selection items with conflicting roles
- Maximum PDU size negotiation with extreme values (0, very large)
- User Identity negotiation with crafted credentials

### 3. Data Element Parsing
- Implicit VR: parser must look up VR from data dictionary (unknown private tags)
- Explicit VR: 2-byte VR field followed by length (2 or 4 bytes depending on VR)
- Sequence (SQ) items with undefined length (0xFFFFFFFF) requiring delimiter items
- Nested sequences creating deep recursion
- Private data elements (odd group numbers) with arbitrary content

### 4. Transfer Syntax Issues
- Implicit VR Little Endian (default): all elements have implicit VR
- Big Endian vs Little Endian confusion
- Encapsulated pixel data (JPEG, JPEG2000) with frame fragments
- Deflated transfer syntax (zlib compressed dataset)

### 5. DIMSE Service-Specific
- C-STORE with very large pixel data (multi-frame images)
- C-FIND with crafted query attributes causing excessive results
- C-MOVE to arbitrary AE titles (data redirection)
- N-ACTION triggering server-side operations

### 6. Pixel Data
- Pixel data (7FE0,0010) with frames, fragments, and offset table
- Bits Allocated/Stored/High Bit inconsistencies
- Planar configuration + samples per pixel combinations
- Compressed pixel data with malformed codec stream

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **r1b/dicom-fuzz** | Python | DICOM format and network protocol fuzzer. Strips image data to create lightweight test cases, then mutates DICOM metadata and structure. | [github.com/r1b/dicom-fuzz](https://github.com/r1b/dicom-fuzz) |
| **RUB-NDS/medfuzz** | Python/C | Medical protocol fuzzing platform. Automates building fuzzing-capable versions of DCMTK (with AFL) and fo-dicom (with SharpFuzz). Manages corpus, fuzzing orchestration, and network communication with targets. | [github.com/RUB-NDS/medfuzz](https://github.com/RUB-NDS/medfuzz) |
| **AFLNet** | C | Greybox network protocol fuzzer with state-feedback. Supports DICOM as a target protocol. Uses mutation-based fuzzing with code coverage and protocol state tracking to explore server state machines. | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **StateAFL** | C | Stateful network server fuzzer. Maximizes both code coverage and protocol state coverage. Applicable to DICOM servers via DIMSE service interaction. | [github.com/stateafl/stateafl](https://github.com/stateafl/stateafl) |
| **DICOM-Fuzzer (academic)** | -- | Research prototype for DICOM vulnerability mining with test case generation, automated testing, and exception monitoring. Described in "Medical Protocol Security: DICOM Vulnerability Mining Based on Fuzzing Technology" (Springer/ACM 2019). | [Paper](https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38) |
| **kosmokato/bad-dicom** | Python | Exploitation framework for CVE-2019-11687 (GDCM heap overflow). Handcrafts malicious DICOM files with crafted JPEG pixel data. | [github.com/kosmokato/bad-dicom](https://github.com/kosmokato/bad-dicom) |

## Attack Surface Notes

### Network Protocol Attack Surface
- **Association negotiation (A-ASSOCIATE-RQ)**: The initial handshake contains Presentation Context items (abstract syntax + transfer syntax proposals), User Information items (max PDU size, implementation class UID), and optional User Identity negotiation. All of these fields are attacker-controlled and parsed by the server before any authentication occurs.
- **DIMSE services over P-DATA-TF**: After association, DIMSE commands (C-STORE, C-FIND, C-MOVE, C-GET, C-ECHO, N-* services) carry DICOM datasets. Each dataset is a tree of data elements with tag, VR, length, and value. The server must parse these without crashing or corrupting memory.
- **C-STORE as file write primitive**: C-STORE sends a DICOM file to the server for storage. The SOP Instance UID is commonly used as the filename. Path traversal in the UID (e.g., `../../etc/cron.d/payload`) has been exploited in DCMTK and Orthanc to write arbitrary files (see CVE-2022-2119, CVE-2023-33466).
- **C-MOVE/C-GET data redirection**: C-MOVE instructs the server to send images to a third-party AE Title. An attacker can redirect patient imaging data to an attacker-controlled destination.
- **No authentication by default**: Most DICOM implementations rely on AE Title matching for "authentication," which is trivially spoofable. The DICOM standard's security profiles (TLS, Kerberos) are rarely deployed. Orthanc CVE-2025-0896 (CVSS 9.8) demonstrated that hundreds of PACS servers are exposed to the internet without any authentication.

### File Format Attack Surface
- **Data element parsing**: Each DICOM data element has a tag (group, element), optional VR (2 bytes), and length field. The length field determines how many bytes to read for the value. Mismatches between declared length and actual data cause buffer overflows (CVE-2024-47796, CVE-2024-52333 in DCMTK).
- **Sequence (SQ) nesting**: Sequences can nest arbitrarily deep. Each level adds stack frames in recursive parsers. Deeply nested SQ items cause stack exhaustion.
- **Encapsulated pixel data**: Compressed pixel data (JPEG, JPEG2000, JPEG-LS, RLE) is stored in fragments within the (7FE0,0010) element. Malformed codec streams trigger bugs in decompression libraries (CVE-2019-11687 in GDCM, CVE-2025-2357 in DCMTK JPEG-LS decoder).
- **Duplicate tags**: The DICOM standard does not permit duplicate tags, but parsers must handle them. libdicom's use-after-free (CVE-2024-24793) was triggered by duplicate tags causing premature memory deallocation.
- **Integer underflows in fragment offsets**: The Basic Offset Table in encapsulated pixel data uses offsets into the fragment data. Unsigned integer underflow in offset arithmetic causes out-of-bounds writes (CVE-2025-11266 in GDCM).
- **Metadata/dimension inconsistency**: Fields like Rows, Columns, BitsAllocated, BitsStored, SamplesPerPixel, and PlanarConfiguration must be consistent with the actual pixel data size. Inconsistencies cause buffer overflows in image rendering code.

### Key Fuzzing Strategies for DICOM
1. **File format fuzzing**: Generate valid DICOM files and mutate data element lengths, VR types, sequence nesting depth, pixel data fragment offsets, and image dimension metadata. Target DCMTK, GDCM, pydicom, fo-dicom.
2. **Network protocol fuzzing**: Use AFLNet or StateAFL against DICOM servers (Orthanc, DCMTK storescp/findscp). Mutate association negotiation PDUs and DIMSE command datasets.
3. **Codec fuzzing**: Fuzz the embedded image codecs (JPEG, JPEG2000, JPEG-LS, RLE) with malformed compressed streams embedded in DICOM pixel data elements.
4. **Path traversal in UIDs**: Systematically inject path traversal sequences (`../`, `..\\`, URL-encoded variants) into SOP Instance UID, Study Instance UID, and other UIDs used in filesystem paths.
5. **Polyglot file attacks**: Create files that are simultaneously valid DICOM instances and valid configuration files (JSON, XML, Lua) for the target PACS server.

## Notable Research

- **"Hacking Healthcare" presentations** - DICOM security research at security conferences
- **"Exploiting Healthcare Servers with Polyglot Files"** - Shielder, 2023 -- CVE-2023-33466 Orthanc RCE via DICOM/JSON polyglot ([blog](https://www.shielder.com/blog/2023/10/cve-2023-33466-exploiting-healthcare-servers-with-polyglot-files/))
- **"Hacking Medical Imaging with DICOM"** - sdnewhop, AISec 2019 -- attack surface analysis of DICOM protocol and implementations ([slides](https://sdnewhop.github.io/AISec/slides/zn-2019-hm.pdf))
- **"Medical Protocol Security: DICOM Vulnerability Mining Based on Fuzzing Technology"** - Springer/ACM CCS 2019 -- systematic DICOM fuzzing framework ([paper](https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38))
- **"Uncovering New Vulnerabilities in PACS Servers and DICOM Viewers"** - TXOne Networks, 2025 -- analysis of PACS server exposure and recent vulnerabilities ([blog](https://www.txone.com/blog/uncovering-new-vulnerabilities-in-pacs-servers-and-dicom-viewers/))
- **"Pentesting of DICOM Software"** - binsec GmbH -- commercial DICOM penetration testing methodology ([page](https://binsec.com/en/projects/penetration-testing-dicom-medical-image-exchange-software/))
- **CISA ICS-CERT ICSMA advisories** - Medical device DICOM vulnerabilities (DCMTK, Orthanc, Philips, MedDream, Sante, MicroDicom)
- **"DICOM Security Profiles"** - Part 15 of DICOM standard
- **Orthanc security bulletins** - [book.orthanc-server.com/faq/security](https://book.orthanc-server.com/faq/security.html)
- **Cisco Talos DCMTK research** - Multiple DCMTK vulnerabilities discovered by Emmanuel Tacheau in 2024 ([blog](https://blog.talosintelligence.com/whatsup-gold-observium-offis-vulnerabilities/))
