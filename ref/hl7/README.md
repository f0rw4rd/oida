# HL7 (Health Level 7) - Reference Materials

## Protocol Overview

HL7 v2.x is the most widely deployed healthcare interoperability standard. It defines message formats for clinical and administrative data exchange between healthcare systems (EHR, LIS, RIS, PACS, etc.). HL7 v2 uses a pipe-delimited text format with MLLP (Minimal Lower Layer Protocol) transport.

- **Transport**: MLLP over TCP (typically port 2575) - Start Block (0x0B) + HL7 Message + End Block (0x1C) + CR (0x0D)
- **Message Format**: Segments separated by CR, fields by |, components by ^, sub-components by &, repetitions by ~
- **Message Types**: ADT (Admit/Discharge/Transfer), ORM (Order), ORU (Result), SIU (Scheduling), MDM (Document), etc.
- **Segments**: MSH (Message Header), PID (Patient ID), OBR (Observation Request), OBX (Observation Result), etc.
- **Encoding Characters**: Defined in MSH-2: |^~\& (field, component, repetition, escape, subcomponent)

## Wireshark Dissectors

- **HL7**: [packet-hl7.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-hl7.c)
- MLLP framing detection
- Segment parsing
- MSH header field extraction

### Key dissector details:
- MLLP Start Block (0x0B) / End Block (0x1C 0x0D) framing
- MSH segment parsing for encoding characters, message type, version
- Segment ID (3-char) + field parsing using MSH-defined separators
- Basic field/component/subcomponent splitting

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **python-hl7** | Python | HL7 v2.x parser | [github.com/johnpaulett/python-hl7](https://github.com/johnpaulett/python-hl7) |
| **HAPI** | Java | HL7 v2.x Java library (most widely used) | [github.com/hapifhir/hapi-hl7v2](https://github.com/hapifhir/hapi-hl7v2) |
| **Mirth Connect** | Java | HL7 integration engine | [github.com/nextgenhealthcare/connect](https://github.com/nextgenhealthcare/connect) |
| **nHapi** | C# | .NET HL7 v2.x library | [github.com/nHapiNET/nHapi](https://github.com/nHapiNET/nHapi) |
| **hl7apy** | Python | Python HL7 v2.x library | [github.com/crs4/hl7apy](https://github.com/crs4/hl7apy) |

## Common Parsing Vulnerabilities

### 1. MLLP Framing
- Missing Start Block (0x0B) or End Block (0x1C 0x0D)
- Multiple messages without proper framing
- Very large messages between Start/End blocks (memory exhaustion)
- Nested Start Block characters within message data

### 2. Encoding Character Redefinition
- MSH-1 (field separator) and MSH-2 (encoding characters) can redefine delimiters
- Custom delimiter characters that conflict with message content
- Escape sequences (\T\, \S\, \R\, \E\, \F\) with redefined characters
- MSH-2 with fewer than 4 encoding characters

### 3. Segment Parsing
- Segment ID not 3 characters
- Unknown/custom segment types (Z-segments)
- Extremely long segments (no length limit in spec)
- Segments with excessive field repetitions

### 4. Escape Sequence Handling
- \H\ (highlight), \N\ (normal) display characters
- \Xhh\ (hex encoding), \.br\ (line break)
- Nested escape sequences
- Unclosed escape sequences
- Custom escape sequences (\Zxxx\)

### 5. Message Type/Trigger Dispatch
- MSH-9 (Message Type): message code + trigger event + message structure
- Unknown message types triggering unhandled code paths
- Version-specific field definitions (v2.1 through v2.9)

### 6. Data Type Validation
- HL7 defines 80+ data types (ST, TX, FT, NM, DT, TM, TS, etc.)
- Date/time parsing with timezone offsets
- Numeric fields with non-numeric data
- Coded values with arbitrary code systems

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **IOActive/HL7-Fuzzer** | Python | HL7 message fuzzer with client and server modes. Generates mutated HL7 messages and sends them over MLLP. | [github.com/IOActive/HL7-Fuzzer](https://github.com/IOActive/HL7-Fuzzer) |
| **ehabhussein/HL7-fuzzer** | Python | Field-targeted HL7 fuzzer. Allows selecting specific fields to fuzz rather than random mutation. | [github.com/ehabhussein/HL7-fuzzer](https://github.com/ehabhussein/HL7-fuzzer) |
| **mechanico/hl7-mllp** | Python | MLLP injection and fuzzing toolkit. Builds "Evil Messages" with injection payloads (SQL, XSS, command injection) targeting specific HL7 fields. Includes `hl7_fuzz.py` (fuzzer) and `hl7_inject.py` (injector). | [github.com/mechanico/hl7-mllp](https://github.com/mechanico/hl7-mllp) |
| **anirudhduggal/medaudit** | Python | Medical device and healthcare infrastructure auditing tool with HL7 protocol support. | [github.com/anirudhduggal/medaudit](https://github.com/anirudhduggal/medaudit) |
| **Synopsys Defensics HL7v2** | Commercial | Commercial protocol fuzzer with HL7v2 server test suite. Generates thousands of malformed HL7 messages with systematic field mutation. | [synopsys.com/.../hl7v2-server](https://www.synopsys.com/software-integrity/security-testing/fuzz-testing/defensics/protocols/hl7v2-server.html) |

## Attack Surface Notes

### Protocol-Level Weaknesses
- **No authentication**: HL7/MLLP has no built-in authentication mechanism. Any host that can reach the MLLP port (typically 2575) can send and receive messages. This is by far the most exploited weakness.
- **No encryption**: HL7 messages transit in plaintext. Patient health information (PHI) including names, SSNs, diagnoses, and lab results are transmitted unencrypted by default.
- **No message integrity**: There is no MAC or signature on HL7 messages. Man-in-the-middle modification of messages (e.g., changing lab results) is trivial for a network-adjacent attacker.
- **No message size limits**: The MLLP framing allows arbitrarily large messages between 0x0B and 0x1C bytes, enabling memory exhaustion attacks.

### Key Attack Vectors for Fuzzing
1. **MLLP framing abuse**: Send data without proper 0x0B/0x1C framing, embed framing bytes within message data, or send multiple Start Block bytes without End Block -- tests connection state machine handling.
2. **MSH-1/MSH-2 delimiter redefinition**: Redefine the field separator and encoding characters to values that conflict with message content or are non-printable bytes. This stresses every downstream parser that relies on MSH-defined delimiters.
3. **Segment injection**: Insert unexpected segments (Z-segments, duplicate MSH segments, segments with non-3-char IDs) to test dispatch logic.
4. **Field injection via barcode readers**: Research has demonstrated injecting HL7 v2.x segments through connected barcode readers on patient monitors, allowing arbitrary observation results to be transmitted (see Insinuator research).
5. **HL7 XML encoding mode**: When XML encoding is negotiated, the XML parser becomes the attack surface -- XXE, SSRF, XML bombs, and billion laughs attacks apply.
6. **Java deserialization in integration engines**: Mirth Connect and similar Java-based HL7 engines use deserialization internally. Crafted payloads in message content or HTTP management APIs can chain to RCE (see CVE-2023-43208).

### Real-World Attack Demonstrations
- **Black Hat USA 2018 -- "Pestilential Protocol"**: Researchers Christian Dameff, Maxwell Bland, et al. demonstrated MitM attacks on HL7 messages between lab analyzers and EHR systems. They modified blood test results in transit, showing that altered HL7 messages could cause clinicians to administer dangerous treatments (e.g., insulin to a non-diabetic patient). ([Whitepaper PDF](https://i.blackhat.com/us-18/Thu-August-9/us-18-Dameff-Pestilential-Protocol-How-Unsecure-HL7-Messages-Threaten-Patient-Lives-wp.pdf))
- **Insinuator 2020 -- "HL7v2 Injections in Patient Monitors"**: Demonstrated injecting HL7 segments through barcode reader input on patient monitors, allowing arbitrary clinical data to be transmitted to downstream systems. ([Blog post](https://insinuator.net/2020/04/hl7v2-injections-in-patient-monitors/))

## Notable Research

- **"Pestilential Protocol: How Unsecure HL7 Messages Threaten Patient Lives"** - Black Hat USA 2018, Dameff et al. -- MitM attacks on HL7/MLLP modifying lab results
- **"HL7v2 Injections in Patient Monitors"** - Insinuator, 2020 -- barcode reader injection of HL7 segments
- **"Demonstration of new attacks on three healthcare network protocols"** - Journal of Computer Virology and Hacking Techniques, 2023 -- academic attacks on HL7, DICOM, and FHIR
- **"HL7 MLLP Security Considerations"** - HL7 International publications
- **CISA Healthcare Cybersecurity advisories** - ICS-CERT medical advisories for HL7-related devices
- **Orange Cyberdefense "awesome-industrial-protocols"** - [HL7 reference page](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/hl7.md)
