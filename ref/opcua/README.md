# OPC UA (Open Platform Communications Unified Architecture) - Reference Materials

## Protocol Overview

OPC UA is a platform-independent, service-oriented architecture for industrial communication. It provides secure, reliable data transport with a rich information model. OPC UA supports both binary (UA Binary/TCP) and XML/SOAP (HTTP) encoding.

- **Transport**: TCP port 4840 (OPC UA Binary), HTTPS port 443 (alternative)
- **UA Binary Protocol**: Message header (type + chunk type + size) + Security header + Sequence header + Body
- **Message Types**: HEL (Hello), ACK, OPN (OpenSecureChannel), CLO (Close), MSG (Message)
- **Services**: Browse, Read, Write, Subscribe, Call, CreateSession, ActivateSession, etc.
- **Security**: X.509 certificates, message signing (HMAC-SHA256), encryption (AES-256-CBC)

## Wireshark Dissectors

- **OPC UA**: [packet-opcua.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-opcua.c)
- **OPC UA Transport**: [packet-opcua-transport.c](https://gitlab.com/wireshark/wireshark/-/blob/master/plugins/epan/opcua/opcua_transport_layer.c) (in plugins directory)
- The OPC UA dissector is a plugin located at: `plugins/epan/opcua/`
- Key files: `opcua.c`, `opcua_transport_layer.c`, `opcua_security_layer.c`, `opcua_application_layer.c`, `opcua_serviceparser.c`

### Key dissector details:
- Message header: type (3 bytes ASCII), chunk type (1 byte: 'F', 'C', 'A'), message size (4 bytes)
- Hello/Acknowledge handshake parsing
- OpenSecureChannel with security policy and mode
- Service request/response NodeId-based dispatch
- Chunking support for large messages
- ExtensionObject parsing with TypeId + encoding + body

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **open62541** | C | Open-source OPC UA reference implementation | [github.com/open62541/open62541](https://github.com/open62541/open62541) |
| **opcua-asyncio** | Python | Async OPC UA client/server for Python | [github.com/FreeOpcUa/opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) |
| **python-opcua** | Python | OPC UA client/server (legacy) | [github.com/FreeOpcUa/python-opcua](https://github.com/FreeOpcUa/python-opcua) |
| **node-opcua** | JavaScript | Full OPC UA stack for Node.js | [github.com/node-opcua/node-opcua](https://github.com/node-opcua/node-opcua) |
| **gopcua** | Go | OPC UA client/server in Go | [github.com/gopcua/opcua](https://github.com/gopcua/opcua) |
| **OPC Foundation UA Stack** | C/C#/Java | Official OPC Foundation reference stacks | [github.com/OPCFoundation](https://github.com/OPCFoundation) |

## Common Server-Side Parsing Vulnerabilities

### 1. Message Size Field
- 4-byte message size in header - maximum negotiated in Hello/Acknowledge
- Size exceeding negotiated MaxMessageSize
- Size=0 or size < minimum header size
- Size mismatched with TCP payload causing reassembly issues

### 2. Chunking and Reassembly
- Large messages split into chunks (Final 'F', Continue 'C', Abort 'A')
- Sequence number validation across chunks
- RequestId correlation across chunks of same message
- Memory exhaustion from never-completed chunk sequences
- Overlapping or out-of-order chunks

### 3. NodeId Encoding
- NodeId types: TwoByte, FourByte, Numeric, String, Guid, ByteString
- Extended NodeIds with NamespaceURI and ServerIndex
- Encoding byte determines NodeId type - invalid encoding byte values
- String/ByteString NodeIds with unbounded length

### 4. ExtensionObject Parsing
- TypeId (NodeId) + Encoding (byte) + Body Length + Body
- Encoding: 0x00 (null), 0x01 (binary), 0x02 (XML)
- TypeId referencing unknown types requires skipping body by length
- Nested ExtensionObjects in service parameters

### 5. Security Channel Attacks
- OpenSecureChannel with crafted SecurityPolicy URI
- Certificate validation bypass in some implementations
- Token renewal with modified security parameters
- Asymmetric vs. symmetric security header confusion

### 6. Service-Specific Issues
- Browse with deep recursion following references
- Read/Write with extremely large node lists
- CreateSubscription with very short intervals
- HistoryRead with excessive time ranges
- Call (method invocation) with type-mismatched arguments

### 7. Variant/DataValue Encoding
- OPC UA Variant supports 25+ built-in types
- Multi-dimensional arrays with dimension sizes exceeding data
- Matrix encoding with rank and dimension array
- Nested Variant types (Variant containing Variants)

## Notable Research

- **Claroty Team82 OPC UA research** - Multiple vulnerabilities in OPC UA stacks
- **JFrog Security Research** - OPC UA heap overflow and info leak in Unified Automation C++ SDK (Pwn2Own Miami 2022)
- **"OPC UA Security Analysis"** by Fraunhofer IOSB
- **S4 Conference** presentations on OPC UA security
- **OPC Foundation Security Bulletins** - Official vulnerability disclosures

## Fuzzing Tools

- [Claroty OPC UA Exploit Framework](https://github.com/claroty/opcua-exploit-framework) -- Advanced framework for OPC UA vulnerability research and exploitation; includes corpus samples from extensive fuzzing campaigns that reproduce discovered bugs; found ~50 CVEs across ~15 protocol stacks
- [Claroty OPC UA Network Fuzzer](https://github.com/claroty/opcua_network_fuzzer) -- Network fuzzer based on BooFuzz framework developed for Pwn2Own Miami 2022; specifically targets the OPC UA binary protocol
- [open62541 AFL Harness](https://github.com/open62541/open62541) -- open62541 includes built-in fuzzing harnesses for use with AFL and libFuzzer; found heap buffer overflows and other issues during fuzzing campaigns
- **Stateful OPC UA Fuzzer** (Radboud University, 2024 research paper) -- Demonstrated that stateless fuzzers miss 3 novel bugs that stateful fuzzing catches; highlights the importance of connection state for OPC UA security testing

## Attack Surface Notes

- **Most dangerous message types**: OpenSecureChannel (security policy negotiation, certificate handling), CreateSession/ActivateSession (identity token parsing), Browse/BrowseNext (continuation point state management), Call (method argument type parsing)
- **Most commonly vulnerable fields**: 4-byte message size (values 0, <header minimum, >MaxMessageSize), String/ByteString length prefixes (4-byte, -1 for null vs 0 vs MAX_INT), NodeId encoding byte (invalid type values), Variant array dimensions (product overflows)
- **Chunk reassembly**: Sending unlimited 'C' (Continue) chunks without 'F' (Final) exhausts memory (CVE-2022-25761). Sequence number gaps, abort chunks mid-stream, and final chunk without prior continues are all productive fuzzing patterns
- **Nested type recursion**: OPC UA allows Variant->Struct->Variant nesting to arbitrary depth. This is the root cause of CVE-2021-27432 (stack overflow) and CVE-2020-36429 (OOB write). Any fuzzer must test recursive type nesting
- **Security handshake**: The OpenSecureChannel phase with different security policies is a rich target. Deprecated policies like Basic128Rsa15 have led to authentication bypass (CVE-2024-42512). Asymmetric security headers with oversized certificate fields are common crash vectors
- **Vendor-specific weak spots**: OPC Foundation .NET Standard Stack has the most CVEs (CVE-2022-29862/29863/29864, CVE-2021-27432, CVE-2023-27321). Softing C++ SDK had UAF in browse continuation points (CVE-2022-39823). open62541 had chunk limit and JSON encoding issues
- **XML encoding mode**: Though rarely used in production, XML/SOAP encoding mode is still supported and has XXE vulnerabilities (CVE-2018-12585)
