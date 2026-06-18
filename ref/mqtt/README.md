# MQTT (Message Queuing Telemetry Transport) - Reference Materials

## Protocol Overview

MQTT is a lightweight publish/subscribe messaging protocol designed for constrained devices and unreliable networks. Widely used in IoT, home automation, and industrial telemetry. MQTT v3.1.1 (ISO/IEC 20922) and MQTT v5.0 are the current standards.

- **Transport**: TCP port 1883 (plain), TCP port 8883 (TLS)
- **Fixed Header**: Packet type (4 bits) + flags (4 bits) + remaining length (1-4 bytes, variable-length encoding)
- **Packet Types**: CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT
- **QoS Levels**: 0 (at most once), 1 (at least once), 2 (exactly once)

## Wireshark Dissectors

- **MQTT**: [packet-mqtt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mqtt.c)
- Supports MQTT v3.1, v3.1.1, and v5.0
- Full packet type parsing with QoS handling
- MQTT v5.0 properties parsing

### Key dissector details:
- Variable-length "remaining length" encoding (7 bits per byte, continuation bit)
- CONNECT packet: Protocol name, version, connect flags, keep alive, payload
- PUBLISH: Topic filter, packet ID (QoS 1/2), payload
- SUBSCRIBE: Topic filter + QoS pairs
- MQTT v5.0: Property length + property key-value pairs

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **mosquitto** | C | Eclipse Mosquitto MQTT broker | [github.com/eclipse/mosquitto](https://github.com/eclipse/mosquitto) |
| **paho.mqtt** | Python/Java/C | Eclipse Paho MQTT clients | [github.com/eclipse/paho.mqtt.python](https://github.com/eclipse/paho.mqtt.python) |
| **EMQX** | Erlang | High-performance MQTT broker | [github.com/emqx/emqx](https://github.com/emqx/emqx) |
| **VerneMQ** | Erlang | Distributed MQTT broker | [github.com/vernemq/vernemq](https://github.com/vernemq/vernemq) |
| **Scapy** | Python | MQTT contrib layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **gmqtt** | Go | Go MQTT client/server | [github.com/DrmagicE/gmqtt](https://github.com/DrmagicE/gmqtt) |
| **rumqtt** | Rust | Rust MQTT client | [github.com/bytebeamio/rumqtt](https://github.com/bytebeamio/rumqtt) |

## Common Parsing Vulnerabilities

### 1. Variable-Length Encoding (Remaining Length)
- 1-4 bytes, 7 bits per byte, MSB is continuation flag
- Maximum value: 268,435,455 (0x0FFFFFFF)
- Invalid encoding: continuation bit set on 4th byte
- Length = 0 for packets that require payload
- Encoded value exceeding maximum or actual TCP data

### 2. CONNECT Packet Parsing
- Protocol name length prefix + string ("MQTT" or "MQIsdp")
- Connect flags byte: conflicting flag combinations (e.g., will QoS without will flag)
- Client ID length: 0-23 chars recommended but not enforced
- Will topic/message with length prefixes
- Username/password with length prefixes - present flags vs. actual payload

### 3. Topic String Handling
- UTF-8 encoded with 2-byte length prefix
- Wildcards: + (single level), # (multi-level, must be last)
- Topics with null bytes, control characters, excessively long names
- Topic filter matching with mixed wildcard/literal segments
- Empty topics or topics starting/ending with /

### 4. MQTT v5.0 Properties
- Property length (variable-length encoding) + key-value pairs
- Property identifier (1 byte) determines value type
- Unknown property identifiers
- Duplicate properties where only one is allowed
- Property length mismatch with sum of encoded properties

### 5. QoS State Machine
- QoS 2 requires PUBLISH -> PUBREC -> PUBREL -> PUBCOMP
- Missing or duplicated steps in the 4-way handshake
- Packet ID reuse before completion
- QoS downgrade by broker not handled by client

### 6. Retained Messages and Sessions
- Retained message flag with empty payload (clear retained)
- Clean session flag interaction with client ID
- Session state overflow from accumulated messages

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **mqtt_fuzz** | Python | WithSecure fuzzer using Radamsa for mutation-based MQTT fuzzing | [github.com/WithSecureOpenSource/mqtt_fuzz](https://github.com/WithSecureOpenSource/mqtt_fuzz) |
| **FUME** | Python | Generation-guided and mutation-guided fuzzing framework for MQTT brokers, modeled as finite state machine | [github.com/PBearson/FUME-Fuzzing-MQTT-Brokers](https://github.com/PBearson/FUME-Fuzzing-MQTT-Brokers) |
| **MosquittoByte** | Python | Mutation-based fuzzer specifically targeting Mosquitto broker | [github.com/PBearson/MosquittoByte](https://github.com/PBearson/MosquittoByte) |
| **FuzzTT (mqtt-fuzzer)** | Python | TCP proxy that captures MQTT traffic (v3.1 and v5.0) and sends fuzz-controlled packets to broker or client | [github.com/certuscyber/mqtt-fuzzer](https://github.com/certuscyber/mqtt-fuzzer) |
| **mqtt_fuzzing** | Python | Black-box network fuzzer adaptable for MQTT and other protocols | [github.com/ramsaut/mqtt_fuzzing](https://github.com/ramsaut/mqtt_fuzzing) |
| **netsecuritylab/mqtt** | Python | Academic MQTT fuzzer from ITASEC21 paper on security assessment of MQTT brokers | [github.com/netsecuritylab/mqtt](https://github.com/netsecuritylab/mqtt) |

## Attack Surface Notes

### Server-Side (Broker) Parsing Targets
- **CONNECT packet**: Protocol name, version, flags byte, keep-alive, client ID, will topic/message, username/password -- all with length-prefixed fields that can be mutated
- **PUBLISH packet**: Topic string (2-byte length prefix), packet ID, payload -- zero-length topics crash Mosquitto (CVE-2021-34432)
- **SUBSCRIBE packet**: Topic filter strings with wildcards -- deeply nested '/' separators cause stack overflow (CVE-2019-11779)
- **MQTT v5 Properties**: Property length + key-value pairs -- invalid property types in will messages cause memory leaks (CVE-2023-3592)
- **Non-CONNECT initial packets**: Sending non-CONNECT packets as first message triggers excessive memory allocation (CVE-2023-0809)
- **QoS 2 state machine**: Duplicate message IDs without completing handshake cause memory leaks (CVE-2023-28366)

### Protocol-Level Attack Vectors
- **Variable-length encoding abuse**: Remaining length field using 1-4 bytes with continuation bits -- malformed encoding can cause infinite loops or integer overflows
- **Connection exhaustion (SlowITe)**: Keep-alive timeout abuse holding connections open (CVE-2020-13849)
- **Retained message flooding**: Accumulated retained messages exhausting broker storage
- **Topic string injection**: Null bytes, control characters, and invalid UTF-8 in topic names

## Notable Research

- **"Practical MQTT Exploitation" (BlackHat/DEF CON)** - Various presentations
- **"MQTT Security: A Novel Fuzzing Approach"** - Academic fuzzing papers
- **"Program-aware fuzzing for MQTT applications" (ISSTA 2020)** - Grammar-based MQTT fuzzing
- **Eclipse Mosquitto Security Advisories**
- **EMQX Security Bulletins**
