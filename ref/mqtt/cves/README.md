# MQTT - Notable CVEs

CVEs related to parsing and processing vulnerabilities in MQTT implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-28366 | Eclipse Mosquitto | Memory leak via QoS 2 messages with duplicate IDs when client fails to respond to PUBREC | DoS / Memory Exhaustion | 7.5 | [Mosquitto Advisory](https://mosquitto.org/blog/2023/08/version-2-0-16-released/) |
| CVE-2023-0809 | Eclipse Mosquitto | Excessive memory allocation from malicious initial packets that are not CONNECT packets | DoS | 5.3 | [Mosquitto Advisory](https://mosquitto.org/blog/2023/08/version-2-0-16-released/) |
| CVE-2023-3592 | Eclipse Mosquitto | Memory leak when clients send v5 CONNECT packets with will message containing invalid property types | DoS | 7.5 | [Mosquitto Advisory](https://mosquitto.org/blog/2023/08/version-2-0-16-released/) |
| CVE-2021-34432 | Eclipse Mosquitto | Crash when client sends PUBLISH packet with topic length of zero | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-34432) |
| CVE-2021-28166 | Eclipse Mosquitto | NULL pointer dereference from crafted CONNACK message sent by authenticated MQTT v5 client | DoS | 6.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-28166) |
| CVE-2019-11779 | Eclipse Mosquitto | Stack overflow from crafted SUBSCRIBE with topic containing ~65400+ '/' characters | Stack Overflow | 6.5 | [Mosquitto Advisory](https://mosquitto.org/blog/2019/09/version-1-6-6-released/) |
| CVE-2018-12543 | Eclipse Mosquitto | Broker crash via assertion failure when message topic starts with '$' but not '$SYS' | DoS | 6.5 | [Mosquitto Advisory](https://mosquitto.org/blog/2019/09/security-advisory-cve-2018-12543/) |
| CVE-2020-13849 | MQTT Protocol 3.1.1 | Keep-alive timeout abuse (SlowITe): attacker holds connections open, exhausting server capacity | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-13849) |
| CVE-2019-5432 | mqtt-packet (npm) | Crash from malformed SUBSCRIBE packet with invalid length encoding | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5432) |

## Exploits and PoCs

### CVE-2024-10525
- **Product**: Eclipse Mosquitto 1.3.2 through 2.0.18
- **Type**: Heap-Based Buffer Overflow / Out-of-Bounds Write
- **CVSS**: 9.8
- **Server-side**: Yes -- libmosquitto client library parses SUBACK packets from a malicious broker; if the SUBACK contains no reason codes, the on_subscribe callback performs out-of-bounds memory access
- **Root cause**: Missing validation that the SUBACK packet contains at least one reason code before indexing into the reason code array in `my_subscribe_callback` (sub_client.c)
- **PoC**: No public PoC (advisory only)
- **Metasploit**: N/A
- **Advisory**: [GitHub Advisory GHSA-cm54-mprw-5279](https://github.com/advisories/GHSA-cm54-mprw-5279)
- **Analysis**: A fuzzer sending SUBACK packets with zero reason codes would trigger this immediately. The parser trusts the broker response without bounds checking.

### CVE-2023-28366
- **Product**: Eclipse Mosquitto 1.3.2 to 2.0.15
- **Type**: Memory Leak / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- broker leaks memory when clients send QoS 2 PUBLISH messages with duplicate message IDs and never respond to PUBREC
- **Root cause**: QoS 2 message state machine does not free the original message when a duplicate message ID is received before the first completes the 4-way handshake
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Mosquitto Advisory](https://mosquitto.org/blog/2023/08/version-2-0-16-released/)
- **Analysis**: Fuzzing QoS 2 state transitions with duplicate packet IDs and incomplete handshakes triggers the leak. A stateful protocol fuzzer would catch this.

### CVE-2023-3592
- **Product**: Eclipse Mosquitto 1.6.0 to 2.0.15
- **Type**: Memory Leak / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- broker leaks memory when parsing MQTT v5 CONNECT packets where the will message contains invalid property types
- **Root cause**: Property parsing allocates memory for will properties but does not free them on validation failure for invalid property type identifiers
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Mosquitto Advisory](https://mosquitto.org/blog/2023/08/version-2-0-16-released/)
- **Analysis**: A v5 CONNECT packet fuzzer mutating property type identifiers in the will message payload would find this immediately.

### CVE-2021-34432
- **Product**: Eclipse Mosquitto
- **Type**: DoS (Crash)
- **CVSS**: 7.5
- **Server-side**: Yes -- broker crashes when it receives a PUBLISH packet with a topic length field of zero
- **Root cause**: Missing check for zero-length topic string before dereferencing the topic pointer
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-34432)
- **Analysis**: Trivial to find with any fuzzer: set the 2-byte topic length prefix to 0x0000 in a PUBLISH packet.

### CVE-2019-11779
- **Product**: Eclipse Mosquitto before 1.6.6
- **Type**: Stack Overflow
- **CVSS**: 6.5
- **Server-side**: Yes -- broker crashes from stack overflow when processing a SUBSCRIBE packet with a topic containing ~65400+ '/' characters
- **Root cause**: Recursive or deeply nested topic parsing with '/' separator exhausts stack space
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Mosquitto Advisory](https://mosquitto.org/blog/2019/09/version-1-6-6-released/)
- **Analysis**: A fuzzer generating extremely long topic strings with many '/' separators would trigger this stack exhaustion.

### CVE-2025-66023
- **Product**: NanoMQ MQTT Broker before 0.24.5
- **Type**: Heap Use-After-Free / DoS
- **CVSS**: N/A
- **Server-side**: Yes -- when NanoMQ acts as a bridge client connecting to a remote broker, a malicious remote broker can trigger a crash by accepting the connection and immediately sending a malformed packet sequence
- **Root cause**: Use-after-free in bridge client connection handling when receiving unexpected packet sequences during initial handshake
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-66023/)
- **Analysis**: Fuzzing the broker-to-broker bridge connection handshake with malformed packet sequences would trigger this UAF condition.

## Key Vulnerability Patterns for Fuzzing

1. **Variable-Length Encoding**: Remaining length with continuation bit on 4th byte, values exceeding 268MB, encoding of 0 as multi-byte
2. **CONNECT Flags Consistency**: Will flag/QoS/retain combinations, username/password flags without data
3. **UTF-8 String Validation**: Strings with invalid UTF-8 sequences, null bytes, control characters
4. **Topic Filter Wildcards**: + and # in invalid positions, extremely deep topic hierarchies
5. **MQTT v5 Properties**: Duplicate properties, unknown identifiers, length mismatches
6. **QoS 2 State Machine**: Out-of-order PUBREC/PUBREL/PUBCOMP, packet ID collisions
7. **Keep Alive Timing**: Keep alive = 0 (disabled), very small values causing rapid PING timeout
8. **Retained Message Accumulation**: Many retained messages exhausting broker storage
