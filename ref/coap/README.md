# CoAP (Constrained Application Protocol) - Reference Materials

## Protocol Overview

CoAP (RFC 7252) is a lightweight RESTful protocol designed for constrained IoT devices. It uses UDP for transport and follows a request/response model similar to HTTP but with much lower overhead. CoAP supports observe (publish/subscribe), block-wise transfer, and resource discovery.

- **Transport**: UDP port 5683 (plain), UDP port 5684 (DTLS)
- **Header**: Version (2 bits) + Type (2 bits) + Token Length (4 bits) + Code (8 bits) + Message ID (16 bits)
- **Types**: CON (Confirmable), NON (Non-confirmable), ACK, RST
- **Methods**: GET (0.01), POST (0.02), PUT (0.03), DELETE (0.04), FETCH (0.05), PATCH (0.06), iPATCH (0.07)
- **Options**: Delta-encoded, TLV format with delta + length + value

## Wireshark Dissectors

- **CoAP**: [packet-coap.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-coap.c)
- Full option parsing with delta-decoded option numbers
- Block-wise transfer (Block1/Block2) support
- Observe notification tracking
- OSCORE (Object Security for Constrained RESTful Environments) support

### Key dissector details:
- 4-byte fixed header parsing
- Token (0-8 bytes) based on TKL field
- Option delta-decoding: running sum of delta values
- Extended delta/length encoding (13=+1 byte, 14=+2 bytes, 15=reserved)
- Payload marker (0xFF) separates options from payload

## Open-Source Parsers and Implementations

| Project | Language | Description | CVE History | Link |
|---------|----------|-------------|-------------|------|
| **libcoap** | C | Reference CoAP implementation. Integrated with OSS-Fuzz for continuous fuzzing. | CVE-2024-0962, CVE-2024-31031, CVE-2025-34468, CVE-2023-51847 | [github.com/obgm/libcoap](https://github.com/obgm/libcoap) |
| **Arm mbed-coap** | C | CoAP library for Mbed OS. Heavy CVE history in option parser (`sn_coap_parser_options_parse`). | CVE-2019-17211, CVE-2019-17212, CVE-2020-12883 through CVE-2020-12887 | [github.com/ARMmbed/mbed-coap](https://github.com/ARMmbed/mbed-coap) |
| **Eclipse Californium** | Java | Full CoAP/DTLS framework for cloud and gateway deployments. | CVE-2022-2576, CVE-2022-39368 | [github.com/eclipse-californium/californium](https://github.com/eclipse-californium/californium) |
| **Eclipse Wakaama** | C | LwM2M client/server with embedded CoAP parser (er-coap-13). | CVE-2019-9004, CVE-2021-41040 | [github.com/eclipse-wakaama/wakaama](https://github.com/eclipse-wakaama/wakaama) |
| **RIOT OS nanocoap/gcoap** | C | Minimal CoAP for RIOT RTOS. gcoap adds proxy/observe. | CVE-2024-32017, CVE-2024-31225, nanocoap options overflow (no CVE) | [github.com/RIOT-OS/RIOT](https://github.com/RIOT-OS/RIOT) |
| **Zephyr RTOS net/coap** | C | CoAP implementation in Zephyr networking stack. | CVE-2020-10063 | [github.com/zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) |
| **FreeCoAP** | C | Lightweight CoAP for embedded systems. | CVE-2024-40494 | [github.com/keith-cullen/FreeCoAP](https://github.com/keith-cullen/FreeCoAP) |
| **Contiki-NG Erbium** | C | CoAP (Erbium) implementation for Contiki-NG OS. Known OOB issues in `coap_parse_message()`. | No assigned CVEs for CoAP parser (issues #1312, #1314 open) | [github.com/contiki-ng/contiki-ng](https://github.com/contiki-ng/contiki-ng) |
| **CoAPthon** | Python | Python 2 CoAP library. | CVE-2018-12680 | [github.com/Tanganelli/CoAPthon](https://github.com/Tanganelli/CoAPthon) |
| **CoAPthon3** | Python | Python 3 CoAP library. | CVE-2018-12679 | [github.com/Tanganelli/CoAPthon3](https://github.com/Tanganelli/CoAPthon3) |
| **aiocoap** | Python | Async CoAP client/server | No known CVEs | [github.com/chrysn/aiocoap](https://github.com/chrysn/aiocoap) |
| **go-coap** | Go | Go CoAP library (plgd-dev) | No known CVEs | [github.com/plgd-dev/go-coap](https://github.com/plgd-dev/go-coap) |
| **node-coap** | JavaScript | Node.js CoAP client/server | No known CVEs | [github.com/coapjs/node-coap](https://github.com/coapjs/node-coap) |
| **microcoap** | C | Minimal CoAP for microcontrollers (server-only) | No known CVEs | [github.com/1248/microcoap](https://github.com/1248/microcoap) |
| **ncoap** | Java | Java CoAP implementation | No known CVEs | [github.com/okleine/nCoAP](https://github.com/okleine/nCoAP) |

## Common Parsing Vulnerabilities

### 1. Option Delta/Length Encoding
- Delta and length each use 4-bit values with extended encoding
- Delta 13: next byte + 13; Delta 14: next 2 bytes + 269; Delta 15: reserved (payload marker or error)
- Length uses same encoding scheme
- Miscomputed option numbers due to incorrect delta accumulation
- Extended encoding values that overflow when added to base
- **CVE examples**: CVE-2020-10063 (Zephyr uint16_t overflow), CVE-2020-12887 (Mbed OS wraparound), CVE-2020-12883 (Mbed OS OOB read)

### 2. Token Length Field
- TKL (4 bits) should be 0-8; values 9-15 are reserved
- TKL mismatch with actual token bytes available
- TKL=0 with token-dependent operations (observe, block)
- **CVE example**: CVE-2020-12886 (Mbed OS OOB read from unchecked TKL)

### 3. Block-Wise Transfer (RFC 7959)
- Block options: NUM (variable) + M (more flag) + SZX (3 bits size exponent)
- Block number overflow with large transfers
- Size2/Size1 options mismatched with actual payload sizes
- Interleaved Block1 and Block2 in single exchange

### 4. Observe (RFC 7641)
- Observe option: Register (0), Deregister (1)
- Notification ordering via observe sequence numbers (24-bit)
- Replay of old notifications with stale sequence numbers
- Resource exhaustion from many concurrent observations

### 5. URI Processing
- Uri-Host, Uri-Port, Uri-Path, Uri-Query as separate options
- Path segments reconstructed by concatenation - traversal via "../"
- Percent-encoding handling inconsistencies
- Proxy-Uri with arbitrary target URLs
- **CVE examples**: CVE-2025-34468 (libcoap hostname overflow), CVE-2024-32017 (RIOT Proxy-Uri overflow)

### 6. Payload Marker
- 0xFF byte separates options from payload
- Payload marker without subsequent data
- Multiple payload markers
- Options appearing after payload marker

### 7. Repeatable Option Handling
- Some options (Uri-Path, Uri-Query, ETag) can appear multiple times
- Others (Content-Format, Accept) must appear at most once
- Missing duplicate detection causes memory corruption
- **CVE examples**: CVE-2020-12884 (Mbed OS OOB in multi-option parse), CVE-2024-32017 (RIOT ETag overflow)

### 8. CoAP Response Payload Processing
- Servers processing CoAP responses (e.g., from Resource Directories) must validate payload sizes
- **CVE example**: CVE-2024-31225 (RIOT cord_lc overflow from oversized RD response)

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **FuzzCoAP** | Python | Black-box CoAP server fuzzer with 5 techniques: Random, Informed Random, Mutational, Smart Mutational, Generational. Found 100 failures across 14 of 25 tested implementations | [github.com/bsmelo/fuzzcoap](https://github.com/bsmelo/fuzzcoap) |
| **U-Fuzz** | Python | Universal IoT protocol fuzzer supporting CoAP, Zigbee, 5G NR. Discovered 5 CoAP CVEs across Jcoap, Canopus, and libcoap implementations | [github.com/asset-group/U-Fuzz](https://github.com/asset-group/U-Fuzz) |
| **Cotopaxi** | Python | IoT protocol security testing toolkit (Samsung). Includes CoAP vulnerability checks for CoAPthon and Erbium. DEF CON 28 demo | [github.com/Samsung/cotopaxi](https://github.com/Samsung/cotopaxi) |
| **libcoap fuzzing (OSS-Fuzz)** | C | libcoap's own fuzzing harness integrated with Google OSS-Fuzz for continuous fuzzing. Harnesses in the libcoap repo, build scripts in oss-fuzz repo | [github.com/obgm/libcoap](https://github.com/obgm/libcoap) |
| **AFLNet** | C | Coverage- and state-guided protocol fuzzer. Supports CoAP among other protocols. Extended by Logos and ChatAFL | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **Logos** | Python/C | Log-guided protocol fuzzer extending AFLNet. Supports CoAP, MQTT, RTPS. Uses log analysis to guide state exploration | [ISSTA 2024 paper](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/paper_from_24/Logos_issta24.pdf) |
| **IoTFuzzSentry** | Python | Protocol-guided mutation-based lexical fuzzer for commercial IoT devices. Integrated with Cotopaxi. Tested on IP cameras and Smart Plugs | [arxiv.org/html/2509.09158v1](https://arxiv.org/html/2509.09158v1) |

## Attack Surface Notes

### Server-Side Parsing Targets (by priority)

**Critical -- direct packet parsing, no auth required:**
- **Option delta/length encoding**: 4-bit delta/length with extended encoding (13, 14, 15 prefixes) -- integer overflows in delta accumulation crash Zephyr RTOS (CVE-2020-10063) and Mbed OS (CVE-2019-17212, CVE-2020-12887); OOB reads from truncated extended fields (CVE-2020-12883)
- **Token Length (TKL) field**: 4-bit field should be 0-8; reserved values 9-15 cause parser confusion; unchecked TKL vs packet size (CVE-2020-12886)
- **Repeatable option parsing**: Options like Uri-Path, ETag parsed in loops with unchecked pointer advancement (CVE-2020-12884) and missing size checks before memcpy (CVE-2024-32017)
- **Zero-length allocation edge case**: Option values that compute to zero-sized heap allocations trigger infinite loops (CVE-2020-12885)
- **Deserialization exception handling**: Python implementations crash on unhandled exceptions from any malformed field (CVE-2018-12679, CVE-2018-12680)

**High -- triggered by specific message flows:**
- **OSCORE configuration**: Stack overflow in libcoap OSCORE config handler (CVE-2024-0962)
- **Address resolution**: Oversized hostnames in Uri-Host cause stack buffer overflow in libcoap (CVE-2025-34468)
- **PDU size computation**: Integer overflow in libcoap coap_pdu.c (CVE-2024-31031)
- **CoAP message parsing**: Stack buffer overflow in FreeCoAP coap_msg.c (CVE-2024-40494)
- **CoRE Link Format responses**: Oversized payloads from Resource Directories overflow static buffers in RIOT (CVE-2024-31225)

**Medium -- protocol state or timing dependent:**
- **DTLS handshake failures**: Repeated failed handshakes leak throttle counters, causing permanent DoS in Californium (CVE-2022-39368)
- **Thread-safe context exhaustion**: Resource exhaustion in libcoap's thread-safe mode (CVE-2023-51847)
- **LwM2M/Wakaama parser**: OOB reads from unsanitized data (CVE-2021-41040), memory leaks from invalid options (CVE-2019-9004)

### Protocol-Level Attack Vectors
- **Amplification**: CoAP over UDP with NoSec mode enables ~34x average amplification factor via IP spoofing (21-byte GET yields ~720-byte response). As of 2019, ~388,000 CoAP devices were internet-accessible. IETF draft [draft-irtf-t2trg-amplification-attacks](https://datatracker.ietf.org/doc/draft-irtf-t2trg-amplification-attacks/) documents this. Mitigated by Echo option (RFC 9175) or not using NoSec mode.
- **Observe flooding**: Resource exhaustion from many concurrent observe subscriptions
- **Proxy-Uri abuse**: Proxy-Uri option with arbitrary target URLs enables SSRF-like attacks
- **Path traversal**: Uri-Path option sequences with ".." segments for directory traversal

### Implementation-Specific Notes

**Mbed OS (mbed-coap)** -- Highest CVE density of any CoAP implementation. The `sn_coap_parser_options_parse()` family of functions had systemic issues: no bounds checking on option reads, no overflow detection on delta accumulation, no validation of TKL vs packet size. All 7 CVEs (2019-17211, 2019-17212, 2020-12883 through 2020-12887) found in the same parser codebase. Fix in [mbed-coap PR #116](https://github.com/ARMmbed/mbed-coap/pull/116).

**RIOT OS (gcoap/nanocoap/cord)** -- Multiple buffer overflows in the application-layer CoAP modules. The nanocoap options buffer overflow (issue #10753, no CVE) predates the gcoap overflows (CVE-2024-32017) and cord_lc overflow (CVE-2024-31225). All stem from missing size checks before memcpy operations. Reported by HN Security in January 2024.

**Eclipse Wakaama** -- Uses a vendored copy of Erbium CoAP parser (er-coap-13). Both CVE-2019-9004 (memory leak) and CVE-2021-41040 (OOB read) affect the same parser. The only official release (1.0) is unsupported; users must use HEAD of main.

**Contiki-NG Erbium** -- Known OOB read (issue #1312) and OOB write (issue #1314) in `coap_parse_message()` reported in 2020. No CVEs assigned despite being confirmed vulnerabilities. The Samsung Cotopaxi project tracks three Erbium memory corruption bugs (ER_COAP_000, ER_COAP_001, ER_COAP_002) also without CVE assignment. These are live fuzzing targets.

**FreeCoAP** -- Stack buffer overflow in `coap_msg.c` (CVE-2024-40494) with public PoC. Small codebase suitable for targeted fuzzing.

## Notable Research

### Protocol Security
- **"CoAP Security" RFC 7925** -- DTLS profiles for IoT
- **"Attacks on the Constrained Application Protocol (CoAP)"** -- [IETF Draft draft-irtf-t2trg-amplification-attacks](https://datatracker.ietf.org/doc/draft-irtf-t2trg-amplification-attacks/) -- documents amplification attack vectors
- **"Amplified Reflection DDoS Attacks over IoT Reflector Running CoAP"** -- [IEEE 2020](https://ieeexplore.ieee.org/document/9140882/) -- measured ~34x amplification factor
- **"CoAP Attacks In The Wild"** -- [NETSCOUT ASERT blog](https://www.netscout.com/blog/asert/coap-attacks-wild) -- first observed CoAP DDoS attacks January 2019

### Fuzzing Research
- **"FuzzCoAP: Fuzzing for Robustness and Security Testing of CoAP Servers"** -- Black-box fuzzing study testing 25 CoAP implementations, found failures in 14
- **"Testing IoT Protocol Requirements Using Fuzzing and Symbolic Execution: Application to CoAP"** -- [IEEE 2025](https://ieeexplore.ieee.org/document/10849709/) -- applies both fuzzing and symbolic execution to test libcoap and FreeCoAP against RFC 7252 requirements
- **"Towards Universal Fuzzing of IoT Protocols" (U-Fuzz)** -- [github.com/asset-group/U-Fuzz](https://github.com/asset-group/U-Fuzz) -- discovered 5 new CoAP CVEs across Jcoap, Canopus, and libcoap
- **"A Survey of Protocol Fuzzing"** -- [ACM Computing Surveys 2024](https://dl.acm.org/doi/abs/10.1145/3696788) / [arxiv.org/abs/2401.01568](https://arxiv.org/abs/2401.01568) -- comprehensive survey covering CoAP among other protocols
- **"AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing"** -- [arxiv.org/abs/2412.20324](https://arxiv.org/abs/2412.20324) -- retrospective on AFLNet with CoAP among supported protocols
- **"Logos: Log Guided Fuzzing for Protocol Implementations"** -- [ISSTA 2024](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/paper_from_24/Logos_issta24.pdf) -- extends AFLNet with log-guided state exploration, supports CoAP
- **"Machine Learning-Based DoS Amplification Attack Detection against CoAP"** -- [MDPI Applied Sciences 2023](https://www.mdpi.com/2076-3417/13/13/7391) -- ML detection of CoAP amplification attacks
- **"IoTFuzzSentry: A Protocol Guided Mutation Based Fuzzer"** -- [arxiv 2025](https://arxiv.org/html/2509.09158v1) -- mutation-based fuzzer for commercial IoT devices supporting CoAP

### Vendor Security Bulletins
- **Eclipse Californium security advisories** -- [eclipse.org/security/known](https://www.eclipse.org/security/known/)
- **Zephyr RTOS vulnerability list** -- [docs.zephyrproject.org/latest/security/vulnerabilities.html](https://docs.zephyrproject.org/latest/security/vulnerabilities.html)
- **RIOT OS security advisories** -- [github.com/RIOT-OS/RIOT/security](https://github.com/RIOT-OS/RIOT/security)
- **Contiki-NG security issues** -- [github.com/contiki-ng/contiki-ng/issues/425](https://github.com/contiki-ng/contiki-ng/issues/425) (Erbium vulnerabilities)
