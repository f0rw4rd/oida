# CoAP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in CoAP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-17212 | Arm Mbed OS | Buffer overflow in CoAP parser (sn_coap_parser_options_parse) due to missing bounds checks on option parsing | Buffer Overflow | 9.8 | [GitHub Issue](https://github.com/ARMmbed/mbed-os/issues/11803) |
| CVE-2019-17211 | Arm Mbed OS | Integer overflow in CoAP builder (sn_coap_builder_calc_needed_packet_data_size_2) causing insufficient buffer allocation | Integer Overflow | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-17211) |
| CVE-2020-10063 | Zephyr RTOS | Integer overflow in CoAP option parsing (coap_packet_parse) creating closed loop in options field | DoS | 7.5 | [Zephyr Security](https://docs.zephyrproject.org/latest/security/vulnerabilities.html) |
| CVE-2022-2576 | Eclipse Californium | DTLS resumption handshake falls back to full handshake without HelloVerifyRequest, enabling DDoS amplification and CPU exhaustion | DoS / Amplification | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-2576) |
| CVE-2024-0962 | libcoap | Stack-based buffer overflow in get_split_entry of coap_oscore.c in configuration file handler | Stack Overflow | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0962) |
| CVE-2020-12883 | Arm Mbed OS | Buffer over-read in sn_coap_parser_options_parse() from improper extended delta/length validation | OOB Read | 9.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12883) |
| CVE-2020-12884 | Arm Mbed OS | Buffer over-read in sn_coap_parser_options_parse_multiple_options() from unchecked option_len pointer increment | OOB Read | 9.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12884) |
| CVE-2020-12885 | Arm Mbed OS | Infinite loop in sn_coap_parser_options_parse_multiple_options() when heap allocation size computes to zero | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12885) |
| CVE-2020-12886 | Arm Mbed OS | Buffer over-read in sn_coap_parser_options_parse() from unchecked token length vs buffer bounds | OOB Read | 9.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12886) |
| CVE-2020-12887 | Arm Mbed OS | Memory leak via integer overflow in option delta accumulation in sn_coap_parser_options_parse() | Integer Overflow / Memory Leak | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12887) |
| CVE-2021-41040 | Eclipse Wakaama | Out-of-bounds read in CoAP parsing code from unsanitized network data | OOB Read | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-41040) |
| CVE-2019-9004 | Eclipse Wakaama | Memory leak in er-coap-13.c from mishandled invalid options (24 bytes per crafted packet) | Memory Leak / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-9004) |
| CVE-2024-32017 | RIOT OS gcoap | Buffer overflows in gcoap_dns_server_proxy_get() and _gcoap_forward_proxy_copy_options() from missing size checks | Buffer Overflow | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-32017) |
| CVE-2024-31225 | RIOT OS cord_lc | Buffer overflow in _on_rd_init() from unchecked memcpy of CoAP payload to static buffer | Buffer Overflow | 9.0 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-31225) |
| CVE-2024-40494 | FreeCoAP | Stack buffer overflow in coap_msg.c from crafted packet with insufficient bounds checking | Stack Overflow | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-40494) |
| CVE-2018-12679 | CoAPthon3 | DoS via crafted CoAP message causing unhandled exception in Serialize.deserialize() | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12679) |
| CVE-2018-12680 | CoAPthon | DoS via crafted CoAP message causing unhandled exception in Serialize.deserialize() | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12680) |
| CVE-2022-39368 | Eclipse Californium | DoS from failed DTLS handshakes not cleaning up throttle counters, permanently dropping records | DoS | 8.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-39368) |
| CVE-2023-51847 | libcoap | DoS via crafted messages causing resource exhaustion in coap_threadsafe.c | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-51847) |

## Exploits and PoCs

### CVE-2025-34468
- **Product**: libcoap up to 4.3.5
- **Type**: Stack-Based Buffer Overflow / DoS / Potential RCE
- **CVSS**: 8.2 (CVSSv4)
- **Server-side**: Yes -- address resolution code copies attacker-controlled hostname data into a fixed 256-byte stack buffer without bounds checking
- **Root cause**: Missing length validation in hostname-to-address resolution; hostnames >= 256 bytes overflow the `addrstr` stack buffer, corrupting adjacent stack frames and return address
- **Trigger**: CoAP request with Uri-Host option containing a hostname >= 256 bytes
- **PoC**: No public PoC (fix commit 30db3ea adds length check)
- **Metasploit**: N/A
- **Advisory**: [Debian Bug Report](http://www.mail-archive.com/debian-bugs-dist@lists.debian.org/msg2077007.html)
- **Analysis**: Classic stack buffer overflow from unbounded copy. A fuzzer sending CoAP requests with oversized Uri-Host options (>= 256 bytes) would trigger this immediately.

### CVE-2024-31031
- **Product**: libcoap 4.3.4
- **Type**: Unsigned Integer Overflow
- **CVSS**: N/A (minor severity)
- **Server-side**: Yes -- sequence of messages triggers unsigned integer overflow in coap_pdu.c leading to undefined behavior
- **Root cause**: Integer overflow in PDU processing when handling a sequence of crafted messages
- **Trigger**: Sequence of CoAP PDUs with boundary-value sizes that cause unsigned integer wraparound
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2024-31031)
- **Analysis**: A fuzzer sending sequences of PDUs with boundary-value sizes would trigger the integer overflow in coap_pdu.c.

### CVE-2024-0962
- **Product**: libcoap 4.3.4
- **Type**: Stack-Based Buffer Overflow
- **CVSS**: 9.8
- **Server-side**: Yes -- the `get_split_entry` function in `src/coap_oscore.c` has a stack-based buffer overflow when parsing OSCORE configuration files
- **Root cause**: Unbounded copy in OSCORE configuration file parsing; attacker-controlled input exceeds fixed stack buffer
- **Trigger**: OSCORE configuration input with entries exceeding the fixed stack buffer size
- **PoC**: Exploit disclosed publicly per VulDB
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0962)
- **Analysis**: The OSCORE configuration parser does not validate input length before copying into a stack buffer. Any fuzzer targeting the config handler would find this.

### CVE-2023-51847
- **Product**: libcoap (commit a3ed466)
- **Type**: DoS / Uncontrolled Resource Consumption
- **CVSS**: 7.5
- **Server-side**: Yes -- remote attacker can cause denial of service via the coap_context_t function in src/coap_threadsafe.c
- **Root cause**: Resource exhaustion in thread-safe context handling; crafted messages trigger uncontrolled resource consumption in the coap_context_t management code
- **Trigger**: Crafted CoAP messages that exploit the thread-safe context handling path
- **PoC**: [GitHub Issue #1302](https://github.com/obgm/libcoap/issues/1302)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-51847)
- **Analysis**: Thread-safe support added in v4.5.3 introduced a resource consumption path. A fuzzer sending concurrent crafted messages to the CoAP server would exhaust resources. Note: thread safe support must be enabled.

### CVE-2019-17212
- **Product**: Arm Mbed OS CoAP parser
- **Type**: Buffer Overflow
- **CVSS**: 9.8
- **Server-side**: Yes -- `sn_coap_parser_options_parse` function lacks bounds checks on option parsing, allowing heap corruption from crafted CoAP packets
- **Root cause**: Option parsing loop does not validate that option data stays within packet boundaries, causing out-of-bounds read/write
- **Trigger**: CoAP packet with option delta/length fields that extend option data beyond packet boundary
- **PoC**: [GitHub Issue #11803](https://github.com/ARMmbed/mbed-os/issues/11803)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-17212)
- **Analysis**: A fuzzer mutating CoAP option delta/length fields to create options that extend beyond packet boundaries would trigger the overflow.

### CVE-2019-17211
- **Product**: Arm Mbed OS CoAP builder
- **Type**: Integer Overflow
- **CVSS**: 9.8
- **Server-side**: Yes -- integer overflow in `sn_coap_builder_calc_needed_packet_data_size_2` causes insufficient buffer allocation
- **Root cause**: Arithmetic overflow when computing required buffer size for CoAP packet construction, leading to undersized allocation and subsequent heap corruption
- **Trigger**: CoAP packet with many large options that cause the size calculation to overflow a uint16_t
- **PoC**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-17211)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-17211)
- **Analysis**: Fuzzing with CoAP packets containing many large options would trigger the integer overflow in buffer size calculation.

### CVE-2020-12883
- **Product**: Arm Mbed OS 5.15.3 (mbed-coap 5.1.5)
- **Type**: OOB Read
- **CVSS**: 9.1
- **Server-side**: Yes -- `sn_coap_parser_options_parse()` fails to validate input packet length against bytes consumed when processing option extended delta and extended length fields
- **Root cause**: The parser does not check that the remaining packet buffer contains enough bytes before reading extended delta (1 or 2 bytes for delta values 13/14) and extended length fields. The calculation of consumed bytes vs packet length is incorrect, allowing reads past the buffer end.
- **Trigger**: CoAP packet with extended option delta (13 or 14) or extended option length where the packet is truncated before the extended bytes are present
- **PoC**: [GitHub Issue #12925](https://github.com/ARMmbed/mbed-os/issues/12925), [GitHub Issue #12926](https://github.com/ARMmbed/mbed-os/issues/12926), [GitHub Issue #12927](https://github.com/ARMmbed/mbed-os/issues/12927)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12883)
- **Analysis**: A fuzzer truncating CoAP packets at various offsets within the option encoding would immediately trigger this OOB read. Mutation strategies that shorten packets while preserving header bytes are ideal.

### CVE-2020-12884
- **Product**: Arm Mbed OS 5.15.3 (mbed-coap 5.1.5)
- **Type**: OOB Read
- **CVSS**: 9.1
- **Server-side**: Yes -- `sn_coap_parser_options_parse_multiple_options()` accesses `packet_data_pptr` after incrementing by `option_len` without a prior out-of-bounds check
- **Root cause**: After advancing the data pointer by the option length value, the function dereferences the pointer without verifying it still points within the packet buffer. An attacker-controlled option length value can point the pointer beyond the buffer.
- **Trigger**: CoAP packet with a repeatable option (Uri-Path, Uri-Query, Location-Path, etc.) where the option length field exceeds remaining packet data
- **PoC**: [GitHub Issue #12928](https://github.com/ARMmbed/mbed-os/issues/12928)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12884)
- **Analysis**: Fuzzing repeatable CoAP options with inflated length values would cause the pointer to advance past the packet buffer. This is a classic length-field mutation target.

### CVE-2020-12885
- **Product**: Arm Mbed OS 5.15.3 (mbed-coap 5.1.5)
- **Type**: DoS / Infinite Loop
- **CVSS**: 7.5
- **Server-side**: Yes -- `sn_coap_parser_options_parse_multiple_options()` enters an infinite loop when input heap memory calculation results in zero bytes
- **Root cause**: When option length values are crafted such that the heap allocation size computes to zero, the while loop's exit condition is never reached, causing the parser to spin indefinitely and denying service.
- **Trigger**: CoAP packet with option values crafted so the computed allocation size for multi-option storage is zero (e.g., empty option values combined with specific delta encoding)
- **PoC**: [GitHub Issue #12929](https://github.com/ARMmbed/mbed-os/issues/12929)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12885)
- **Analysis**: A fuzzer generating CoAP packets with zero-length repeatable options or option values that cause zero-sized allocations would trigger the infinite loop. Boundary value testing on option lengths is the key mutation strategy.

### CVE-2020-12886
- **Product**: Arm Mbed OS 5.15.3 (mbed-coap 5.1.5)
- **Type**: OOB Read
- **CVSS**: 9.1
- **Server-side**: Yes -- `sn_coap_parser_options_parse()` does not validate that the token length (TKL field) stays within the actual packet buffer
- **Root cause**: The parser trusts the 4-bit TKL field value without verifying that the packet contains that many bytes after the fixed header. A TKL value larger than available bytes causes reads beyond the buffer.
- **Trigger**: CoAP packet with TKL field set to 8 (maximum valid) but packet truncated to fewer than 12 bytes total (4 header + 8 token)
- **PoC**: [GitHub Issue #12948](https://github.com/ARMmbed/mbed-os/issues/12948)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12886)
- **Analysis**: Fuzzing the TKL field with values 1-8 while truncating the packet to be shorter than header + TKL bytes would trigger this. Also testable with TKL set to reserved values (9-15).

### CVE-2020-12887
- **Product**: Arm Mbed OS 5.15.3 (mbed-coap 5.1.5)
- **Type**: Integer Overflow / Memory Leak
- **CVSS**: 7.5
- **Server-side**: Yes -- `sn_coap_parser_options_parse()` uses uint16_t for option delta accumulation without overflow detection, causing option number wraparound and memory leaks
- **Root cause**: Option delta and previous option number are uint16_t. Crafted delta values cause the accumulated option number to wrap around to a previously-seen option number. Options like URI_QUERY, URI_PATH, LOCATION_QUERY, and ETAG allocate memory without checking if memory was already allocated for that option, leading to orphaned heap allocations.
- **Trigger**: CoAP packet with a sequence of options whose delta values sum to >= 65536, causing uint16_t wraparound back to option numbers that trigger duplicate allocation (e.g., wrapping back to option 11 for Uri-Path)
- **PoC**: [GitHub Issue #12930](https://github.com/ARMmbed/mbed-os/issues/12930), [GitHub Issue #12957](https://github.com/ARMmbed/mbed-os/issues/12957)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12887)
- **Analysis**: A fuzzer generating CoAP packets with many large delta values (using extended encoding) that accumulate past 65535 would trigger the wraparound. Each malformed packet leaks memory, leading to eventual OOM on constrained devices.

### CVE-2020-10063
- **Product**: Zephyr RTOS CoAP parser
- **Type**: Integer Overflow / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- integer overflow in `coap_packet_parse` creates an infinite loop in options field processing
- **Root cause**: Option delta/length accumulation overflows uint16_t, causing the parser to loop indefinitely over the options field. The `_parse_option` function uses unsigned 16-bit integers for all length values without sanitization.
- **Trigger**: CoAP packet with option delta values that cause uint16_t overflow when accumulated (e.g., multiple options with delta=14 extended encoding yielding values near 65535)
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Zephyr Security](https://docs.zephyrproject.org/latest/security/vulnerabilities.html)
- **Analysis**: Delta-encoded option numbers that overflow when accumulated would create the parsing loop. A fuzzer generating options with large delta values would trigger this.

### CVE-2021-41040
- **Product**: Eclipse Wakaama 1.0
- **Type**: OOB Read / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- CoAP parsing code does not properly sanitize network-received data, leading to reads past or before intended buffer boundaries
- **Root cause**: The CoAP parser in Eclipse Wakaama (used in the LwM2M stack) performs out-of-bounds reads when processing malformed packets. The parsing code trusts length fields from the network without bounds validation.
- **Trigger**: Crafted CoAP packet with option or payload length fields that reference memory outside the packet buffer
- **PoC**: [Eclipse Bug 577968](https://bugs.eclipse.org/bugs/show_bug.cgi?id=577968), [GitHub PR #640](https://github.com/eclipse/wakaama/pull/640)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-41040)
- **Analysis**: The Wakaama CoAP parser trusts network-supplied length values. A fuzzer sending packets with inflated option lengths or truncated payloads would trigger the OOB reads. This affects any LwM2M deployment using Wakaama.

### CVE-2019-9004
- **Product**: Eclipse Wakaama 1.0
- **Type**: Memory Leak / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- `core/er-coap-13/er-coap-13.c` in lwm2mserver mishandles invalid options, leaking 24 bytes per crafted packet
- **Root cause**: When the CoAP parser encounters invalid option values, it allocates memory for option processing but fails to free it on the error path. Each malformed packet leaks 24 bytes.
- **Trigger**: CoAP packet with invalid option encoding (e.g., reserved delta value 15, malformed extended encoding)
- **PoC**: [GitHub Issue #319](https://github.com/eclipse/wakaama/issues/319) (redacted as #425 in newer tracking)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-9004)
- **Analysis**: A fuzzer repeatedly sending packets with invalid option encodings would cause progressive memory exhaustion. On constrained IoT devices with limited RAM, this leads to OOM crash relatively quickly.

### CVE-2024-32017
- **Product**: RIOT OS 2024.01 and prior (gcoap module)
- **Type**: Buffer Overflow
- **CVSS**: 9.8 (GitHub CNA) / 9.0 (NIST)
- **Server-side**: Yes -- two buffer overflow vulnerabilities in the gcoap forward proxy and DNS proxy functionality
- **Root cause**: (1) `gcoap_dns_server_proxy_get()` contains a typo checking length of `_uri` instead of `_proxy` before `strcpy()`. (2) `_gcoap_forward_proxy_copy_options()` does not check size before copying CoAP ETag option data to the `cep->req_etag` buffer (COAP_ETAG_LENGTH_MAX bytes).
- **Trigger**: (1) CoAP request to the DNS proxy endpoint with a proxy URI longer than the `_proxy` buffer. (2) CoAP request with an ETag option whose `optlen` exceeds COAP_ETAG_LENGTH_MAX (8 bytes per RFC 7252).
- **PoC**: [GitHub Advisory GHSA-v97j-w9m6-c4h3](https://github.com/RIOT-OS/RIOT/security/advisories/GHSA-v97j-w9m6-c4h3)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-32017)
- **Analysis**: Both bugs are classic missing-bounds-check overflows triggered by CoAP option values. A fuzzer sending CoAP requests with oversized ETag options (>8 bytes) or long Proxy-Uri values would trigger the overflows immediately. CWE-120 (Classic Buffer Overflow).

### CVE-2024-31225
- **Product**: RIOT OS 2024.01 and prior (cord_lc module)
- **Type**: Buffer Overflow
- **CVSS**: 9.0 (NIST) / 8.3 (GitHub CNA)
- **Server-side**: Yes -- `_on_rd_init()` in `cord_lc.c` performs `memcpy()` of CoAP response payload into a static buffer without size validation
- **Root cause**: The CoRE Link Format response handler copies the entire CoAP payload into `_result_buf` without checking that the payload length does not exceed the buffer size. An attacker controlling a malicious Resource Directory can send oversized payloads.
- **Trigger**: CoAP response from a Resource Directory with a payload exceeding the size of `_result_buf` (sent to a RIOT device performing resource directory lookup)
- **PoC**: [GitHub Advisory GHSA-2572-7q7c-3965](https://github.com/RIOT-OS/RIOT/security/advisories/GHSA-2572-7q7c-3965)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-31225)
- **Analysis**: A fuzzer or malicious CoAP server sending oversized CoRE Link Format payloads in response to resource directory lookups would trigger the overflow. The static buffer has a fixed size but the memcpy uses the network-supplied payload length. CWE-120.

### CVE-2024-40494
- **Product**: FreeCoAP 0.7
- **Type**: Stack Buffer Overflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- `coap_msg.c` contains insufficient bounds checking when parsing incoming CoAP packets, allowing stack buffer overflow
- **Root cause**: The CoAP message parser in FreeCoAP copies packet data into stack-allocated buffers without verifying that the data length does not exceed the buffer size. A crafted packet with oversized fields overflows the stack buffer.
- **Trigger**: Crafted CoAP packet with oversized option values or payload that exceeds the stack buffer in coap_msg.c
- **PoC**: [GitHub PoC](https://github.com/dqp10515/security/tree/main/FreeCoAP_bug), [Gist with details](https://gist.github.com/dqp10515/e9d7d663cb89187bfe7b39bb3aeb0113)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-40494)
- **Analysis**: Classic stack buffer overflow from unbounded copy in the message parser. A fuzzer sending CoAP packets with progressively larger option values or payloads would find this quickly. The public PoC provides a crafted packet that triggers the overflow.

### CVE-2018-12680
- **Product**: CoAPthon 3.1, 4.0.0, 4.0.1, 4.0.2
- **Type**: DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- `Serialize.deserialize()` method mishandles exceptions when processing crafted CoAP messages, crashing the server
- **Root cause**: The CoAP message deserialization code does not properly catch and handle exceptions raised by malformed input. Specific malformed field combinations cause unhandled exceptions that propagate up and crash the application.
- **Trigger**: Crafted CoAP packet with malformed fields (e.g., invalid option encoding, corrupted header bytes) that trigger uncaught exceptions in the Python deserialization code
- **PoC**: [GitHub Issue #135](https://github.com/Tanganelli/CoAPthon/issues/135)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12680)
- **Analysis**: A fuzzer sending random mutations of valid CoAP packets would trigger unhandled exceptions in the Python deserializer. The lack of defensive exception handling means almost any malformed packet can crash the server.

### CVE-2018-12679
- **Product**: CoAPthon3 1.0, 1.0.1
- **Type**: DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- `Serialize.deserialize()` method in CoAPthon3 mishandles exceptions when processing crafted CoAP messages
- **Root cause**: Same pattern as CVE-2018-12680 but in the Python 3 port. The deserializer lacks defensive exception handling for malformed input, causing server crashes.
- **Trigger**: Crafted CoAP message with malformed serialization that triggers an unhandled exception
- **PoC**: [GitHub Issue #16](https://github.com/Tanganelli/CoAPthon3/issues/16)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12679)
- **Analysis**: Same as CVE-2018-12680. Random fuzzing of CoAP packet bytes would trigger crashes. Both CoAPthon and CoAPthon3 share this vulnerability pattern.

### CVE-2022-39368
- **Product**: Eclipse Californium 2.0.0 to 2.7.3, 3.0.0 to 3.6.x
- **Type**: DoS / Resource Leak
- **CVSS**: 8.2
- **Server-side**: Yes -- failed DTLS handshakes do not clean up throttling counters, eventually causing permanent record drops
- **Root cause**: When certificate-based (or PSK-based) DTLS handshakes fail, the throttling counter for the connection is incremented but never decremented. After enough failures, the threshold is permanently reached and the server drops all subsequent records.
- **Trigger**: Repeated crafted DTLS ClientHello messages that cause handshake failures (e.g., invalid certificate, malformed handshake extensions) -- each failure leaks a throttle counter
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [GitHub Advisory GHSA-p72g-cgh9-ghjg](https://github.com/eclipse-californium/californium/security/advisories/GHSA-p72g-cgh9-ghjg)
- **Analysis**: A fuzzer sending malformed DTLS ClientHello messages (invalid cipher suites, truncated extensions, bad certificates) would cause handshake failures. After sustained fuzzing, the throttle counter exhaustion would cause permanent DoS. Fixed in 3.7.0 and 2.7.4.

## Key Vulnerability Patterns for Fuzzing

1. **Option Delta Accumulation**: Delta values that when accumulated exceed valid option number range -- triggers uint16_t overflow in Mbed OS (CVE-2020-12887) and infinite loops in Zephyr (CVE-2020-10063)
2. **Extended Delta/Length Encoding**: 13/14 prefix with subsequent bytes creating values that overflow -- causes OOB reads in Mbed OS (CVE-2020-12883)
3. **TKL (Token Length)**: Reserved values 9-15, mismatch with actual available bytes -- OOB read in Mbed OS (CVE-2020-12886)
4. **Block-Wise Transfer**: Block number overflow, size exponent creating unreasonable block sizes (SZX=7)
5. **Multiple Options of Same Type**: Repeatable vs. non-repeatable option handling -- OOB read in Mbed OS (CVE-2020-12884)
6. **Payload Marker Edge Cases**: 0xFF as last byte (empty payload), no options before marker
7. **URI Option Assembly**: Path traversal via Uri-Path option sequences
8. **Observe Sequence Numbers**: 24-bit wraparound, notifications with decreasing sequence numbers
9. **Option Length Inflation**: Options with length fields exceeding remaining packet data -- buffer overflows in RIOT gcoap (CVE-2024-32017), FreeCoAP (CVE-2024-40494)
10. **Unsanitized Network Data in LwM2M Stack**: Wakaama CoAP parser trusts all network-supplied length fields (CVE-2021-41040)
11. **Zero-Length Allocation**: Crafted options that compute to zero-sized heap allocations -- infinite loop in Mbed OS (CVE-2020-12885)
12. **CoAP Proxy/Gateway URI Handling**: Oversized hostnames in Uri-Host (CVE-2025-34468), oversized Proxy-Uri (CVE-2024-32017)
13. **CoRE Link Format Payload Overflow**: Oversized payloads in resource directory responses (CVE-2024-31225)
14. **Deserialization Exception Handling**: Uncaught exceptions from malformed packets crash Python implementations (CVE-2018-12679, CVE-2018-12680)
15. **DTLS Handshake State Leak**: Repeated malformed DTLS handshakes exhaust throttle counters (CVE-2022-39368)
