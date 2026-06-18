# OCPP / EV Charging Infrastructure - Server-Side Parsing CVEs

All entries pass the fuzzer test: "Would sending malformed/crafted bytes on the wire trigger
this bug?" Only parsing bugs, memory corruption, and input validation failures that a
protocol fuzzer would find are included.

**Excluded** (not parsing bugs):
- CVE-2018-16669 (CIRCONTROL plaintext credentials) - configuration issue
- CVE-2023-49956 (OCPP.Core arbitrary StopTransaction) - logic flaw, no parsing involved
- CVE-2023-49957 (OCPP.Core duplicate transactions) - logic flaw
- CVE-2024-21550 (SteVe XSS via WebSocket) - client-side rendering bug
- CVE-2024-25994 (CHARX arbitrary file upload) - file upload logic, not parsing
- CVE-2024-25995 (CHARX missing auth on config) - auth bypass, not parsing
- CVE-2024-25998 (CHARX OCPP command injection) - command injection, not parsing
- CVE-2024-26002 (CHARX Qualcomm plctool priv esc) - local privilege escalation
- CVE-2024-26005 (CHARX incomplete cleanup) - resource management, not parsing
- CVE-2024-26288 (CHARX OCPP 1.6J no encryption) - protocol design limitation
- CVE-2024-28136 (CHARX local OCPP command injection) - local command injection
- CVE-2025-24005, CVE-2025-24006 (CHARX local priv esc) - local exploitation
- CVE-2025-68133 (EVerest unlimited connections) - resource exhaustion, not parsing
- CVE-2025-68136 (EVerest session fd leak) - resource management, not parsing
- CVE-2025-68138 (libocpp strdup leak) - memory leak, not parsing crash
- CVE-2025-68139 (EVerest error handling) - error handling logic
- CVE-2025-68140 (EVerest null session ID bypass) - auth logic flaw
- CVE-2026-24003 (EVerest sequence state bypass) - state machine logic flaw

---

## EVerest / everest-core / libocpp

### CVE-2024-37310
- **Product**: EVerest everest-core (EvseV2G module) before 2024.3.1
- **Type**: Integer Overflow -> Heap Buffer Overflow
- **CVSS**: 9.0 CRITICAL (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
- **Server-side**: Yes -- V2GTP (V2G Transport Protocol) server parses incoming packet header
- **Root cause**: Integer overflow in `v2g_incoming_v2gtp()` in `v2g_server.cpp`. The V2GTP header contains a 4-byte payload length field. The code adds 8 (header size) to this value. When the length field is in range [0xFFFFFFF8, 0xFFFFFFFF], the addition wraps to [0, 7] on 32-bit arithmetic, passing the size check. The undersized allocation is then filled with attacker-controlled data via `connection_read()`, overflowing the heap buffer.
- **Trigger**: V2GTP packet with payload length field set to any value in [0xFFFFFFF8, 0xFFFFFFFF]. Send to port 15118 (ISO 15118 service). Example: V2GTP header bytes `01 FE XX XX FF FF FF FF` followed by arbitrary payload bytes.
- **PoC**: GitHub Security Advisory GHSA-8g9q-7qr9-vc96 -- https://github.com/EVerest/everest-core/security/advisories/GHSA-8g9q-7qr9-vc96
- **Metasploit**: N/A
- **Advisory**: PlaxidityX discovery blog: https://plaxidityx.com/blog/automotive-cyber-security/ev-cyber-security-plaxidityx-discovers-critical-vulnerability-in-everest-open-source-ev-charging-firmware-stack-cve-2024-37310/
- **Analysis**: Classic integer overflow in a length field. The 32-bit addition `length + 8` wraps around, causing a small heap allocation to be made while `connection_read` happily writes the full attacker-controlled payload. A byte-level fuzzer mutating the 4-byte length field in V2GTP headers would find this immediately by trying large values near UINT_MAX.

### CVE-2025-68137
- **Product**: EVerest everest-core (ISO 15118 SDP handler) before 2025.10.0
- **Type**: Integer Overflow -> Stack Buffer Overflow / Infinite Loop
- **CVSS**: 8.3 HIGH (AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
- **Server-side**: Yes -- SDP (SECC Discovery Protocol) server parses incoming packet header
- **Root cause**: Integer overflow in `SdpPacket::parse_header()`. The 4-byte payload length from the V2GTP header is read as `uint32_t` and added to `V2GTP_HEADER_SIZE` (8, type `int`). Values in [UINT_MAX-7, UINT_MAX] cause 32-bit wrap to [0, 7]. When `length` becomes 7 (less than header size 8), `get_remaining_bytes_to_read()` computes `7 - 8 = -1` which is cast to `size_t` (SIZE_MAX). On plain TCP, `read(fd, buf, SIZE_MAX)` returns -1 creating an infinite loop. On TLS, `SSL_read_ex()` reads up to 16KB into a 2048-byte stack buffer, causing stack buffer overflow.
- **Trigger**: SDP request to port 15118 multicast, then connect to returned TCP/TLS port. Send V2GTP header: `01 FE 80 04 FF FF FF FF` followed by overflow payload (`0xAF` * 2040 + `0xDEADBEEF` * 300).
- **PoC**: Full Python PoC in GitHub Security Advisory GHSA-7qq4-q9r8-wc7w (Quarkslab audit). Both TCP infinite-loop and TLS stack-overflow variants demonstrated. GDB output confirms stack variables overwritten with `0xBEEFDEAD`.
- **Metasploit**: N/A
- **Advisory**: https://github.com/EVerest/everest-core/security/advisories/GHSA-7qq4-q9r8-wc7w
- **Analysis**: Nearly identical root cause to CVE-2024-37310 (integer overflow in V2GTP length field) but in a different code path (SDP vs V2G session). The TLS variant is more exploitable because SSL_read_ex has no upper bound on read size. A fuzzer mutating the 4-byte length field in SDP/V2GTP headers with values near 0xFFFFFFFF would find both variants. The researchers confirmed controllable stack corruption including overwriting callback pointers in the Session class.

### CVE-2025-68141
- **Product**: EVerest everest-core (libiso15118) before fix
- **Type**: NULL Pointer Dereference (DoS)
- **CVSS**: HIGH (per GitHub advisory)
- **Server-side**: Yes -- EVSE parses incoming DC_ChargeLoopRes messages from EV
- **Root cause**: During deserialization of `DC_ChargeLoopRes` with Receipt containing TaxCosts, the `out.tax_costs` vector is never initialized (empty). The code iterates `in.TaxCosts.arrayLen` times calling `convert(in.TaxCosts.array[i], out.tax_costs[i])`, accessing index 0 of an empty vector. This dereferences a null pointer when writing `out.tax_costs[0].tax_rule_id = in.TaxRuleID`.
- **Trigger**: Send an ISO 15118-20 `DC_ChargeLoopRes` message with `Receipt` present and `TaxCosts.arrayLen` set to any value between 1-10. First establish SDP session, then send crafted EXI-encoded payload. Exact bytes in PoC: `\x01\xfe\x80\x04\x00\x00\x00\x27...` (see advisory for full payload).
- **PoC**: Full Python PoC in GitHub Security Advisory GHSA-ph4w-r9q8-vm9h (Quarkslab audit). Script sends SDP request then crafted V2GTP payload triggering SIGSEGV. Log shows: "Module iso15118_charger (pid: 2885105) exited with status: 11. Terminating all modules."
- **Metasploit**: N/A
- **Advisory**: https://github.com/EVerest/everest-core/security/advisories/GHSA-ph4w-r9q8-vm9h
- **Analysis**: Classic uninitialized container access during deserialization. The TaxCosts field is optional per spec but the code assumes the output vector is pre-populated. A fuzzer generating DC_ChargeLoopRes messages with various combinations of optional fields (Receipt present, TaxCosts with arrayLen=1 but no prior resize) would trigger this. Crash kills the entire EVerest manager and all connected EVSE.

### CVE-2025-68134
- **Product**: EVerest everest-core (libiso15118) before fix
- **Type**: Assertion Failure -> Process Abort (DoS)
- **CVSS**: HIGH (per GitHub advisory)
- **Server-side**: Yes -- EVSE parses incoming DC_ChargeLoopReq messages
- **Root cause**: The `convert()` function for `DC_ChargeLoopReqType` uses `assert(false)` as the fallback when none of the expected control mode flags (`Scheduled_DC_CLReqControlMode_isUsed`, etc.) are set. In production builds with assertions enabled, this aborts the process. The manager then shuts down all modules.
- **Trigger**: Send a DC_ChargeLoopReq message where none of the four control mode `_isUsed` flags are set to true. The deserialization succeeds past field parsing but hits `assert(false)` in the control mode dispatch.
- **PoC**: Described in Quarkslab audit advisory GHSA-cxc5-rrj5-8pf3. Triggering requires sending an ISO 15118-20 ChargeLoopReq with all control mode flags cleared.
- **Metasploit**: N/A
- **Advisory**: https://github.com/EVerest/everest-core/security/advisories/GHSA-cxc5-rrj5-8pf3
- **Analysis**: Using assert() for error handling in production code that processes untrusted network input. A fuzzer zeroing out flag bytes in ChargeLoopReq messages would find this. The crash propagates to terminate all EVSE managed by the same EVerest instance.

### CVE-2025-68132
- **Product**: EVerest everest-core (DZG_GSH01 powermeter driver) before fix
- **Type**: Out-of-Bounds Read (DoS)
- **CVSS**: LOW (per GitHub advisory)
- **Server-side**: Yes -- powermeter driver parses incoming SLIP frames on serial link
- **Root cause**: `is_message_crc_correct()` in `slip_protocol.cpp` accesses `vec[vec.size()-1]` and `vec[vec.size()-2]` without checking that at least 2 bytes are present. The multi-message path in `SlipProtocol::unpack()` splits on 0xC0 delimiters and forwards sub-messages without minimum length enforcement.
- **Trigger**: Crafted SLIP frame: `{0xC0, device_id, 0xC0, 0xC0, 0xC0, 0xC0}`. This creates a 1-byte sub-message that passes the address filter (first byte == device_id) but triggers OOB read in CRC check.
- **PoC**: Full C++ PoC with ASAN output in GitHub Security Advisory GHSA-79gc-m8w6-9hx5. ASAN confirms: `heap-buffer-overflow on address ... READ of size 1 ... in is_message_crc_correct slip_protocol.cpp:25`. Found by SecMate automated fuzzer.
- **Metasploit**: N/A
- **Advisory**: https://github.com/EVerest/everest-core/security/advisories/GHSA-79gc-m8w6-9hx5
- **Analysis**: Classic missing bounds check before array access. The single-message path enforces `message.size() > 3` but the multi-message path does not. A fuzzer generating short SLIP frames with multiple 0xC0 delimiters would find this quickly. Attack requires access to the serial link (physical or via compromised USB-serial bridge).

### CVE-2025-59398
- **Product**: EVerest libocpp before 0.26.2
- **Type**: Unhandled Exception -> Process Crash (DoS)
- **CVSS**: 3.1 LOW (AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)
- **Server-side**: Yes -- OCPP library on charge point parses incoming JSON messages from CSMS
- **Root cause**: When receiving JSON input with a string field larger than 255 characters, libocpp creates a `CiString<255>` object with `StringTooLarge` policy set to `Throw`. The resulting exception is not caught, propagating up and crashing the EVerest process.
- **Trigger**: Send any OCPP JSON message over WebSocket where a CiString<255>-typed field contains more than 255 characters. Example: a ChangeConfiguration response or any message with oversized string fields.
- **PoC**: GitHub issue EVerest/everest-core#1152 -- https://github.com/EVerest/everest-core/issues/1152
- **Metasploit**: N/A
- **Advisory**: NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-59398
- **Analysis**: Uncaught exception from string length validation. The CiString template correctly detects oversized input but the Throw policy crashes the process instead of rejecting the message gracefully. A fuzzer sending OCPP JSON messages with increasingly large string values would find this trivially. Fixed in libocpp 0.26.2 by switching to truncation instead of throwing.

### CVE-2025-59399
- **Product**: EVerest libocpp before 0.28.0
- **Type**: Secondary Exception -> Process Crash (DoS)
- **CVSS**: 3.1 LOW (AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)
- **Server-side**: Yes -- OCPP library on charge point crashes during error message generation
- **Root cause**: When an error condition is triggered during OCPP message processing, the error message generation code throws a secondary exception (CWE-460: Improper Cleanup on Thrown Exception). The double-throw terminates the process.
- **Trigger**: Send malformed OCPP JSON messages that trigger error handling paths. The specific input depends on which error path is triggered, but any message causing an initial parse error that then fails during error response construction.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-59399
- **Analysis**: Exception-during-exception handling bug. Error paths are notoriously undertested. A fuzzer that generates many invalid OCPP messages will exercise error handling paths and discover secondary exceptions. Fixed in libocpp 0.28.0.

---

## Dalmann OCPP.Core

### CVE-2023-49955
- **Product**: Dalmann OCPP.Core before 1.2.0 (.NET OCPP server)
- **Type**: Denial of Service (resource exhaustion / server crash)
- **CVSS**: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- CSMS parses BootNotification from Charge Point
- **Root cause**: No validation of `chargePointVendor` field length in BootNotification messages. The OCPP spec limits this to CiString20 (20 characters), but the server accepts and attempts to process arbitrarily large values without bounds checking.
- **Trigger**: Send OCPP CALL message: `[2, "uuid", "BootNotification", {"chargePointVendor": "A" * 442000000, "chargePointModel": "test"}]`. A 442MB chargePointVendor value crashes the server.
- **PoC**: GitHub Issue #32 -- https://github.com/dallmann-consulting/OCPP.Core/issues/32
- **Metasploit**: N/A
- **Advisory**: NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-49955
- **Analysis**: Missing length validation on a bounded protocol field. The OCPP specification clearly defines chargePointVendor as CiString20 but the implementation does not enforce it. Any fuzzer that grows string field sizes would find this. The simplest mutation: take a valid BootNotification and make chargePointVendor progressively larger.

### CVE-2023-49958
- **Product**: Dalmann OCPP.Core up to 1.2.0 (.NET OCPP server)
- **Type**: Improper Input Validation (JSON parsing)
- **CVSS**: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Server-side**: Yes -- CSMS parses StartTransaction and other messages
- **Root cause**: The JSON parser accepts additional/duplicate properties in OCPP messages. When duplicate JSON keys are present, the last occurrence is accepted. This allows attackers to inject values by appending duplicate keys after legitimate ones.
- **Trigger**: Send OCPP message with duplicate JSON keys: `[2, "uuid", "StartTransaction", {"connectorId": 1, "idTag": "valid", "meterStart": 100, "timestamp": "2024-01-01T00:00:00Z", "meterStart": 999999}]`. The second `meterStart` overrides the first.
- **PoC**: No public PoC (discovered by OCPPStorm fuzzer)
- **Metasploit**: N/A
- **Advisory**: NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-49958
- **Analysis**: Duplicate key handling in JSON deserialization. A JSON-aware fuzzer that duplicates keys with different values would find this. This is a parsing behavior bug -- the parser should either reject duplicates or use the first occurrence.

---

## SteVe Community ocpp-jaxb

### CVE-2023-52096
- **Product**: SteVe Community ocpp-jaxb before 0.0.8 (Java OCPP library)
- **Type**: Invalid Timestamp Generation -> SQL Exception (DoS)
- **CVSS**: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Server-side**: Yes -- CSMS parses timestamp in StartTransaction message
- **Root cause**: The JAXB timestamp converter generates invalid timestamps (e.g., month=00) when parsing certain numeric timestamp values. A StartTransaction with `timestamp: 1000000` produces a database value `0000-00-00 00:00:00.000000` that causes SQL exceptions on retrieval.
- **Trigger**: Send OCPP CALL: `[2, "uuid", "StartTransaction", {"connectorId": 1, "idTag": "test", "meterStart": 0, "timestamp": "1000000"}]`. The invalid timestamp is stored in the database and causes SQL exceptions when the transaction record is later queried.
- **PoC**: GitHub Issue steve-community/steve#1292 -- https://github.com/steve-community/steve/issues/1292
- **Metasploit**: N/A
- **Advisory**: NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-52096
- **Analysis**: Timestamp parsing edge case. The JAXB converter does not properly validate parsed timestamp components. A fuzzer sending various numeric and malformed timestamp values in OCPP messages would find this. The impact is delayed -- the database corruption causes exceptions on subsequent reads, not on the initial write.

---

## Phoenix Contact CHARX SEC (Charging Hardware)

### CVE-2024-26001
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware before 1.5.1
- **Type**: Out-of-Bounds Write (memory corruption)
- **CVSS**: 9.8 CRITICAL (NIST) / 7.4 HIGH (CERT VDE)
- **Server-side**: Yes -- MQTT message handler on the charging controller
- **Root cause**: Improper input validation in the MQTT protocol stack allows an unauthenticated remote attacker to write beyond allocated memory bounds. The MQTT message parser does not properly validate length fields before writing data into fixed-size buffers.
- **Trigger**: Crafted MQTT messages with oversized payloads sent to the CHARX controller's MQTT service. Exploitation requires brute force due to ASLR but is feasible.
- **PoC**: Pwn2Own Automotive 2024 demonstration (ZDI disclosure). PoC repo: https://github.com/ret2/Pwn2Own-Auto-2024-CHARX (partial exploit chain)
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2024-011: https://certvde.com/en/advisories/VDE-2024-011
- **Analysis**: OOB write in MQTT parser. The MQTT stack on the CHARX processes messages from the network without adequate length validation. A fuzzer sending MQTT PUBLISH messages with large or malformed payloads to the CHARX controller would trigger this. Found at Pwn2Own Automotive 2024.

### CVE-2024-26000
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware before 1.5.1
- **Type**: Out-of-Bounds Read (information disclosure)
- **CVSS**: 7.5 HIGH (NIST) / 5.9 MEDIUM (CERT VDE)
- **Server-side**: Yes -- MQTT message handler on the charging controller
- **Root cause**: Improper input validation in the MQTT stack allows reading beyond allocated buffer bounds. The parser trusts length fields in MQTT messages without validating they fall within the allocated buffer.
- **Trigger**: Crafted MQTT messages that cause the parser to read past buffer boundaries. Similar attack vector to CVE-2024-26001 but information disclosure instead of write.
- **PoC**: No public standalone PoC. Discovered at Pwn2Own Automotive 2024.
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2024-011: https://certvde.com/en/advisories/VDE-2024-011
- **Analysis**: OOB read companion to CVE-2024-26001. Same MQTT parser, different impact. Fuzzing MQTT messages with boundary-value length fields would find both the read and write variants.

### CVE-2024-26003
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware before 1.5.1
- **Type**: NULL Pointer Dereference (DoS)
- **CVSS**: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- HomePlug GreenPHY packet handler (ControllerAgent)
- **Root cause**: Incorrect byte offset interpretation in `MME_CM_Amp_Map_Req` constructor. The AMLEN field is read from bytes 4-5 instead of the correct bytes 5-6, causing a mismatch between the stored length and actual data size. When iterating through amplitude map entries using the correct length but with undersized backing data, the vector is empty, causing a null dereference.
- **Trigger**: Send malformed HomePlug MME (Management Message Entry) packets via Ethernet to the CHARX ETH1 interface. The packet must have a crafted AMLEN field at the wrong byte offset.
- **PoC**: https://github.com/ret2/Pwn2Own-Auto-2024-CHARX (charxpwn.py) -- triggers the null deref via HomePlug packets, then chains with CVE-2024-26005 UAF during signal handler/destructor.
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2024-011: https://certvde.com/en/advisories/VDE-2024-011 ; Blog: https://blog.ret2.io/2024/07/17/pwn2own-auto-2024-charx-bugs/
- **Analysis**: Off-by-one byte offset in HomePlug packet parsing. The parser reads the AMLEN field from the wrong position in the packet, creating a size mismatch. A fuzzer sending mutated HomePlug MME packets with various lengths and offsets would trigger the empty vector access. This was part of a chain exploit at Pwn2Own Automotive 2024 by RET2 Systems.

### CVE-2024-26004
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware before 1.5.1
- **Type**: Access of Uninitialized Pointer (DoS)
- **CVSS**: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- ControllerAgent on the charging controller
- **Root cause**: The control agent accesses an uninitialized pointer when processing certain network inputs, causing a crash that prevents or disrupts charging functionality.
- **Trigger**: Network-accessible without authentication. Specific malformed input not publicly disclosed.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2024-011: https://certvde.com/en/advisories/VDE-2024-011
- **Analysis**: Uninitialized pointer access in the control agent. A fuzzer exercising various network interfaces of the CHARX controller would find this by triggering code paths that use uninitialized memory.

### CVE-2025-24002
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware up to 1.6.5
- **Type**: Denial of Service (crash via malformed MQTT)
- **CVSS**: 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N)
- **Server-side**: Yes -- MQTT message handler on charging controller
- **Root cause**: Improper input validation in MQTT message processing. Malicious MQTT messages crash a service on the charging station, causing temporary unavailability until the watchdog restarts the system.
- **Trigger**: Send crafted MQTT messages (e.g., `{"data":{}}` to certain topics). The empty object causes the service to crash when it attempts to access expected fields.
- **PoC**: ivision Research exploitation writeup: https://research.ivision.com/charx-exploitation.html
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2025-014 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-24002)
- **Analysis**: Missing null/empty field checks in MQTT JSON message handler. A fuzzer sending MQTT messages with empty objects, missing fields, or null values to various topics would trigger this. Service restarts via watchdog but repeated triggering creates persistent DoS.

### CVE-2025-24003
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware up to 1.6.5
- **Type**: Buffer Overflow (Out-of-Bounds Write via MQTT)
- **CVSS**: 8.2 HIGH (AV:N/AC:L/PR:N/UI:N)
- **Server-side**: Yes -- CharxEichrechtAgent parses MQTT messages on the charging controller
- **Root cause**: The `eichrecht_status` MQTT topic handler lacks bounds checking on the status field. `memcpy(dest, status_field, status_length)` copies up to 0x78C bytes past the intended buffer into the .bss section without size validation.
- **Trigger**: Publish crafted MQTT message to the `eichrecht_status` topic with an oversized status field. Example: `{"data": {"status": "A" * 4000}}` causes memcpy overflow into adjacent .bss memory.
- **PoC**: ivision Research exploitation writeup: https://research.ivision.com/charx-exploitation.html
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2025-014 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-24003)
- **Analysis**: Classic buffer overflow from unchecked memcpy. The MQTT message parser trusts the length of the status field from JSON input without validating it fits the destination buffer. A fuzzer publishing MQTT messages with increasingly large field values would find this quickly. This was chained with CVE-2025-24004 (sprintf stack overflow) for code execution.

### CVE-2025-24004
- **Product**: Phoenix Contact CHARX SEC-3000/3050/3100/3150, firmware up to 1.6.5
- **Type**: Stack Buffer Overflow (via sprintf)
- **CVSS**: 5.2 MEDIUM (AV:P/AC:L/PR:N/UI:N)
- **Server-side**: Yes -- CharxEichrechtAgent on the charging controller
- **Root cause**: A `sprintf(buffer, ...)` call uses controlled data from the CVE-2025-24003 overflow region. When multiple instances of user-controlled strings are formatted, the result exceeds the 0x800-byte stack buffer.
- **Trigger**: Requires physical access (USB-C display emulation) or chaining with CVE-2025-24003. The overflowed .bss data is used by sprintf to construct a string that overflows a 2048-byte stack buffer.
- **PoC**: ivision Research exploitation writeup: https://research.ivision.com/charx-exploitation.html. Full chain demonstrated: CVE-2025-24003 .bss overflow -> CVE-2025-24004 stack overflow -> code execution via brute-forcing 256 ASLR offsets on ARM32.
- **Metasploit**: N/A
- **Advisory**: CERT VDE VDE-2025-014 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-24004)
- **Analysis**: Secondary overflow from sprintf with attacker-controlled format arguments. The .bss corruption from CVE-2025-24003 provides the controlled input. Together these form a reliable remote code execution chain. A fuzzer targeting MQTT topics on the CHARX would trigger CVE-2025-24003 first.

---

## Autel MaxiCharger

### CVE-2024-23967
- **Product**: Autel MaxiCharger AC Elite Business C50, firmware v1.32 and earlier
- **Type**: Stack Buffer Overflow (OOB Write)
- **CVSS**: 8.0 HIGH (AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- WebSocket message handler on the charger (ACMP protocol)
- **Root cause**: Base64-encoded data in WebSocket messages is decoded into a fixed-size 1024-byte stack buffer without checking the decoded output size. The function responsible for handling ACMP (Autel Cloud Management Protocol) messages performs base64 decode directly into the stack buffer.
- **Trigger**: Connect to the charger's WebSocket interface and send a base64-encoded payload that decodes to more than 1024 bytes. The auth mechanism can be bypassed (CVE-2024-23958).
- **PoC**: Demonstrated at Pwn2Own Automotive 2024 by Computest Sector 7. Technical details: https://www.thezdi.com/blog/2024/10/2/from-pwn2own-automotive-more-autel-maxicharger-vulnerabilities
- **Metasploit**: N/A
- **Advisory**: ZDI advisory; NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-23967
- **Analysis**: Classic stack buffer overflow from base64 decoding without bounds check. The WebSocket handler receives messages, identifies base64-encoded fields, and decodes them into a fixed 1024-byte buffer on the stack. A fuzzer sending WebSocket messages with increasingly large base64 payloads would trigger this immediately. The ACMP protocol runs over WebSocket and is used for cloud management -- it is closely related to the OCPP communication path on these chargers.

---

## Fuzzer Test Verification Summary

| CVE | Malformed bytes trigger? | Verdict |
|-----|-------------------------|---------|
| CVE-2024-37310 | V2GTP header with length 0xFFFFFFF8-0xFFFFFFFF | PASS - integer overflow in length field |
| CVE-2025-68137 | SDP header with length 0xFFFFFFF8-0xFFFFFFFF | PASS - integer overflow in length field |
| CVE-2025-68141 | DC_ChargeLoopRes with TaxCosts arrayLen=1 | PASS - null deref from missing field |
| CVE-2025-68134 | DC_ChargeLoopReq with no control mode flags | PASS - assert on unexpected field combo |
| CVE-2025-68132 | Short SLIP frame with multiple 0xC0 delimiters | PASS - OOB read from short message |
| CVE-2025-59398 | OCPP JSON with string >255 chars | PASS - unhandled exception from length |
| CVE-2025-59399 | Malformed OCPP JSON triggering error path | PASS - secondary exception |
| CVE-2023-49955 | BootNotification with 442MB chargePointVendor | PASS - no length validation |
| CVE-2023-49958 | OCPP JSON with duplicate keys | PASS - parser accepts duplicates |
| CVE-2023-52096 | StartTransaction with timestamp=1000000 | PASS - invalid timestamp gen |
| CVE-2024-26001 | Crafted MQTT with oversized payload | PASS - OOB write in MQTT parser |
| CVE-2024-26000 | Crafted MQTT with boundary lengths | PASS - OOB read in MQTT parser |
| CVE-2024-26003 | Malformed HomePlug MME packets | PASS - null deref from offset error |
| CVE-2024-26004 | Malformed network input to control agent | PASS - uninitialized pointer |
| CVE-2025-24002 | MQTT message with empty/missing fields | PASS - crash from missing field access |
| CVE-2025-24003 | MQTT message with oversized status field | PASS - memcpy without bounds check |
| CVE-2025-24004 | Chained with CVE-2025-24003 overflow | PASS - sprintf stack overflow |
| CVE-2024-23967 | WebSocket msg with large base64 payload | PASS - stack overflow in decode |

---

# Broader EV Charger / OCPP Vendor CVEs

Non-parsing CVEs covering authentication bypasses, hardcoded credentials, BLE exploits,
command injection, and other attack vectors across the EV charging ecosystem.

---

## ABB

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2023-0863 | Terra AC Wallbox | 8.8 | BLE improper auth -- unauthenticated admin access via Bluetooth |
| CVE-2023-0864 | Terra AC Wallbox | 7.1 | BLE plaintext communication, replay attacks |
| CVE-2025-5517 | Terra AC Wallbox | -- | Buffer overflow causing DoS |

## Schneider Electric

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2018-7800 | EVLink Parking | 9.8 | Hard-coded credentials |
| CVE-2018-7801 | EVLink Parking | 8.8 | Code injection / RCE |
| CVE-2018-7802 | EVLink Parking | 6.4 | SQL injection |
| CVE-2021-22707 | EVlink City/Parking/Wallbox | 9.8 | Hard-coded credentials (cookie bypass) |
| CVE-2021-22708 | EVlink City/Parking/Wallbox | -- | Flawed firmware signature verification |
| CVE-2021-22726 | EVlink City/Parking/Wallbox | -- | SSRF |
| CVE-2021-22774 | EVlink City/Parking/Wallbox | -- | Weak password storage (unsalted hashes) |
| CVE-2024-8070 | EVlink Home Smart / Schneider Charge | 8.5 | Cleartext creds in firmware binary |
| CVE-2025-5740 | EVLink Wallbox | -- | Path traversal (arbitrary file read) |
| CVE-2025-5741 | EVLink Wallbox | -- | Arbitrary code execution via file write |

Note: Schneider will NOT patch EVLink Wallbox (end-of-life). DIVD-2025-00012 recommends decommissioning.

## Siemens

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2025-31929 | VersiCharge AC Series | 8.8 | Missing immutable root of trust -- arbitrary code execution |
| CVE-2025-31930 | VersiCharge AC Series | 8.7 | Modbus enabled by default -- unauthenticated remote control |

## ChargePoint

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2024-23968 | Home Flex | -- | Stack buffer overflow in SrvrToSmSetAutoChnlListMsg (RCE) |
| CVE-2024-23921 | Home Flex | -- | OS command injection in wlanapp module (root) |
| CVE-2024-23970 | Home Flex | -- | Buffer overflow via Bluetooth (RCE) |
| CVE-2024-23971 | Home Flex | -- | Pwn2Own Automotive 2024 |
| CVE-2024-23920 | Home Flex | -- | Pwn2Own Automotive 2024 |
| CVE-2024-7391 | Home Flex | -- | BLE information disclosure |

## Autel

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2024-23958 | MaxiCharger AC Wallbox | -- | Hard-coded debug credentials |
| CVE-2024-23959 | MaxiCharger AC Wallbox | -- | Stack buffer overflow via Bluetooth |
| CVE-2024-23957 | MaxiCharger AC Wallbox | -- | Stack buffer overflow via DLB protocol |

## Tesla

| CVE | Product | Type |
|-----|---------|------|
| CVE-2025-8321 | Wall Connector Gen 3 | Exploit chain: SWCAN -> firmware downgrade -> buffer overflow -> RCE (via charging port) |
| CVE-2025-8320 | Wall Connector | HTTP Content-Length validation flaw -> RCE |

## Circontrol

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2018-17918 | CirCarLife SCADA | 10.0 | Authentication bypass by URL navigation |
| CVE-2018-17922 | CirCarLife SCADA | 10.0 | PAP credentials in cleartext log file |
| CVE-2020-8006 | Raption | -- | Pre-auth stack buffer overflow |
| CVE-2020-8007 | Raption | -- | Command injection in pwrstudio |

## Alpitronic

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2024-4622 | Hypercharger (all versions) | 8.3 | Default credentials on web interface (admin/admin123) |

## eCharge / Hardy Barth

| CVE | Product | Type |
|-----|---------|------|
| CVE-2024-11665 | eCharge controllers | Unauthenticated information leak |
| CVE-2024-11666 | eCharge controllers | RCE via insecure cloud channel (MITM) |
| CVE-2023-46359 | Hardy Barth cPH2 | Remote command execution |
| CVE-2025-27803 | cPH2/cPP2 | Missing auth for web interface and MQTT |
| CVE-2025-27804 | cPH2/cPP2 | OS command injection via MQTT (root) |
| CVE-2025-48413 | cPH2/cPP2 | Hard-coded root password hashes |

## Phoenix Contact (Additional)

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2025-25270 | CHARX SEC-3xxx | 9.8 | Unauthenticated RCE (root) via config alteration |
| CVE-2025-25268 | CHARX SEC-3xxx | 8.8 | Unauthenticated config modification via API |
| CVE-2025-25271 | CHARX SEC-3xxx | 8.8 | OCPP backend reconfiguration via insecure defaults |

## JuiceBox (Enel X Way)

| CVE | Product | Type |
|-----|---------|------|
| CVE-2024-23938 | JuiceBox 40 | RCE via Gecko OS logging + Bluetooth |

## Ubiquiti

| CVE | Product | Type |
|-----|---------|------|
| CVE-2026-21635 | UniFi Connect EV Station Lite | WiFi AutoLink exploit |

---

## CISA ICS Advisories for EV Chargers

| Advisory ID | Date | Vendor/Product |
|-------------|------|----------------|
| ICSA-18-305-03 | Oct 2018 | Circontrol CirCarLife |
| ICSA-19-031-01 | Jan 2019 | Schneider Electric EVLink Parking |
| ICSA-24-130-02 | May 2024 | alpitronic Hypercharger |
| ICSA-25-023-03 | Jan 2025 | Schneider Electric EVlink Home Smart |
| ICSA-25-135-08 | May 2025 | Siemens VersiCharge AC Series |
| ICSA-25-175-04 | Jun 2025 | Schneider Electric EVLink WallBox |
| ICSA-25-303-01 | Oct 2025 | ISO 15118-2 SLAC protocol MITM |

## Pwn2Own Automotive Statistics

- **2024 (Tokyo):** 49 unique zero-days, 26 attack chains targeting EV chargers
- **2025 (Tokyo):** 49 unique zero-days across 50 attempts over 3 days
- Chargers described as the "simplest" targets at Pwn2Own

## References

- SaiFlow: ABB Terra AC/ChargerSync, OCPP hijacking research
- Pwn2Own Automotive 2024/2025: Computest Sector 7, Synacktiv, ZDI, RET2 Systems
- SEC Consult: Schneider EVlink, eCharge Hardy Barth advisories
- ONEKEY: eCharge controllers firmware analysis
- Pen Test Partners: Smart Car Chargers research (2021)
- Quarkslab: EVerest security audit (OSTIF-sponsored)
- INL/Sandia/SwRI: National lab EV charging security research
- CERT VDE: Phoenix Contact advisories
