# GATT / BLE - Notable CVEs

CVEs related to parsing and processing vulnerabilities in BLE/GATT implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2020-10069 | Zephyr BLE Stack | Bluetooth unchecked packet data causes denial of service | DoS | 6.5 | [Zephyr Advisory](https://github.com/zephyrproject-rtos/zephyr/security) |
| CVE-2020-10061 | Zephyr BLE Stack | Improper handling of full-buffer case causes out-of-bounds write / memory corruption | OOB Write | 8.8 | [Zephyr Advisory](https://github.com/zephyrproject-rtos/zephyr/security) |
| CVE-2019-16336 | Cypress PSoC 4 BLE (SweynTooth) | BLE Link Layer payload length overflow causes crash | Buffer Overflow | 6.5 | [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) |
| CVE-2019-17519 | NXP KW41Z SDK (SweynTooth) | BLE Link Layer payload length not restricted, causing buffer overflow | Buffer Overflow / RCE | 8.8 | [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) |
| CVE-2019-17517 | Dialog Semiconductor DA14580/1/2/3 (SweynTooth) | L2CAP payload length not restricted causing buffer overflow | Buffer Overflow | 5.7 | [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) |
| CVE-2019-17060 | NXP KW41Z SDK (SweynTooth) | BLE Link Layer with LLID zero causes deadlock or buffer overflow | DoS / Buffer Overflow | 6.5 | [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) |

| CVE-2018-16986 | Texas Instruments BLE Chips (BLEEDINGBIT) | RCE via BLE advertising packet overflow, malicious packets stored in chip memory | RCE | 8.8 | [Armis BLEEDINGBIT](https://www.armis.com/research/bleedingbit/) |
| CVE-2018-7080 | Texas Instruments BLE Chips (BLEEDINGBIT) | OAD backdoor allows unauthenticated firmware upload over BLE | RCE | 9.8 | [Armis BLEEDINGBIT](https://www.armis.com/research/bleedingbit/) |
| CVE-2021-28139 | Espressif ESP32 (BrakTooth) | BLE Classic LMP feature response handler lacks bounds check, arbitrary code execution | RCE | 8.8 | [BrakTooth PoC](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks) |
| CVE-2025-20700 | Airoha BLE SoC (RACE) | Missing authentication in GATT services allows unauthenticated BLE access | Auth Bypass | 8.1 | [Insinuator Advisory](https://insinuator.net/2025/06/airoha-bluetooth-security-vulnerabilities/) |
| CVE-2025-20702 | Airoha BLE SoC (RACE) | RACE protocol exposes unauthenticated RAM/flash read/write over BLE, enables firmware tampering and code execution | RCE | 9.8 | [RACE Toolkit](https://github.com/auracast-research/race-toolkit) |
| CVE-2025-44557 | Cypress PSoC4 BLE Stack | State machine transition flaw allows pairing bypass via crafted 'pairing_failed' packet | Auth Bypass | 8.1 | [CVE Details](https://www.cvedetails.com/vulnerability-list/vendor_id-11436/Bluetooth.html) |

---

## Detailed Writeups (Server-Side Parsing Bugs)

The following CVEs pass the fuzzer test: sending malformed/crafted bytes on the wire (BLE radio link) triggers the bug. CVEs that are auth bypasses, logic flaws, or design issues (CVE-2018-7080, CVE-2025-20700, CVE-2025-20702, CVE-2025-44557) are excluded from detailed writeups because they are not parser-triggered vulnerabilities.

### CVE-2019-16336
- **Product**: Cypress PSoC 4 BLE Component v3.61 and earlier (also PSoC 6 BLE Component v2.60)
- **Type**: Buffer Overflow
- **CVSS**: 6.5 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the BLE peripheral (server role) processes incoming Link Layer data channel frames and trusts the payload length field without validating it against the configured maximum RX payload size
- **Root cause**: The BLE Link Layer implementation does not check that the incoming data channel frame's payload length is within the maximum RX payload size negotiated via LL_LENGTH_REQ/RSP (or the default 27 bytes). The length field from the LL header is used directly to determine how many bytes to copy into a fixed-size reception buffer, causing a stack or heap buffer overflow when the attacker sends a frame with length larger than the buffer.
- **Trigger**: BLE Link Layer data channel PDU with the Length field in the LL header set to a value larger than the negotiated/default maximum RX payload size (e.g., 0xFF when the buffer is sized for 27 bytes). The attacker must first establish a BLE connection to the target peripheral, then send the oversized data channel frame.
- **PoC**: [link_layer_length_overflow.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/link_layer_length_overflow.py) -- requires a Nordic nRF52840 dongle flashed with custom firmware
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-ALERT-20-063-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01), [Infineon Security Bulletin](https://community.infineon.com/t5/Blogs/Security-Bulletin-BLE-Security-Vulnerabilities-CVE-2019-17061-and-CVE-2019-16336/ba-p/179519)
- **Analysis**: Classic unchecked length field leading to memcpy overflow. A fuzzer mutating the 8-bit Length field in the BLE Link Layer header to values beyond the negotiated MTU (especially 0xFF, 0xFE, boundary values around 27/251) would trigger this immediately. The mutation strategy is trivial: bit-flip or replace the LL Length byte with maximum/random values. This is the canonical "length field overflow" pattern that any protocol-aware BLE fuzzer should test.

### CVE-2019-17519
- **Product**: NXP MCUXpresso SDK with BLE Driver v2.2.1 and earlier for KW41Z SoC
- **Type**: Buffer Overflow / RCE
- **CVSS**: 8.8 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the BLE peripheral running on the KW41Z processes incoming Link Layer frames and does not restrict the payload length, allowing a buffer overflow that can overwrite return addresses or function pointers
- **Root cause**: Identical vulnerability class to CVE-2019-16336 but in the NXP BLE stack. The Link Layer payload length from the incoming frame header is not validated against the maximum allowed RX PDU size before the payload is copied into a fixed-size buffer. On the KW41Z, the memory layout allows the overflow to corrupt adjacent structures, making RCE feasible with firmware reverse engineering.
- **Trigger**: BLE Link Layer data channel PDU with Length field exceeding the configured maximum. After establishing a connection to the KW41Z peripheral, send a data channel frame with an oversized length (e.g., length=0xFF with >27 bytes of payload data). The device crashes immediately; with crafted payload content, code execution is possible.
- **PoC**: [link_layer_length_overflow.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/link_layer_length_overflow.py) -- same SweynTooth script, target the KW41Z device MAC address
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-ALERT-20-063-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01), [NXP SweynTooth Blog](https://community.nxp.com/t5/NXP-Tech-Blog/Bluetooth-Low-Energy-Vulnerabilities-SweynTooth/ba-p/1131173)
- **Analysis**: Same mutation strategy as CVE-2019-16336. The NXP KW41Z is found in products from August Home (smart locks), Eve Systems, and Samsung. The higher CVSS (8.8 vs 6.5) reflects that on the KW41Z the memory layout makes the overflow exploitable for code execution, not just DoS. A fuzzer should vary the LL Length field across the full 0x00-0xFF range while also varying the actual payload size independently (length field says 200, but actual data is 50 bytes, or vice versa -- testing both truncated and oversized cases).

### CVE-2019-17060
- **Product**: NXP MCUXpresso SDK with BLE Driver v2.2.1 and earlier for KW41Z SoC
- **Type**: DoS / Buffer Overflow (LLID Deadlock)
- **CVSS**: 6.5 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the BLE Link Layer controller on the KW41Z does not validate the LLID field in data channel PDU headers, and processes memory contents based on an LLID value of zero which is not a valid state
- **Root cause**: The BLE Link Layer header contains a 2-bit LLID field (values 0x01=continuation, 0x02=start of L2CAP, 0x03=LL control). The value 0x00 is reserved/invalid per the BLE spec, but the NXP stack does not reject it. When LLID=0x00 is received, the stack enters an undefined code path that either deadlocks the BLE state machine (no further packets are processed, device requires hard reset) or triggers a buffer overflow depending on the packet sequence.
- **Trigger**: BLE Link Layer data channel PDU with the LLID field set to 0x00 (binary: clear bits 0-1 of the first byte of the LL header). This can be sent as part of a LL_VERSION_IND or pairing request. The SweynTooth PoC alternates between sending version requests and pairing requests with LLID=0 on each reconnection to reliably trigger the deadlock.
- **PoC**: [llid_deadlock.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/llid_dealock.py) -- requires nRF52840 dongle
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-ALERT-20-063-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01), [NXP SweynTooth Blog](https://community.nxp.com/t5/NXP-Tech-Blog/Bluetooth-Low-Energy-Vulnerabilities-SweynTooth/ba-p/1131173)
- **Analysis**: This is a reserved-value injection bug. The LLID field is only 2 bits, so exhaustive fuzzing of all 4 values (0x00, 0x01, 0x02, 0x03) is trivial. The bug is found by simply clearing the LLID bits to zero. A BLE Link Layer fuzzer should test all reserved/undefined values in every header field, especially fixed-width enum fields where the spec defines only a subset of possible values. The deadlock behavior (device stops responding but does not crash) is also an important detection case -- fuzzers need liveness checks, not just crash detection.

### CVE-2019-17517
- **Product**: Dialog Semiconductor SDK v5.0.4 and earlier for DA14580/DA14581/DA14582/DA14583 SoCs
- **Type**: Buffer Overflow
- **CVSS**: 5.7 (CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the BLE peripheral on the Dialog DA14580 family processes incoming L2CAP frames and trusts the L2CAP Length field without cross-checking it against the Link Layer payload length
- **Root cause**: When the BLE stack receives a data channel frame, the L2CAP header contains its own length field. If the LL payload length (from the Link Layer header) is smaller than the L2CAP length + 4 (L2CAP header size), the stack still copies L2CAP-length bytes into the reception buffer. The extra bytes come from whatever follows the actual payload in memory, causing an out-of-bounds read. More critically, the truncated frame triggers the L2CAP reassembly logic to write beyond the reception buffer boundary, causing a buffer overflow. This is a length-field inconsistency bug between protocol layers.
- **Trigger**: BLE data channel frame where LL Length < (L2CAP Length + 4). For example: LL header with Length=10, but the L2CAP header inside claims Length=100. The L2CAP reassembly logic trusts the L2CAP length and overflows the buffer. Send this after establishing a BLE connection. Affected medical devices include the Medtronic Azure XT DR MRI pacemaker and the VivaCheck blood glucose meter.
- **PoC**: [DA14580_exploit_att_crash.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/DA14580_exploit_att_crash.py) -- requires nRF52840 dongle
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-ALERT-20-063-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01), [Dialog/Renesas Security Advisory](https://www.dialog-semiconductor.com/sweyntooth-bluetooth-low-energy-vulnerability)
- **Analysis**: This is a cross-layer length inconsistency bug -- the L2CAP length disagrees with the LL length, and the parser trusts the wrong one. A fuzzer should independently mutate length fields at each protocol layer (LL Length vs. L2CAP Length) and test all combinations: LL < L2CAP, LL > L2CAP, LL = 0, L2CAP = 0, L2CAP = 0xFFFF. This pattern is extremely common in layered protocols and is a high-value mutation strategy for any protocol with nested length fields.

### CVE-2020-10069
- **Product**: Zephyr RTOS BLE Stack v1.14.2+, v2.2.0+ (affects nRF51/nRF52 targets)
- **Type**: DoS (Assertion Failure / Division by Zero)
- **CVSS**: 6.5 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the Zephyr BLE Link Layer controller parses the Channel Map field from incoming LL_CONNECTION_REQ (CONNECT_IND) PDUs without validating that at least one data channel is enabled
- **Root cause**: When a BLE central sends a connection request, the Channel Map field (5 bytes, 37 bits for data channels) specifies which RF channels to use for the connection. The Zephyr controller does not check for an all-zeros channel map. An all-zeros value causes either a reachable assertion failure (ASSERT fires when no valid channel is found) or a division by zero when the hop calculation divides by the number of used channels (which is zero). Both paths cause the peripheral to crash/restart immediately.
- **Trigger**: BLE LL_CONNECTION_REQ (CONNECT_IND) PDU with the Channel Map field set to 0x0000000000 (all 37 data channel bits cleared). This is sent during the connection establishment phase, before any L2CAP or ATT traffic. The peripheral crashes on the first connection event.
- **PoC**: [invalid_channel_map.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/invalid_channel_map.py) -- requires nRF52840 dongle
- **Metasploit**: N/A
- **Advisory**: [Zephyr GHSA-f6vh-7v4x-8fjp](https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-f6vh-7v4x-8fjp), [CISA ICS-ALERT-20-063-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01)
- **Analysis**: This is a zero-value edge case that developers routinely miss. The Channel Map is supposed to have at least 2 bits set per the BLE spec, but the Zephyr controller did not enforce this. A fuzzer should test boundary values in bitmap/bitfield parameters: all-zeros, all-ones, single-bit-set, and random patterns. The fact that this causes either an assertion or a div-by-zero means the bug manifests differently depending on build configuration (debug vs. release), so fuzzing infrastructure must detect both crash types.

### CVE-2020-10061
- **Product**: Zephyr RTOS BLE Stack v1.14.0+, v2.2.0+ (affects nRF51/nRF52 targets)
- **Type**: OOB Write / Memory Corruption (Dangling Pointer)
- **CVSS**: 8.8 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the Zephyr BLE Link Layer controller mishandles the sequence number (SN) and next-expected sequence number (NESN) bits in the first connection event anchor point, leading to memory corruption in the TX retry buffer
- **Root cause**: When a BLE central initiates a connection, the first data channel PDU (anchor point) should have SN=0 and NESN=0. If the central sends the anchor point with both NESN=1 and SN=1, the Zephyr peripheral's Link Layer controller treats this as an acknowledgment of a packet it never sent. This triggers an invalid operation on the internal packet buffer (advancing the TX queue past its actual contents). If the central continues sending packets, the retry buffer fills up and the controller creates a dangling pointer to freed memory, leading to memory corruption and eventual crash with potential for code execution.
- **Trigger**: BLE connection anchor point (first data channel PDU after CONNECT_IND) with both SN and NESN bits set to 1 in the Link Layer header. Follow with additional data channel PDUs to fill the retry buffer and trigger the dangling pointer dereference. The invalid sequence must be sent in the very first packet of the connection.
- **PoC**: [zephyr_invalid_sequence.py](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks/blob/master/zephyr_invalid_sequence.py) -- requires nRF52840 dongle
- **Metasploit**: N/A
- **Advisory**: [Zephyr Security Advisories](https://github.com/zephyrproject-rtos/zephyr/security), fixes in PRs [#23516](https://github.com/zephyrproject-rtos/zephyr/pull/23516), [#23517](https://github.com/zephyrproject-rtos/zephyr/pull/23517), [#23547](https://github.com/zephyrproject-rtos/zephyr/pull/23547)
- **Analysis**: This is a state machine corruption bug triggered by invalid sequence numbers in the very first packet. The SN/NESN fields are only 1 bit each, so exhaustive testing of all 4 combinations (00, 01, 10, 11) at the connection anchor point is trivial and would catch this. The dangling pointer is a use-after-free class bug that requires multi-packet interaction to fully trigger -- the fuzzer needs to continue the connection after the initial invalid packet, not just send-and-check. Stateful BLE fuzzers that maintain connection state will find this; single-packet fuzzers will only see the initial "no crash" and miss the delayed corruption.

### CVE-2018-16986
- **Product**: Texas Instruments BLE-STACK v2.2.1 for CC2640 (non-R2) and CC2650; SimpleLink CC2640R2 SDK v1.00.00.22 for CC2640R2F; SimpleLink CC13x0 SDK v2.20.00.38 and earlier for CC1350
- **Type**: Heap Overflow / RCE
- **CVSS**: 8.8 (CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the BLE chip firmware (acting as a BLE peripheral/observer in enterprise access points from Cisco, Meraki, and Aruba) parses incoming BLE advertising packets via the llGetAdvChanPDU() ROM function and mishandles a reserved header bit
- **Root cause**: The function llGetAdvChanPDU() in the TI BLE-STACK ROM image parses BLE advertising PDU headers. The BLE 4.2 spec defines the Length field in advertising headers as 6 bits, with 2 bits reserved (RFU). BLE 5.0 extended this to 8 bits. The TI firmware on affected chips interprets the RFU bits as part of the length field when a specific header bit is set, causing the chip to allocate a much larger memory region than the actual packet size. When the attacker first stages multiple benign advertising packets (containing shellcode fragments) in the chip's memory, then sends a final "overflow packet" with the RFU/length bit manipulation, the heap overflow overwrites adjacent heap metadata and stored packet data, achieving code execution.
- **Trigger**: Two-phase attack: (1) Send multiple BLE advertising packets containing crafted payloads (shellcode fragments) that get stored in the chip's advertising packet cache. (2) Send a final advertising packet with the RFU bit in the header turned ON, causing the 6-bit length field to be interpreted as 8 bits. This triggers heap overflow in the advertising packet parser, overwriting critical heap structures. No BLE connection or pairing required -- advertising packets are processed passively.
- **PoC**: No public exploit PoC released. The vulnerability was discovered and disclosed by Ben Seri and Dor Zusman at Armis. Technical white paper available from Armis.
- **Metasploit**: N/A
- **Advisory**: [CERT/CC VU#317277](https://vulners.com/cert/VU:317277), [Armis BLEEDINGBIT](https://www.armis.com/research/bleedingbit/)
- **Analysis**: This is a header bit reinterpretation bug -- reserved bits in the advertising PDU header change the semantics of the length field. A fuzzer should test all possible values of "reserved" or "RFU" bits in protocol headers, not just the spec-defined values. The two-phase attack (staging + trigger) is sophisticated but the trigger itself is a single bit flip in a header field. The key mutation strategy is to toggle every RFU/reserved bit in BLE advertising PDU headers and observe the chip's memory allocation behavior. This vulnerability is especially impactful because it does not require an established connection -- any device scanning for BLE advertisements (which enterprise APs do constantly) is vulnerable.

### CVE-2021-28139
- **Product**: Espressif ESP-IDF v4.4 and earlier (ESP32 SoC Bluetooth Classic stack)
- **Type**: OOB Write / RCE
- **CVSS**: 8.8 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the ESP32 Bluetooth Classic (BR/EDR) Link Manager Protocol handler accepts LMP_feature_response_ext packets with arbitrary Feature Page values and writes 8 bytes of attacker-controlled data to an out-of-bounds offset in the Extended Feature Page Table
- **Root cause**: When the ESP32 BT Library receives an LMP_feature_response_ext packet, it uses the Features Page field as an index into the Extended Feature Page Table to determine the write offset, and writes the 8-byte Extended Features bitfield to that offset. There is no bounds check on the page index. The Feature Page Table is small (a few entries), but the attacker can specify arbitrary page values (e.g., 0x62). At offset 0x62 from the table base, the BT Library stores callback function pointers. By writing a known function address (e.g., nvs_flash_erase) to this offset via the Features bitfield, the attacker overwrites a callback that is later invoked during normal BT connection operation, achieving arbitrary code execution.
- **Trigger**: After establishing a Bluetooth Classic (BR/EDR) connection to the ESP32 (no pairing or authentication required), send an LMP_feature_response_ext packet with Features Page = 0x62 and Extended Features = address of target function (e.g., nvs_flash_erase). The overwritten callback pointer is invoked during subsequent BT operations, redirecting execution to the attacker-chosen function. The PoC demonstrates erasing the ESP32's NVS flash partition.
- **PoC**: [braktooth_esp32_bluetooth_classic_attacks](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks) -- exploit module `invalid_feature_page_execution` in `modules/exploits/`. Requires ESP-WROVER-KIT with custom LMP firmware.
- **Metasploit**: N/A
- **Advisory**: [CISA BrakTooth Alert](https://www.cisa.gov/news-events/alerts/2021/11/04/braktooth-proof-concept-tool-demonstrates-bluetooth-vulnerabilities), [BrakTooth Disclosure](https://asset-group.github.io/disclosures/braktooth/)
- **Analysis**: This is an array index out-of-bounds bug where a single-byte index field controls a write offset into a table that is adjacent to function pointers in memory. A fuzzer should enumerate all possible values of the Features Page field (0x00-0xFF) in LMP_feature_response_ext packets. The bug is triggered by any page value outside the small valid range (typically 0-2). The exploitation is made reliable by the deterministic memory layout of the ESP32 firmware -- the callback table is at a fixed offset from the feature page table. This pattern (unchecked index into array adjacent to function pointers) is a high-value target for mutation-based fuzzing of any protocol with index/offset fields.

---

## Key Vulnerability Patterns for Fuzzing

1. **ATT PDU Size vs. MTU**: Sending PDUs larger than negotiated MTU, or MTU Exchange with extreme values
2. **Handle Ranges**: Start handle > end handle, handle 0x0000, handles beyond database size
3. **UUID Format Byte**: Wrong format byte (0x01 vs 0x02) causing UUID size mismatch with data
4. **Prepare Write Queue**: Large number of queued writes exhausting memory, conflicting offsets
5. **L2CAP Length**: L2CAP length field mismatched with actual BLE payload
6. **Notification Flooding**: Rapid notifications without flow control
7. **Read Blob Offset**: Offset values exceeding attribute value length
8. **Link Layer Length**: LL_LENGTH_REQ with extreme values (SweynTooth attack pattern)
9. **Advertising Packet Overflow**: BLE advertising packets stored in chip memory then triggered by overflow packet (BLEEDINGBIT CVE-2018-16986)
10. **Vendor GATT Services Without Auth**: Manufacturer debug/diagnostic services exposed over GATT without authentication (Airoha RACE CVE-2025-20700/20702)
11. **Pairing State Machine Flaws**: Crafted pairing_failed or unexpected SMP packets causing state machine transitions that bypass authentication (CVE-2025-44557)
12. **Cross-Layer Length Inconsistency**: LL Length vs. L2CAP Length disagreement causes buffer overflows when the parser trusts the wrong length (CVE-2019-17517)
13. **Reserved/RFU Bit Manipulation**: Setting reserved bits in LL/advertising headers changes parser behavior in unexpected ways (CVE-2018-16986)
14. **Invalid Sequence Numbers**: SN/NESN bit combinations not expected at connection start cause state machine corruption and dangling pointers (CVE-2020-10061)
15. **Zero/Cleared Bitmap Fields**: All-zero channel maps, feature masks, or bitfields trigger division by zero or assertion failures (CVE-2020-10069)
16. **LMP Index Fields**: Unchecked page/index values in LMP packets cause out-of-bounds writes to adjacent function pointer tables (CVE-2021-28139)
