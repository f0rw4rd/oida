# Industrial Ethernet - Notable CVEs

## Summary Table

**Parsing bugs (pass fuzzer test -- malformed bytes on the wire trigger the bug):**

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-7244 | ICSNPP EtherCAT Zeek Plugin | OOB write in primary EtherCAT analysis function | OOB Write / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7244) |
| CVE-2023-7243 | ICSNPP EtherCAT Zeek Plugin | OOB write in EtherCAT datagram analysis | OOB Write / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7243) |
| CVE-2023-7242 | ICSNPP EtherCAT Zeek Plugin | OOB read during EtherCAT packet analysis, crash and info leak | OOB Read / Info Leak | 8.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7242) |
| CVE-2025-32405 | RT-Labs P-Net v1.0.1 (PROFINET) | ArVendorBlock parsing OOB write corrupts AR connection buffer | OOB Write / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32405) |
| CVE-2025-32396 | RT-Labs P-Net v1.0.1 (PROFINET) | Heap overflow in ExpectedSubmoduleBlockReq RPC parsing | Heap Overflow / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32396) |
| CVE-2025-32400 | RT-Labs P-Net v1.0.1 (PROFINET) | Heap overflow in ppm-init-buf from malicious RPC packet | Heap Overflow / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32400) |
| CVE-2025-32398 | RT-Labs P-Net v1.0.1 (PROFINET) | NULL deref in RPCPtRequest from malformed RPC packet | NULL Deref / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32398) |
| CVE-2022-25622 | Siemens PROFINET (Interniche Stack) | PNIO stack crashes on TCP segments with header length < minimum | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-25622) |
| CVE-2019-5637 | Beckhoff TwinCAT 2/3.1 | Divide-by-zero in PROFINET DCP ResponseDelay parsing | Divide-by-Zero / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5637) |
| CVE-2019-5636 | Beckhoff TwinCAT 2/3.1 | ADS Discovery handler exits on empty UDP packet (zero-length parsing) | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5636) |
| CVE-2020-12494 | Beckhoff TwinCAT RT Network Driver | Uninitialized padding bytes leak memory in EtherCAT frames | Info Leak | 5.3 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-12494) |

**Resource exhaustion / flooding bugs (fail fuzzer test -- valid packets at high volume, not malformed bytes):**

| CVE ID | Affected Product | Description | Type | CVSS | Why excluded from writeups |
|--------|-----------------|-------------|------|------|---------------------------|
| CVE-2019-13946 | Siemens PROFINET (PNIO Stack) | DCE-RPC diagnostic request flooding exhausts memory | Resource Exhaustion | 7.5 | Flooding with valid diagnostic packets, not malformed parsing |
| CVE-2020-28400 | Siemens SCALANCE / SIMATIC | DCP reset packet flooding causes DoS | Resource Exhaustion | 7.5 | Volume-based DCP reset flood, not crafted bytes |
| CVE-2017-2681 | Siemens Industrial Products | Crafted PROFINET DCP packets cause DoS | Resource Exhaustion | 6.5 | CWE-400 resource consumption, Layer 2 flooding |
| CVE-2019-10936 | Siemens PROFINET (PNIO Stack) | UDP packet flooding exhausts memory on DCE-RPC | Resource Exhaustion | 7.5 | Volume-based flood of UDP packets, not malformed parsing |

**REMOVED from previous version (fabricated or misattributed CVE entries):**

| Claimed CVE | Claimed Product | Actual Product (per NVD) | Reason removed |
|-------------|----------------|--------------------------|----------------|
| CVE-2020-15034 | "Beckhoff TwinCAT EtherCAT" | NeDi 1.9C (XSS vulnerability) | Wrong product. NVD says this is XSS in NeDi, not EtherCAT. |
| CVE-2022-37885 | "Beckhoff ADS EtherCAT" | Aruba Networks InstantOS/ArubaOS | Wrong product. NVD says this is Aruba AP management protocol buffer overflow. |
| CVE-2021-25664 | "SOEM EtherCAT datagram parsing" | Siemens Nucleus NET IPv6 stack | Wrong product. NVD says this is IPv6 Hop-by-Hop infinite loop in Nucleus NET, not SOEM/EtherCAT. |

---

## Detailed Writeups

### CVE-2025-32405
- **Product**: RT-Labs P-Net v1.0.1 (open-source PROFINET IO device stack)
- **Type**: Out-of-bounds Write (CWE-787)
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- IO device stack parses incoming PROFINET RPC ArVendorBlock requests over UDP
- **Root cause**: When the P-Net library parses ArVendorBlock requests within PROFINET CMRPC (Connection Manager RPC) messages, it increments a counter and uses it as an array index to write data extracted from the incoming UDP packet into a buffer storing Application Relation (AR) context. The counter is never bounds-checked against the array size. By sending repeated ArVendorBlock requests, an attacker drives the index past the array boundary, writing attacker-controlled data into adjacent heap memory. The vulnerable function is the handler for PF_BT_AR_VENDOR_BLOCK_REQ.
- **Trigger**: Send multiple PROFINET CMRPC UDP packets (port 34964 or 49155) containing ArVendorBlock sub-blocks. Each packet increments the unbounded counter. After enough packets, the write index exceeds the AR context array, corrupting adjacent memory. The device becomes permanently unusable (bricked until power cycle or reflash).
- **PoC**: No public PoC. Discovered via libFuzzer harness by Nozomi Networks Labs (Luca Borzacchiello).
- **Metasploit**: N/A
- **Advisory**: [Nozomi Networks Blog](https://www.nozominetworks.com/blog/fuzzing-the-p-net-profinet-implementation) | [RT-Labs Security Update](https://rt-labs.com/cybersecurity/security-update-2025-06-26-p-net-profinet-stack-now-even-more-robust/) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32405)
- **Analysis**: This is a classic unbounded array index from protocol field data. A basic mutation strategy that repeats sub-blocks within CMRPC messages would find this: send a valid ArVendorBlock, then replay it N times with incrementing or duplicated block structures. The fuzzer discovered it with a simple stdin-based harness feeding raw UDP payloads to the CMRPC parser. Mutation strategies: block duplication (repeat ArVendorBlock N times in one session), counter overflow (many small packets with ArVendorBlock), and structure nesting. Fixed in P-Net v1.0.2.

### CVE-2025-32396
- **Product**: RT-Labs P-Net v1.0.1 (open-source PROFINET IO device stack)
- **Type**: Heap-based Buffer Overflow (CWE-122 / CWE-787)
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- IO device stack parses incoming PROFINET CMRPC ExpectedSubmoduleBlockReq over UDP
- **Root cause**: The ExpectedSubmoduleBlockReq parsing function in the PROFINET CMRPC stack does not properly validate the length of submodule data fields before copying them into a heap-allocated buffer. When a malformed RPC packet contains submodule block data larger than expected, memcpy writes past the end of the destination buffer on the heap, corrupting adjacent allocations. This is one of seven CVEs found with a basic single-packet fuzzing harness.
- **Trigger**: Send a single crafted UDP packet to the PROFINET CMRPC port (34964 or 49155) with an ExpectedSubmoduleBlockReq containing oversized submodule data fields. The length field in the submodule block exceeds the allocated buffer, causing a heap overflow on the IO device.
- **PoC**: No public PoC. Discovered via libFuzzer harness by Nozomi Networks Labs (Luca Borzacchiello).
- **Metasploit**: N/A
- **Advisory**: [Nozomi Networks Advisory](https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2025-32396) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32396)
- **Analysis**: Classic heap overflow from trusting a length field in the protocol message. A mutation strategy that inflates length fields (set submodule data length to 0xFFFF while providing minimal actual data, or provide oversized data with a matching large length) would trigger this immediately. The Nozomi team found this with a "basic harness" that fed individual UDP packets to the CMRPC parser via stdin -- no connection establishment required. Byte-level mutations on the length fields of PROFINET RPC sub-blocks are the key strategy. Fixed in P-Net v1.0.2.

### CVE-2025-32398
- **Product**: RT-Labs P-Net v1.0.1 (open-source PROFINET IO device stack)
- **Type**: NULL Pointer Dereference (CWE-476)
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- IO device stack parses incoming PROFINET RPC request over UDP
- **Root cause**: The RPCPtRequest function dereferences a pointer without checking for NULL. When a malformed RPC packet arrives with certain fields missing or zeroed out, the function attempts to access a data structure through a NULL pointer, causing an immediate crash of the IO device process. The parsing code assumes that prior RPC setup steps have populated the pointer, but a crafted packet can bypass those steps.
- **Trigger**: Send a single crafted UDP packet to the PROFINET CMRPC port (34964 or 49155) with an RPC request that omits or zeroes out fields required for pointer initialization. The RPCPtRequest handler dereferences NULL and the device crashes.
- **PoC**: No public PoC. Discovered via libFuzzer harness by Nozomi Networks Labs (Luca Borzacchiello).
- **Metasploit**: N/A
- **Advisory**: [CVE Details](https://www.cvedetails.com/cve/CVE-2025-32398/) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32398)
- **Analysis**: NULL deref from missing/zeroed fields is one of the most common fuzzer finds in C protocol stacks. The mutation strategy is straightforward: zero out individual fields in a valid RPC request, or truncate the packet at various offsets so that fields needed for pointer initialization are absent. A coverage-guided fuzzer with a zero-fill mutation operator would find this quickly. The basic single-packet harness that Nozomi used found this without needing an established session. Fixed in P-Net v1.0.2.

### CVE-2023-7244
- **Product**: ICSNPP EtherCAT Zeek Plugin (versions through commit d78dda6)
- **Type**: Out-of-bounds Write (CWE-787)
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- Zeek IDS/monitor server-side plugin parses EtherCAT frames passively from network traffic
- **Root cause**: The primary analysis function for EtherCAT communication packets in the ICSNPP Zeek plugin writes past the end of a buffer when processing crafted EtherCAT frames. The parser walks the EtherCAT datagram chain (EtherType 0x88A4) and for each datagram extracts fields based on length values embedded in the frame header. When a datagram header declares a data length that exceeds the actual buffer, the parser writes out of bounds. Because Zeek plugins run with full process privileges, this achieves arbitrary code execution on the monitoring host.
- **Trigger**: Send an EtherCAT frame (EtherType 0x88A4) on the monitored network segment with a crafted datagram chain where the primary datagram header contains a data length field larger than the actual frame payload. The Zeek plugin's primary analysis function writes past the allocated buffer.
- **PoC**: No public exploit PoC. The fix commit is [3bca34c](https://github.com/cisagov/icsnpp-ethercat) in the cisagov/icsnpp-ethercat repository.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-24-051-02](https://www.cisa.gov/news-events/ics-advisories/icsa-24-051-02) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7244) | [Snyk](https://security.snyk.io/vuln/SNYK-UNMANAGED-CISAGOVICSNPPETHERCAT-6370637)
- **Analysis**: This is an attack on the IDS itself, not on the EtherCAT device. An attacker on the same Layer 2 segment can achieve code execution on the Zeek monitoring host by injecting crafted EtherCAT frames. The root cause is trusting length fields in the EtherCAT datagram header without bounds checking against the actual frame size. Fuzzing strategy: mutate the 11-bit datagram length field in the EtherCAT header (bits 0-10 of the datagram header word) to values larger than the frame, chain multiple datagrams with inconsistent lengths, or truncate the frame after the header. A simple pcap replay fuzzer that mutates EtherCAT datagram headers would find this.

### CVE-2023-7243
- **Product**: ICSNPP EtherCAT Zeek Plugin (versions through commit d78dda6)
- **Type**: Out-of-bounds Write (CWE-787)
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- Zeek IDS/monitor server-side plugin parses EtherCAT datagrams passively from network traffic
- **Root cause**: During analysis of specific EtherCAT datagrams within the Zeek plugin, a secondary parsing function writes beyond allocated buffer boundaries. This is distinct from CVE-2023-7244 in that it occurs in the datagram-specific analysis path (handling individual datagram types like LRD, LWR, LRW, BRD, etc.) rather than in the primary frame analysis function. The parser does not validate that the datagram payload fits within the buffer before writing extracted fields.
- **Trigger**: Send an EtherCAT frame (EtherType 0x88A4) containing a specific datagram type (e.g., LRW -- Logical Read Write) with crafted payload data that causes the datagram-specific parser to write past its buffer. The datagram command byte selects which parsing path is taken, and certain paths have insufficient bounds checking.
- **PoC**: No public exploit PoC. Fixed in commit [3bca34c](https://github.com/cisagov/icsnpp-ethercat) of cisagov/icsnpp-ethercat.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-24-051-02](https://www.cisa.gov/news-events/ics-advisories/icsa-24-051-02) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7243)
- **Analysis**: Same attack surface as CVE-2023-7244 but in a different code path. Fuzzing strategy: iterate over all EtherCAT datagram command types (0x00 through 0x0C: APRD, APWR, APRW, FPRD, FPWR, FPRW, BRD, BWR, BRW, LRD, LWR, LRW) with oversized or truncated payloads for each type. The combination of command-type enumeration plus length mutation would cover both this bug and CVE-2023-7244. Three critical OOB write bugs in one parser highlights how dangerous it is to trust protocol length fields in C/C++ parsers.

### CVE-2022-25622
- **Product**: Siemens PROFINET Stack integrated on Interniche IP Stack (multiple SIMATIC products)
- **Type**: DoS / Resource Exhaustion via Malformed TCP Header (CWE-400)
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) per NIST; 5.3 per Siemens
- **Server-side**: Yes -- PROFINET device TCP stack parses incoming TCP segments
- **Root cause**: The PROFINET (PNIO) stack integrated with the Interniche IP stack improperly handles internal resources for TCP segments where the TCP header data offset field specifies a minimum header length smaller than the protocol-defined minimum (20 bytes). When a TCP segment arrives with a data offset value indicating fewer than 5 32-bit words (e.g., data offset = 0 or 1), the stack fails to reject the malformed segment and enters an error state that exhausts internal resources for TCP processing.
- **Trigger**: Send a TCP SYN or data segment to any TCP service port on the PROFINET device with the TCP header data offset field set to a value less than 5 (e.g., set the 4-bit data offset field to 0x0 or 0x1 in the TCP header byte at offset 12). This creates a TCP header that claims to be shorter than the 20-byte minimum, which the Interniche stack fails to reject.
- **PoC**: No public PoC.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-22-104-06](https://www.cisa.gov/news-events/ics-advisories/icsa-22-104-06) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-25622)
- **Analysis**: This is a parsing bug in the TCP layer of the Interniche IP stack used by Siemens PROFINET devices. The TCP data offset field (4 bits) normally indicates 5-15 32-bit words of header. Setting it below 5 creates an impossible header that many embedded TCP stacks fail to handle. Fuzzing strategy: mutate the TCP data offset nibble at byte offset 12 of the TCP header to values 0x0-0x4 (below minimum). Also try all combinations of TCP flags with undersized data offset. A simple TCP header fuzzer that targets the data offset field would catch this. This affects SIMATIC S7-300, S7-400, S7-1500, and other PLCs running the Interniche stack.

### CVE-2019-5637
- **Product**: Beckhoff TwinCAT 2 (v2304 and prior), TwinCAT 3.1 (v4204.0 and prior)
- **Type**: Divide-by-Zero (CWE-369)
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- TwinCAT PLC runtime parses incoming PROFINET DCP Ident Request packets
- **Root cause**: The PROFINET DCP handler in TwinCAT processes Ident Request packets sent to broadcast MAC address 01:0e:cf:00:00:00. The ResponseDelay field from the packet is used as the divisor in a modulo operation to calculate the response timing: `delay = (MAC_low_bytes % ResponseDelay) * constant`. When ResponseDelay is set to zero, this causes a divide-by-zero exception in the PLC runtime.
- **Trigger**: Send a PROFINET DCP Ident Request (EtherType 0x8892, Service ID 0x05 Identify, Service Type 0x00 Request) to broadcast MAC 01:0e:cf:00:00:00 with the ResponseDelay field (2 bytes at the end of the DCP header) set to 0x0000. The PLC runtime crashes with a divide-by-zero exception and restarts into CONFIG mode, stopping all PLC programs and fieldbus activity.
- **PoC**: No public PoC script. Technical details disclosed by Rapid7 in [R7-2019-32](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/).
- **Metasploit**: N/A
- **Advisory**: [Rapid7 Disclosure](https://www.rapid7.com/blog/post/2019/10/08/r7-2019-32-denial-of-service-vulnerabilities-in-beckhoff-twincat-plc-environment-fixed/) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5637)
- **Analysis**: Textbook divide-by-zero from untrusted protocol field used as divisor. Trivially discoverable by any fuzzer that tries zero values for numeric fields. The PROFINET DCP ResponseDelay field is only 2 bytes -- a brute-force enumeration of all 65536 values would hit this instantly. More generally, any integer field used in arithmetic (especially division/modulo) should be fuzzed with 0, 1, 0xFFFF, and boundary values. This bug crashes the entire PLC runtime (not just the network stack), taking all control programs offline. Scapy's ProfinetIO layer can craft DCP Ident Requests trivially: `Ether(dst="01:0e:cf:00:00:00")/ProfinetIO()/...`. Fixed in TwinCAT 2 build 2305+ and TwinCAT 3.1 build 4204.2+.

### CVE-2023-7242
- **Product**: ICSNPP EtherCAT Zeek Plugin (versions through commit d78dda6)
- **Type**: Out-of-bounds Read (CWE-125)
- **CVSS**: 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H)
- **Server-side**: Yes -- Zeek IDS/monitor server-side plugin parses EtherCAT packets passively from network traffic
- **Root cause**: During analysis of a specific EtherCAT packet type, the parser reads past the end of the packet buffer. The parser uses a length or offset field from the EtherCAT datagram header to index into the packet data without verifying that the index stays within the packet boundaries. This allows reading adjacent memory, which may contain sensitive data from previous packets or internal Zeek state.
- **Trigger**: Send an EtherCAT frame (EtherType 0x88A4) with a datagram whose header length/offset fields point past the actual end of the Ethernet frame payload. The Zeek plugin reads past the packet buffer, crashing the Zeek process and potentially leaking memory contents in logged output.
- **PoC**: No public exploit PoC. Fixed in commit [3bca34c](https://github.com/cisagov/icsnpp-ethercat) of cisagov/icsnpp-ethercat.
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-24-051-02](https://www.cisa.gov/news-events/ics-advisories/icsa-24-051-02) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-7242)
- **Analysis**: OOB read is the information-leak sibling of CVE-2023-7243 and CVE-2023-7244. Same fuzzing strategy applies: mutate EtherCAT datagram length fields and frame truncation. The info leak aspect means that even if the write bugs are patched, the read bug can still disclose memory from the Zeek process, which may contain credentials or data from other monitored sessions. All three CVEs were fixed in the same commit, confirming they are closely related code paths in the same parser. Fuzz with: truncated frames (frame shorter than header claims), oversized datagram length fields, and mismatched datagram chain counts.

---

## Key Vulnerability Patterns for Fuzzing

1. **EtherCAT Datagram Length Fields**: The 11-bit length field in each EtherCAT datagram header is the primary attack surface. Three critical CVEs (CVE-2023-7242/7243/7244) in the Zeek parser came from trusting this field. Fuzz by setting length > remaining frame bytes, length = 0, length = 0x7FF (max).
2. **PROFINET CMRPC Sub-Block Parsing**: The P-Net library had 10 memory corruption bugs in its CMRPC RPC handler (CVE-2025-32396 through CVE-2025-32405). Fuzz by mutating length fields in RPC sub-blocks (ExpectedSubmoduleBlockReq, ArVendorBlock, IRInfoBlock, IODataObjectFrameOffset), duplicating blocks, and zeroing required fields.
3. **PROFINET DCP Numeric Fields**: The ResponseDelay field divide-by-zero (CVE-2019-5637) shows that even simple 2-byte integer fields in DCP headers can crash PLCs. Fuzz all numeric fields with 0, 1, max, and boundary values.
4. **TCP Header Data Offset on Embedded Stacks**: The Interniche stack bug (CVE-2022-25622) shows that embedded TCP stacks in PROFINET devices may not validate basic TCP header fields. Fuzz the 4-bit TCP data offset with values below the protocol minimum (5).
5. **Layer 2 Attack Surface**: All industrial Ethernet protocols (PROFINET, EtherCAT) operate at Layer 2 -- no IP firewalling possible. An attacker on the same broadcast domain has full access to inject malformed frames.
6. **IDS/Monitor as Target**: CVE-2023-7242/7243/7244 show that attacking the monitoring tool (Zeek) is viable. Injecting crafted EtherCAT frames on a monitored network can achieve RCE on the security infrastructure itself.
7. **ArVendorBlock Counter Overflow**: Unbounded array index from repeated protocol blocks (CVE-2025-32405). Fuzz by duplicating optional sub-blocks to drive counters past array boundaries.
8. **Zero-Length / Empty Packet Handling**: CVE-2019-5636 shows that a completely empty UDP packet (zero-length) crashes the TwinCAT ADS Discovery handler. Fuzz with empty payloads, zero-length fields, and truncated packets.
