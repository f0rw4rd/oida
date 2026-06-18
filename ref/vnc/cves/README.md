# VNC / RFB - Notable CVEs

## Server-Side Parsing Bugs (fuzzer-discoverable)

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2017-18922 | LibVNCServer (< 0.9.12) | Heap overflow in WebSocket frame decoding (websockets.c) | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-18922) |
| CVE-2018-6307 | LibVNCServer (< 0.9.12) | Use-after-free in file transfer extension server code | UAF / RCE | 8.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-6307) |
| CVE-2018-7225 | LibVNCServer (<= 0.9.11) | Unsanitized msg.cct.length in rfbProcessClientNormalMessage -> integer overflow, uninitialized memory | Integer Overflow / Info Disclosure | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-7225) |
| CVE-2018-15127 | LibVNCServer (< 0.9.12) | Heap OOB write in rfbProcessFileTransferReadBuffer via uint32 length overflow | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-15127) |
| CVE-2019-15681 | LibVNCServer (< 0.9.13) | Uninitialized rfbServerCutTextMsg struct leaks stack memory to remote | Info Disclosure | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-15681) |
| CVE-2020-14397 | LibVNCServer (< 0.9.13) | NULL pointer dereference in libvncserver/rfbregion.c | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14397) |
| CVE-2020-25708 | LibVNCServer 0.9.12 | Divide-by-zero in rfbSendRectEncodingRaw when client sends width=0 | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-25708) |
| CVE-2022-46340 | X.Org Server (VNC module) | Stack buffer overflow in XTestSwapFakeInput via GenericEvents > 32 bytes | Stack Overflow / RCE | 8.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-46340) |

## Client-Side Parsing Bugs (malicious VNC server -> crash in viewer/client)

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2018-20020 | LibVNCClient | Heap buffer overflow in HandleRFBServerMessage | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-20020) |
| CVE-2019-20839 | LibVNCClient (< 0.9.13) | Buffer overflow in ConnectClientToUnixSock via long socket filename | Buffer Overflow | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-20839) |
| CVE-2020-14398 | LibVNCClient (< 0.9.13) | Improperly closed TCP connection causes infinite loop in libvncclient/sockets.c | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14398) |
| CVE-2020-14405 | LibVNCClient (< 0.9.13) | TextChat size not limited, uncontrolled memory allocation | DoS | 6.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14405) |
| CVE-2022-23967 | TightVNC 1.3.10 (client) | Integer signedness error in InitialiseRFBConnection -> heap overflow via -1 malloc size | Heap Overflow / RCE | 10.0 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-23967) |
| CVE-2019-15680 | TightVNC 1.3.10 (client) | Heap buffer overflow in HandleCoRREBBP macro | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-15680) |
| CVE-2019-8287 | TightVNC 1.3.10 (client) | Heap buffer overflow in ServerCutText handler | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-8287) |
| CVE-2019-15678 | TightVNC 1.3.10 (client) | Heap buffer overflow in InitialiseRFBConnection (rfbproto.c) | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-15678) |
| CVE-2019-15679 | TigerVNC (< 1.10.1, client) | Stack buffer overflow in CMsgReader::readSetCursor | Stack Overflow / RCE | 9.8 | [Ubuntu Advisory](https://ubuntu.com/security/notices/USN-5965-1) |
| CVE-2019-15694 | TigerVNC (< 1.10.1, client) | Heap buffer overflow in DecodeManager::decodeRect, signedness error | Heap Overflow / RCE | 7.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-15694) |
| CVE-2020-14400 | LibVNCServer (< 0.9.13) | Pointer aliasing/alignment issues in libvncserver | Memory Corruption | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14400) |

## Gateway/Proxy Parsing Bugs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-43826 | Apache Guacamole (< 1.5.4) | Integer overflow in guacd VNC FramebufferUpdate handling -> heap buffer wild copy | Integer Overflow / RCE | 8.0 | [elttam writeup](https://github.com/elttam/publications/blob/master/writeups/CVE-2023-43826.md) |

---

## Detailed Writeups -- Server-Side Parsing Bugs

### CVE-2017-18922
- **Product**: LibVNCServer < 0.9.12
- **Type**: Heap Overflow / RCE
- **CVSS**: 9.8 (NVD v3.1)
- **Server-side**: Yes -- the LibVNCServer WebSocket handler parses incoming WebSocket frames from clients connecting over ws:// or wss://
- **Root cause**: The WebSocket Hybi frame decoder in `websockets.c` assumed one `ws_read()` call corresponded to exactly one complete WebSocket frame. When frames were fragmented across reads or multiple frames arrived in a single read, the decoder wrote past the end of its heap-allocated decode buffer. An attacker-controlled frame length was not validated against the buffer size before memcpy.
- **Trigger**: Connect to the VNC server over WebSocket (ws://host:5900). Send a crafted WebSocket Hybi frame with a payload length exceeding the internal decode buffer size. The server's `webSocketsDecodeHybi()` function copies the payload without bounds checking, overwriting adjacent heap data including a function pointer.
- **PoC**: No standalone public PoC. The fix commit shows the vulnerable code path: [LibVNC/libvncserver@aac95a9](https://github.com/LibVNC/libvncserver/commit/aac95a9dcf4bbba87b76c72706c3221a842ca433)
- **Metasploit**: N/A
- **Advisory**: [Red Hat RHSA-2020:3456](https://access.redhat.com/errata/RHSA-2020:3456), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-18922)
- **Analysis**: The WebSocket layer sits before any VNC authentication, making this a pre-auth RCE. A fuzzer sending randomized WebSocket frames with varying payload lengths would find this quickly. The key mutation is: take a valid WebSocket Hybi frame header, set the payload length field to a value larger than the server's internal decode buffer (~4096 bytes), then supply that many bytes. Fragmentation fuzzing (splitting one logical frame across multiple TCP segments) is also effective since the original bug involved incorrect reassembly.

### CVE-2018-7225
- **Product**: LibVNCServer <= 0.9.11
- **Type**: Integer Overflow / Info Disclosure
- **CVSS**: 9.8 (NVD v3.0)
- **Server-side**: Yes -- the server parses `rfbClientCutText` messages sent by VNC clients
- **Root cause**: `rfbProcessClientNormalMessage()` in `rfbserver.c` reads `msg.cct.length` (a 4-byte uint32 field from the client) and uses it to `malloc(msg.cct.length + sz_rfbClientCutTextMsg)`. When `msg.cct.length` is close to `SIZE_MAX` or `INT_MAX`, the addition overflows, causing `malloc()` to allocate a tiny buffer. The subsequent `rfbReadExact()` reads `msg.cct.length` bytes into this undersized buffer, causing a heap overflow. Even without overflow, the unsanitized length allows the server to allocate up to 2 GB of memory from a single client message (DoS), or to read and potentially leak uninitialized heap memory.
- **Trigger**: After completing the VNC handshake, send an `rfbClientCutText` message (type 6) with the 4-byte length field set to `0xFFFFFFFF` or any value near `SIZE_MAX - sz_rfbClientCutTextMsg`. The server calls `malloc(length + overhead)` which overflows to a small value, then attempts to read `length` bytes into the undersized buffer.
- **PoC**: No standalone public PoC. The fix constrains client cut text length to 1 MB: [LibVNC Issue #218](https://github.com/LibVNC/libvncserver/issues/218)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-7225), [SUSE CVE-2018-7225](https://www.suse.com/security/cve/CVE-2018-7225.html)
- **Analysis**: Classic integer overflow in a length field. A byte-level fuzzer mutating the 4-byte length field of `rfbClientCutText` messages would find this trivially. Effective mutations: set length to `0xFFFFFFFF`, `0x7FFFFFFF`, `0x80000000`, or values that cause `length + N` to wrap around on 32-bit or 64-bit platforms. This pattern recurs across VNC implementations -- the `rfbClientCutTextMsg` structure is documented in the RFB spec and every implementation must parse it.

### CVE-2018-15127
- **Product**: LibVNCServer < 0.9.12 (with file transfer extension enabled)
- **Type**: Heap Overflow / RCE
- **CVSS**: 9.8 (NVD v3.0)
- **Server-side**: Yes -- the server parses file transfer extension messages from authenticated clients
- **Root cause**: `rfbProcessFileTransferReadBuffer()` in `rfbserver.c` takes a `uint32_t length` parameter directly from the client message. It calls `malloc((uint64_t)length + 1)` to allocate the receive buffer, then null-terminates with `buffer[length] = 0`. When `length = 0xFFFFFFFF` (UINT32_MAX), `length + 1` overflows to 0 on 32-bit platforms, causing `malloc(0)` to return a 16-byte heap chunk. The function then passes this tiny buffer and the original large `length` to `rfbReadExact()`, which writes up to 4 GB into 16 bytes of heap. The original fix cast to `uint64_t` but this was incomplete on 32-bit systems where `size_t` is 32 bits; a follow-up commit added an explicit `length == SIZE_MAX` check.
- **Trigger**: Enable the TightVNC file transfer extension on the server (not default). After authentication, send a file transfer request message with the length field set to `0xFFFFFFFF`. The server allocates a 0-byte (or 16-byte) buffer and attempts to read 4 GB into it.
- **PoC**: No standalone exploit PoC. Fix commits: [LibVNC/libvncserver@15bb719](https://github.com/LibVNC/libvncserver/commit/15bb719c03cc70f14c36a843dcb16ed69b405707), [LibVNC/libvncserver@09e8fc0](https://github.com/LibVNC/libvncserver/commit/09e8fc02f59f16e2583b34fe1a270c238bd9ffec). Ixia BreakingPoint has a test strike: [Ixia CVE-2018-15127](https://support.ixiacom.com/strikes/exploits/vnc/cve_2018_15127_libvnc_file_transfer_heap_overflow.xml)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-15127), [LibVNC Issue #243](https://github.com/LibVNC/libvncserver/issues/243)
- **Analysis**: Textbook uint32 overflow leading to undersized allocation. The file transfer extension adds its own message types beyond standard RFB, each with length-prefixed payloads. A fuzzer should enumerate all file transfer sub-commands and mutate their length fields to boundary values (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF). The incomplete initial fix demonstrates why platform-dependent size types (size_t vs uint32_t vs uint64_t) need separate test cases for 32-bit and 64-bit builds.

### CVE-2018-6307
- **Product**: LibVNCServer < 0.9.12 (with file transfer extension enabled)
- **Type**: Use-After-Free / RCE
- **CVSS**: 8.1 (NVD v3.0)
- **Server-side**: Yes -- the server parses Tight file transfer extension messages
- **Root cause**: Heap use-after-free in the server-side file transfer extension code. When processing a sequence of file transfer requests, a heap object is freed but a dangling pointer to it remains. A subsequent file transfer message dereferences the freed pointer, allowing an attacker to control execution flow if the freed region has been reallocated with attacker-controlled data.
- **Trigger**: Enable the TightVNC file transfer extension on the server. After authentication, send a specific sequence of file transfer protocol messages that causes the server to free a file transfer context structure, then send another message that references the freed context. The exact sequence involves initiating and aborting file transfers in a specific order.
- **PoC**: No public PoC. Fix commit: [LibVNC/libvncserver@ca2a5ac](https://github.com/LibVNC/libvncserver/commit/ca2a5ac02fbbadd0a21fabba779c1ea69173d10b)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-6307), [Kaspersky ICS-CERT KLCERT-18-026](https://ics-cert.kaspersky.com/vulnerabilities/klcert-18-026-libvnc-heap-use-after-free/), [FortiGuard IPS 47362](https://www.fortiguard.com/encyclopedia/ips/47362)
- **Analysis**: Use-after-free bugs require stateful fuzzing -- a simple single-message mutator will not find this. The fuzzer must send sequences of file transfer messages (open, read, write, close, abort) in randomized orders, with randomized timing. State machine fuzzing with message reordering, duplication, and deletion is the right approach. The file transfer extension's state machine has transitions that were not properly validated, leading to the dangling pointer.

### CVE-2019-15681
- **Product**: LibVNCServer < 0.9.13
- **Type**: Info Disclosure (stack memory leak)
- **CVSS**: 7.5 (NVD v3.1)
- **Server-side**: Yes -- the server sends an `rfbServerCutTextMsg` structure to clients with uninitialized padding bytes
- **Root cause**: In `rfbserver.c`, the `rfbServerCutTextMsg sct` structure is declared on the stack but not zeroed before use. The structure contains padding fields (`pad1`, `pad2`) that are never explicitly assigned. When the server sends this structure over the network, the uninitialized padding bytes leak whatever data was previously on the stack at those memory locations. Combined with other bugs, this can be used to defeat ASLR.
- **Trigger**: Connect to the VNC server and complete the handshake. When the server sends a `ServerCutText` message (triggered by clipboard activity on the server side or by certain server events), the padding bytes in the message structure contain leaked stack memory. A client can passively capture these messages to harvest stack data.
- **PoC**: No public PoC. Fix commit: [LibVNC/libvncserver@d01e1bb](https://github.com/LibVNC/libvncserver/commit/d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-15681), [Kaspersky ICS-CERT VNC Research](https://ics-cert.kaspersky.com/publications/reports/2019/11/22/vnc-vulnerability-research/)
- **Analysis**: This is an information disclosure from the server rather than a crash, but it directly assists exploitation of other memory corruption bugs by leaking stack layout information. A fuzzer with response validation (checking that padding/reserved bytes are zero) would flag this. The fix is a single `memset((char *)&sct, 0, sizeof(sct))` before the structure is populated and sent. This bug class affects any RFB structure with padding fields -- the spec defines `pad1` and `pad2` in several message types, and implementations frequently forget to zero them.

### CVE-2020-14397
- **Product**: LibVNCServer < 0.9.13
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 7.5 (NVD v3.1)
- **Server-side**: Yes -- the server crashes when processing client messages that trigger region operations with NULL pointers
- **Root cause**: Missing NULL pointer checks in `libvncserver/rfbregion.c`. Certain code paths in the server's region handling can reach functions in `rfbregion.c` with NULL region pointers, causing a segfault. The NULL condition arises when client messages cause the server to compute framebuffer update regions under specific error or edge-case conditions.
- **Trigger**: Connect to the VNC server and send client messages that exercise the region computation code paths in ways that produce NULL region pointers. Specific crafted `FramebufferUpdateRequest` messages with edge-case coordinates (e.g., zero-width or zero-height regions, regions extending beyond the framebuffer) can trigger the NULL dereference.
- **PoC**: No public PoC. Fix commit: [LibVNC/libvncserver@38e98ee](https://github.com/LibVNC/libvncserver/commit/38e98ee61d74f5f5ab4aa4c77146faad1962d6d0)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14397), [Kaspersky ICS-CERT KLCERT-18-034](https://ics-cert.kaspersky.com/vulnerabilities/klcert-18-034-libvnc-null-pointer-dereference/)
- **Analysis**: NULL deref bugs in VNC servers are reliably found by fuzzing `FramebufferUpdateRequest` messages with boundary values for x, y, width, and height fields. Key mutations: set width or height to 0, set coordinates that extend past the framebuffer dimensions, use maximum uint16 values (0xFFFF). The region computation code must handle all combinations of valid and invalid rectangle coordinates without crashing.

### CVE-2020-25708
- **Product**: LibVNCServer 0.9.12
- **Type**: Divide-by-Zero / DoS
- **CVSS**: 7.5 (NVD v3.1)
- **Server-side**: Yes -- the server crashes when a client requests a framebuffer update with zero-width rectangles
- **Root cause**: In `rfbSendRectEncodingRaw()` in `rfbserver.c`, the variable `bytesPerLine` is calculated as `w * (cl->format.bitsPerPixel / 8)`. When `w` (width) is 0, `bytesPerLine` is 0. At line 3391, the code computes `nlines = (UPDATE_BUF_SIZE - cl->ublen) / bytesPerLine`, which is a divide-by-zero causing a SIGFPE (floating point exception) that crashes the server.
- **Trigger**: Connect to the VNC server, complete the handshake. Send a `FramebufferUpdateRequest` (message type 3) with `width` set to 0. When the server processes this request using the Raw encoding, it divides by zero and crashes with "Floating point exception (core dumped)". The specific 24-byte payload that triggers this is documented in the bug report.
- **PoC**: PoC included in the bug report with a Python script that sends a 24-byte crafted payload: [LibVNC Issue #409](https://github.com/LibVNC/libvncserver/issues/409). The payload bytes: `0x52 0x46 0x42 0x20 0x30 0x30 0x33 0x2e 0x30 0x30 0x38 0x0a 0x01 0x01 0x03 0x10 0x00 0xff 0x00 0x00 0x00 0x00 0x80 0x00`
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-25708), [Red Hat Bugzilla 1896739](https://bugzilla.redhat.com/show_bug.cgi?id=1896739)
- **Analysis**: Trivially found by any fuzzer that mutates the width/height fields in `FramebufferUpdateRequest` or `SetPixelFormat` messages to zero. The fix is a 3-line early return: `if(!h || !w) return TRUE;`. Zero-dimension testing should be part of any VNC fuzzing harness. This is a pre-auth DoS on servers that accept unauthenticated connections (security type "None"), which is common in ICS environments.

### CVE-2022-46340
- **Product**: X.Org Server (including TigerVNC server which embeds X.Org)
- **Type**: Stack Buffer Overflow / RCE
- **CVSS**: 8.8 (NVD v3.1)
- **Server-side**: Yes -- the X server (which provides VNC server functionality via the VNC module) parses XTest extension requests from clients
- **Root cause**: The swap handler `XTestSwapFakeInput` in the XTest extension uses a fixed 32-byte stack buffer for byte-swapping incoming requests. When a client sends a `GenericEvent` through `XTestFakeInput` with a length greater than 32 bytes, the swap handler writes past the end of the stack buffer. The handler did not validate that the event length matched the expected 32-byte XTest event size before performing the byte-swap copy.
- **Trigger**: Connect to the X server (e.g., via VNC or SSH X forwarding). Send an `XTestFakeInput` request containing a `GenericEvent` with `length > 32` bytes. The server's byte-swap handler copies the oversized event onto a 32-byte stack buffer, corrupting the return address and enabling RCE. Note: this only triggers when client and server have different byte orders (the swap handler is only invoked for byte-order mismatches).
- **PoC**: No public PoC. ZDI tracking: ZDI-CAN-19265. Fix: xorg-server 21.1.5 and xwayland 22.1.6
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-46340), [X.Org Security Advisory](https://www.x.org/wiki/Development/Security/), [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2022-46340)
- **Analysis**: This affects TigerVNC servers because TigerVNC embeds the X.Org server. Fuzzing approach: target the XTest extension's `FakeInput` request handler, specifically sending GenericEvent types with lengths from 33 to 256+ bytes. The byte-swap requirement means the fuzzer must connect with the opposite endianness from the server. Stack buffer overflows in byte-swap handlers are a recurring pattern in X11 protocol code because swap handlers are often written as simple memcpy-like loops without length checks.

---

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2020-25708 | Python PoC (24-byte payload) for LibVNCServer divide-by-zero DoS | [LibVNC Issue #409](https://github.com/LibVNC/libvncserver/issues/409) |
| CVE-2022-23967 | Python PoC for TightVNC client heap overflow via crafted server | [github.com/MaherAzzouzi/CVE-2022-23967](https://github.com/MaherAzzouzi/CVE-2022-23967) |
| CVE-2023-43826 | Detailed writeup of Apache Guacamole VNC integer overflow by elttam | [github.com/elttam/publications](https://github.com/elttam/publications/blob/master/writeups/CVE-2023-43826.md) |
| CVE-2018-15127 | Ixia BreakingPoint test strike for LibVNCServer file transfer heap overflow | [Ixia Strike DB](https://support.ixiacom.com/strikes/exploits/vnc/cve_2018_15127_libvnc_file_transfer_heap_overflow.xml) |
| VMware VNC | Cisco Talos Vulnerability Spotlight: VNC vulnerabilities in VMware found via Mutiny fuzzer | [Talos Intelligence](https://blog.talosintelligence.com/vulnerability-spotlight-vmware-vnc/) |
| Kaspersky ICS-CERT | Comprehensive VNC vulnerability research report (37 CVEs across LibVNC, TightVNC, TurboVNC, UltraVNC) | [Kaspersky ICS-CERT Report](https://ics-cert.kaspersky.com/publications/reports/2019/11/22/vnc-vulnerability-research/) |
| Kaspersky PDF | Full technical paper with code-level analysis of VNC parsing bugs | [KASPERSKY_ICS_CERT_VNC_VULN_EN.pdf](https://ics-cert.kaspersky.com/media/KASPERSKY_ICS_CERT_VNC_VULN_EN.pdf) |
| General | Metasploit module for VNC keyboard-based code execution | [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/multi/vnc/vnc_keyboard_exec/) |

## Key Vulnerability Patterns for Fuzzing

1. **FramebufferUpdateRequest width/height**: Zero values cause divide-by-zero (CVE-2020-25708). Boundary values trigger NULL derefs in region handling (CVE-2020-14397). These are pre-auth on servers with security type None.
2. **rfbClientCutText length field**: The 4-byte length field is the single most dangerous field in the RFB protocol. Values near INT_MAX/SIZE_MAX cause integer overflows in `malloc(length + N)` (CVE-2018-7225). Every VNC implementation must parse this.
3. **File transfer extension messages**: The TightVNC file transfer extension adds complex server-side state management. Integer overflows in length fields (CVE-2018-15127) and use-after-free from message reordering (CVE-2018-6307) are both present. Requires the extension to be enabled.
4. **WebSocket frame decoding**: The WebSocket transport layer (used by noVNC web clients) adds a pre-auth attack surface before any RFB parsing occurs. Frame reassembly bugs cause heap overflows (CVE-2017-18922).
5. **Encoding types**: Requesting unknown encoding types, encoding-specific sub-rect parsing in Tight, ZRLE, Hextile, CoRRE encoders.
6. **SetPixelFormat**: Invalid pixel format combinations (bits/depth/color values) can cause unexpected calculation results in encoding handlers.
7. **Structure padding/reserved bytes**: RFB message structures contain padding fields that implementations may not zero, leaking stack memory (CVE-2019-15681).
8. **XTest extension (X.Org/TigerVNC)**: GenericEvent handling in byte-swap handlers has fixed-size stack buffers (CVE-2022-46340).
9. **Handshake state machine**: Out-of-order messages during the ProtocolVersion/SecurityType/ClientInit/ServerInit sequence.
