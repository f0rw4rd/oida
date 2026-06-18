# CoAP Attack Research

Consolidated from IETF drafts, NETSCOUT ASERT, and Payatu research.

## Sources

- [IETF Draft: Attacks on CoAP](https://core-wg.github.io/attacks-on-coap/draft-ietf-core-attacks-on-coap.html) (draft-ietf-core-attacks-on-coap-06)
- [IETF Draft: Amplification Attacks Using CoAP](https://www.ietf.org/archive/id/draft-mattsson-t2trg-amplification-attacks-01.html)
- [NETSCOUT ASERT: CoAP Attacks in the Wild](https://www.netscout.com/blog/asert/coap-attacks-wild) (Jan 2019)
- [AMP-Research: Port 5683 CoAP](https://github.com/Phenomite/AMP-Research/blob/master/Port%205683%20-%20CoAP/README.md)
- [Shadowserver: Accessible CoAP Report](https://www.shadowserver.org/news/accessible-coap-report-scanning-for-exposed-constrained-application-protocol-services/)
- [Payatu: IoT Security Part 11 - CoAP Protocol and Security](https://payatu.com/masterclass/iot-security-part-11-introduction-to-coap-protocol-and-security/)

---

## 1. Protocol-Level Attacks (IETF draft-ietf-core-attacks-on-coap-06)

### 1.1 Selective Blocking

- **Attacker position**: On-path (MITM)
- **Mechanism**: Drops chosen requests or responses while forwarding others. Encryption (DTLS/TLS/OSCORE) makes this harder but not impossible -- IP addresses, ports, and message lengths remain visible.
- **Impact**: Client loses actuator state synchronization. Cannot determine if command was executed (Schrodinger's cat problem).
- **Mitigation**: Use confirmable (CON) messages. Client must handle missing responses appropriately with timeouts and retries.

### 1.2 Request Delay

- **Attacker position**: On-path
- **Mechanism**: Stores a request and forwards it after a chosen delay. Server processes delayed request without awareness of the postponement.
- **Replay window**: DTLS default 64 packets, OSCORE default 32 packets. Delayed request must arrive within this window to be accepted.
- **Attack scenario**: "Unlock" request delayed until after client has re-locked the door. Server processes stale unlock at attacker's chosen time.
- **Variant**: Attacker delays original request, forwards retransmissions, then injects original after client state changes.
- **Mitigation**: Echo option (RFC 9175) -- server verifies request freshness. Alternative: application-specific challenge-response or timestamp mechanisms.

### 1.3 Response Delay and Mismatch

- **Scope**: Affects DTLS and TLS. Does NOT affect OSCORE (which binds responses to requests).
- **Mechanism**: Attacker delays a response until client reuses the same token for a different request. Client misattributes the delayed response to the new request.
- **Prerequisites**: Unpatched CoAP implementation with predictable token reuse. For UDP, response must arrive within replay window.
- **Attack variants**:
  - Mismatched PUT responses: "unlock" confirmation accepted as "lock" confirmation
  - Mismatched GET responses: false sensor readings
  - Cross-resource: mixing responses from different URI paths
- **Mitigation**: RFC 9175 Section 4.2 updates client token processing. Patched implementations completely mitigate this.

### 1.4 Request Fragment Rearrangement

- **Scope**: Affects block-wise transfers (RFC 7959). Q-Block (RFC 9177) already mitigated.
- **Two sub-attacks**:

**4a. Earlier Final Block Completion**:
- Attacker substitutes the final block of one operation with a final block from a different operation.
- Server completes an unintended composite action.
- Requires operations within the same replay window.

**4b. Withheld First Block Injection**:
- Attacker stores the initial block of one request, later injects it into a different operation.
- Server primed for altered processing path.

- **Prerequisites**: On-path position, multiple sequential block-wise operations, ability to distinguish blocks by timing or size.
- **Mitigation**: Request-Tag option (RFC 9175) labels fragments to prevent mixing.

### 1.5 Relay Attack

- **Mechanism**: CoAP messages relayed out-of-band using alternate radio technology to falsely establish proximity.
- **Attack scenario**: Car key proximity system -- attacker relays challenge/response over distance, unlocking vehicle remotely.
- **Mitigation**: RTT distance bounds (speed of light), short-range radio (NFC: cm vs m), GPS coordinates (guard against GNSS spoofing).

---

## 2. Amplification/DDoS Attacks

### 2.1 Simple Amplification

- **Vector**: Single GET request to `/.well-known/core` on UDP port 5683
- **Average amplification factor**: **34x** (range 20-34x depending on implementation)
- **Request size**: 13-21 bytes
- **Response size**: 450-991 bytes
- **Scan payload** (hex, Californium CoAP): `44010f3cd19796c1c13cff0000`
- **Response fingerprints**: ASCII strings `CoAP RFC 7252` or `/.well-known/core`
- **Attacker can increase factor**: By creating/updating resources to enlarge `/.well-known/core` response

### 2.2 Observe-Based Amplification

- **Mechanism**: Single Observe registration triggers multiple notification responses
- **Amplification factor**: `c * n` (response_size * notification_count)
- **Techniques to increase factor**:
  - Register same client multiple times with different Tokens or ports
  - Use conditional attributes (pmax) to increase notification frequency
  - Predictable confirmable Message IDs may be spoofable

### 2.3 Multicast/Group Amplification

- **Mechanism**: Single multicast request elicits responses from `m` different servers
- **Amplification factor**: `c * m` (response_size * server_count)
- **Combined with Observe**: `c * n * m` (size * notifications * servers)
- **Key issue**: Servers cannot determine `m` beforehand, making rate limiting ineffective

### 2.4 MITM Amplification

- **Mechanism**: DTLS with Connection ID and OSCORE permit address updates without robust validation
- **Attack**: Redirect Observe notifications from legitimate client to victim by spoofing address update
- **Duration**: Flood continues until ACK requirements trigger timeout

### 2.5 Real-World Attack Data (NETSCOUT, January 2019)

- First observed CoAP DDoS attacks: mid-January 2019
- Primary targets: mobile infrastructure in China
- Average attack duration: ~90 seconds
- Attack rate: ~100 packets-per-second generated by attacker
- Vast majority of reflectors: IoT devices on wireless broadband carriers
- Internet-accessible CoAP devices: ~388,000 (Shadowserver, 2019)
- Geographic concentration: predominantly China

### 2.6 Amplification Mitigations

- **Address validation**: Echo option (RFC 9175) or security protocol handshake
- **Avoid NoSec mode**: All amplification attacks require IP spoofing, which NoSec permits
- **QUIC best practice**: "Limit data sent to unvalidated address to 3x data received"
- **Rate limiting**: Per-source IP response throttling
- **Multicast limitation**: Inherently resistant to address validation (unknown responder count)

---

## 3. Scanner/Fuzzer Target Matrix

Based on all sources, priority targets for a CoAP security assessment tool:

### Critical (no auth required, direct parsing)

| Target | What to Test | CVE Examples |
|--------|-------------|--------------|
| `/.well-known/core` | Response size ratio for amplification factor measurement | n/a |
| Option delta/length | Overflow in delta accumulation, truncated extended fields | CVE-2020-10063, CVE-2019-17212, CVE-2020-12887 |
| Token Length (TKL) | Reserved values 9-15, TKL vs packet size mismatch | CVE-2020-12886 |
| Repeatable options | Unchecked loop iteration on Uri-Path, ETag multiples | CVE-2020-12884, CVE-2024-32017 |
| Zero-length options | Zero-sized heap allocations from computed length | CVE-2020-12885 |
| Payload marker (0xFF) | Without data, multiple markers, options after marker | CVE-2018-12679 |
| URI path traversal | `/../` segments in Uri-Path options | CVE-2025-34468 |

### High (specific message flows)

| Target | What to Test | CVE Examples |
|--------|-------------|--------------|
| NoSec mode detection | Responses without DTLS = all attacks trivially exploitable | n/a |
| Block-wise transfers | Fragment rearrangement, mismatched Block1/Block2 | n/a |
| Observe registration | Multiple registrations, notification flooding | n/a |
| Proxy-Uri | Arbitrary target URLs (SSRF-like) | CVE-2024-32017 |
| Large payloads | Oversized CoRE Link Format, PDU size overflow | CVE-2024-31031, CVE-2024-31225 |
| Uri-Host overflow | Oversized hostname in Uri-Host option | CVE-2025-34468 |

### Medium (state/timing dependent)

| Target | What to Test | CVE Examples |
|--------|-------------|--------------|
| Token reuse patterns | Predictability for response mismatch attacks | n/a |
| Multicast group membership | Count of responders for amplification measurement | n/a |
| DTLS cipher suite | Weak/export ciphers, missing FALLBACK_SCSV | CVE-2022-39368 |
| Concurrent connections | Thread-safe context exhaustion | CVE-2023-51847 |

---

## 4. Security Properties Beyond CIA

The IETF draft emphasizes that traditional security (confidentiality, authentication, integrity, replay protection) is insufficient for CoAP. Secure operation requires:

| Property | Description |
|----------|-------------|
| **Availability** | Service must function when needed (selective blocking defeats this) |
| **Data-to-data binding** | Responses bound to requests; fragments bound together (mismatch/rearrangement defeats this) |
| **Data-to-space binding** | Geographic proximity verification (relay attack defeats this) |
| **Data-to-time binding** | Freshness and temporal validity (delay attack defeats this) |
