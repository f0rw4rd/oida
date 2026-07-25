# BACnet fuzzer — gap analysis / TODO

Goal: make `src/oida/fuzz/protocols/bacnet.py` a genuinely good BACnet/IP fuzzer.

These gaps were found by benchmarking the current fuzzer against a **live closed
BACnet stack** as ground truth: CODESYS Control for Linux SL 4.21 `libCmpBACnet.so`
(the licensed MBS BACstack "VIN", pre-auth UDP/47808), which has a **known
reproducible pre-auth crash** (empty-bit-string underflow in the WriteGroup
change-list decoder — a single 18-byte datagram SIGSEGVs the server) and known
input-rejection gates. A good BACnet fuzzer must (a) get past those gates and (b)
detect the crash. The current one does neither. Evidence for each gap is cited
inline (`file` refs are in this repo; live-behaviour notes are from replaying the
fuzzer's own packets at the stack).

---

## P0 — blockers (the fuzzer cannot find a real crash today)

### 1. No BACnet crash oracle (no monitor)
- **What:** `MONITOR_REGISTRY` has `modbus, iec104, mms, mqtt, opcua, http, ftp,
  smtp, dns, dhcp, tftp, hl7` but **no `bacnet`** (`src/oida/fuzz/monitors/registry.py`,
  `industrial.py`). `BACnetFuzzer` does not override `DEFAULT_MONITORS`, so it inherits
  `"socket"` (`src/oida/fuzz/core/base_fuzzer.py:131`).
- **Why it matters:** BACnet/IP is connectionless UDP. A `socket` monitor cannot
  distinguish a crashed daemon from a silent one — there is no TCP RST, and a dead
  UDP port still `sendto()`s fine. So when the target actually crashes (verified: the
  stack SIGSEGVs and stops answering), the fuzzer keeps sending and records **nothing**.
  A whole fuzzing run can miss a real, reproducible pre-auth crash.
- **Fix:** add a `BACnetMonitor(ProtocolMonitor)` whose `_check_alive_once()` sends an
  unconfirmed **Who-Is** (or a ReadProperty of the Device object's `object-name`) and
  waits for **I-Am** (or the ReadProperty-ACK). No reply within timeout across N retries
  = target down. Register it as `bacnet` (default port 47808) and set
  `DEFAULT_MONITORS = "bacnet"` (optionally `"bacnet,socket"`) on `BACnetFuzzer`.
  Model it on the existing `ModbusMonitor` / `OpcuaMonitor`.

### 2. Confirmed-service requests are rejected before reaching any decoder (no device addressing)
- **What:** the fuzzer hardcodes `device_instance = 1234` and never discovers the
  target. Confirmed-service requests (ReadProperty, WriteProperty, RPM, etc.) are sent
  with no correct destination address.
- **Why it matters:** the stack's `conf_serv_indication` does a `DB_FindDevice(dmac)`
  first; a request that is not addressed to the local device is answered with a **REJECT
  (reason 9 = missing/inconsistent)** and never reaches the service handler. Verified
  live: WriteProperty test packets came back `N_Unitdata_REJECT reason:9 "destination
  device not found"`. So the entire confirmed-service surface (the richest attack
  surface — WriteProperty/RPM/CreateObject/AtomicFile) is fuzzing a rejection path, not
  the decoders.
- **Fix:** run a **discovery pre-step** (Who-Is → I-Am, or a directed ReadProperty of
  `device,4194303 object-identifier`) to learn the target's device instance + MAC, then
  populate NPDU dest / APDU object-ids from it. Feed the discovered instance into every
  confirmed request instead of the static 1234.

### 3. Malformed/truncated APDUs are grammar-rejected, so "high-crash" tests hit a wall
- **What:** the Phase-2 "high-crash" and length-desync tests (`BACnet_Malformed_APDU`,
  `BACnet_APDU_Truncated`, `BACnet_APDU_Length_Underflow`) work by truncating the APDU
  below its declared length / dropping closing tags (`bacnet.py` ~L1471–1542).
- **Why it matters:** production stacks pre-validate APDU grammar (`TestConfServRequest`
  / `TestUnconfServRequest`) and **REJECT** malformed tag/length framing before the
  service decoder runs. Verified live: every truncated RPM body (`0005050e0c0200`,
  `…1e09` with the closing `1f` missing, `0005050e`) returned `REJECT reason:9` — none
  reached the vulnerable code. Truncation is the wrong primitive for a stack with a
  grammar pre-pass.
- **Fix:** keep truncation (it still catches stacks that skip validation), but treat it
  as a *secondary* strategy. The primary strategy must be gap #4.

---

## P1 — the fuzzer misses the bug class that actually crashes BACnet decoders

### 4. No grammatically-valid-but-semantically-malicious primitive fuzzing (ASN.1 TLV edge cases)
- **What:** the fuzzer sends fixed application/context values and hardcoded object-ids
  (`Object_ID 0x020004D2`, `Property_Value 0x4D`). It never systematically emits **legal
  BACnet primitive encodings with edge-case lengths** across the tag zoo.
- **Why it matters:** the real memory-safety bugs live *behind* the grammar validator and
  fire on inputs that are perfectly legal BACnet but hit an unchecked length/underflow in
  the value decoder. The ground-truth crash is exactly this: a **legal empty bit string**
  (application tag 8, LVT=1, one unused-bits octet — bytes `81 00`) passes validation and
  then underflows a write index (`len-2` → `0xFFFFFFFF`) in the bit-string decoder. The
  current fuzzer never generates an empty bit string, so it cannot find this class at all.
- **Fix:** add a **structure-aware BACnet primitive generator** that, for each primitive
  type (Null, Boolean, Unsigned, Signed, Real, Double, OctetString, CharString, BitString,
  Enumerated, Date, Time, ObjectID), emits the *legal* encodings plus the legal-but-nasty
  edges:
  - zero-length / empty value (LVT=0) and **length-1** value (the bit-string killer),
  - each length just under / at / over the primitive's fixed width (1,2,3,4,5,8-byte
    boundaries — Unsigned/Enumerated decoders often assume `< 5`),
  - LVT=5 **extended length** (next octet, then 2-/4-byte extended) with declared length
    at 0, 1, 253/254/255, 0xFFFF, 0xFFFFFFFF while keeping the datagram self-consistent,
  - context-tag vs application-tag confusion, constructed vs primitive tag class,
  - CharString with each character-set byte (0..255) and a 0-length string,
  - BitString with `unused-bits` 0..255 (only 0..7 legal) at each value length.
  Deliver these as real value blocks inside **correctly-framed** confirmed/unconfirmed
  requests (so they pass the grammar pre-pass), addressed to the discovered device.

### 5. Value edges are not carried into every service that decodes a value
- **What:** the primitive edges (once #4 exists) matter most where a service decodes an
  *attacker-supplied value into a buffer*: WriteProperty, WritePropertyMultiple,
  AddListElement, WriteGroup (unconfirmed — note this one skips the device-address gate),
  ConfirmedCOV/EventNotification parameters, AtomicWriteFile data.
- **Fix:** parameterize the value block so the same primitive-edge corpus is injected into
  each of these carriers, not just a standalone ReadProperty. Prioritise the **unconfirmed
  broadcast** carriers (WriteGroup, COV/Event notification) — they reach the decoders
  without needing device addressing (this is the path the ground-truth crash uses).

---

## P2 — coverage / quality polish

### 6. BVLL length is static except one test
- Only `BACnet_BVLL_Length_Desync` fuzzes the BVLL length. Many stacks trust the UDP
  datagram length over BVLL, but some trust BVLL — make BVLL length a fuzzable field on
  the primary requests too (declared >/</= actual, 0, 0xFFFF), while keeping the datagram
  otherwise valid.

### 7. Static Group packets, not a generative grammar
- The requests are hand-listed `Group` values with shallow structure; real coverage comes
  from boofuzz field-mutating shallow frames. Once #4 exists, drive the primitive
  generator from a small grammar (BVLC → NPDU → APDU → service → value) so structure is
  explored systematically rather than enumerated by hand.

### 8. NPDU network-layer surface is under-fuzzed
- The fuzzer stays at the application layer. The NPDU/network-layer messages
  (control byte bit 0x80 → network-layer message types: Who-Is-Router, I-Am-Router,
  Init-Routing-Table, etc.) and the BVLL foreign-device/BBMD functions (Register-FD,
  Forwarded-NPDU, Distribute-Broadcast) are separate pre-auth decoders worth their own
  request set. (The Forwarded-NPDU length-mismatch class — CVE-2018-10238 — is already
  stubbed; extend to the routing-table messages.)

### 9. No differential/among-stacks corpus replay
- The pcap fixtures in `tests/fixtures/pcap/bacnet/` (cisagov, automayt schedule/RPM) are
  real BACnet exchanges. Seed the fuzzer's corpus from them (extract each APDU as a base
  case, then apply #4's edge mutations) so mutation starts from valid, stack-accepted
  frames instead of hand-written skeletons.

---

## Validation / benchmark (how to know it's fixed)

Use a **known-crashing target as the oracle**:
1. Stand up a BACnet/IP server with a reproducible pre-auth decoder crash (the CODESYS
   `libCmpBACnet` empty-bit-string WriteGroup crash is one; any stack with a known
   value-decoder bug works).
2. **Before:** run the current fuzzer → confirm it neither dispatches confirmed services
   (all REJECT) nor detects the crash (no oracle). This is the failing baseline.
3. **After #1–#4:** the `bacnet` monitor flags the target down within one check interval
   of the crash, and the primitive-edge corpus (empty bit string, etc.) actually reaches
   the decoder and triggers it.
4. Regression: the fuzzer should re-find the crash from a cold start (discovery →
   valid framing → empty-bit-string value in an unconfirmed WriteGroup) with the monitor
   catching the death.

Priority order: **1 (oracle) → 4 (primitive edges) → 2 (addressing) → 3/5 → 6–9.**
Without 1 the fuzzer can't score; without 4 it can't reach the interesting bugs.
