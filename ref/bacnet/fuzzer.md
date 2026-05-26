# BACnet — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/bacnet.py` |
| Boofuzz class | `BACnetFuzzer` (BaseFuzzer) |
| Requests | 13 |
| Mutation depth | 0 fuzzable : 0 Static (boofuzz default behavior throughout) |
| State machine | None (BaseFuzzer only) |
| Test coverage | Benchmark `(20, 28000, 240)`. |

## CVE patterns covered

See `ref/bacnet/cves/README.md`. BACnet/IP CVEs cluster around the BVLL
encapsulation, NPDU routing, and APDU service handling:

| CVE pattern | BACnet fuzzer request | Covered? |
|---|---|---|
| BVLL function type out-of-range | `BACnet_BVLL_Function` | ✓ |
| NPDU Network Layer Protocol Control Information (NPCI) abuse | `BACnet_NPDU_Mutation` | ✓ |
| APDU service-choice enumeration | `BACnet_APDU_Service` | ✓ |
| ReadProperty / ReadPropertyMultiple — object identifier mutations | `BACnet_ReadProperty` | ✓ |
| WriteProperty — property-identifier mismatches | `BACnet_WriteProperty` | ✓ |
| BBMD (BACnet Broadcast Management Device) FDT entry parsing | `BACnet_BBMD_FDT` | ✓ |
| Foreign Device Registration | `BACnet_FDR` | ✓ |
| Who-Is / I-Am broadcast handling | `BACnet_WhoIs`, `BACnet_IAm` | ✓ |
| BACnet/SC (Secure Connect) cert / WebSocket | **not covered** — separate transport | ✗ |

## Audit observation: opaque mutation profile

This fuzzer has **zero explicit `fuzzable=True` or `fuzzable=False`
annotations** across all 13 requests. Mutation happens via boofuzz
defaults — most `String`, `Word`, `DWord` primitives default to
`fuzzable=True`; `Static` defaults to non-fuzzable.

The audit called this "opaque mutation profile" because a reviewer
cannot tell *which fields are intended to be mutated* without
instantiating the protocol tree and counting. It works, but the next
contributor changing a `Word` to a `Static` to fix a framing issue may
unintentionally remove a fuzz site they didn't know existed.

**This is a documentation problem, not a runtime problem.** No fix
recommended for 1.0. If revisited, add explicit `fuzzable=` annotations
to every primitive matching current default behavior — that's a
mechanical pass, not a logic change.

## Optimization recommendations

1. **Document the BACnet attack surface** in this file (done above).
2. **Add BACnet/SC** (Secure Connect, ANSI/ASHRAE 135-2020) as a
   separate fuzzer module — it's WebSocket-based, transport-distinct
   from BACnet/IP. Requires bacpypes3 BACnet/SC support; not present
   in 1.0.
3. **Foreign-device registration sweep.** The FDR table is a common
   misconfiguration target. A `Group()` of registration-period values
   (0, 1, 65535) on `BACnet_FDR` would catch off-by-one parsers.
