# EtherNet/IP (CIP) — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/ethernetip.py` |
| Boofuzz class | `EtherNetIPFuzzer` (BaseFuzzer) |
| Requests | 11 |
| Mutation depth | 1 fuzzable : 121 explicit `fuzzable=False` : 0 Static (**suspicious**) |
| State machine | None (BaseFuzzer only) |
| Test coverage | Benchmark `(18, 22000, 170)`. tshark dissector validation passes. |

## CVE patterns covered

See `ref/ethernetip/cves/README.md`. EtherNet/IP CVEs cluster around the
CIP encapsulation header, the CIP message router, and CIP object
class-specific parsers:

| CVE pattern | EtherNet/IP fuzzer request | Covered? |
|---|---|---|
| EncapsulationHeader — Length field vs. actual data | `ENIP_Header_Mutation` | ✓ |
| RegisterSession — protocol version + option flags | `ENIP_RegisterSession` | ✓ |
| SendRRData — CPF item count / type ID mismatches | `ENIP_SendRRData` | ✓ |
| ListIdentity reply parsing (CVE-2017-7901 class) | `ENIP_ListIdentity` | ✓ |
| CIP path encoding — class/instance/attribute byte abuse | `CIP_Path_Mutation` | ✓ |
| Connection Manager — Forward_Open with bad parameters | `CIP_Forward_Open` | ✓ |
| Identity Object (class 0x01) attribute fuzzing | covered via `CIP_Path_Mutation` | ✓ |
| Vendor-specific class enumeration | **no dedicated request** | ⚠ partial |

## Known gaps (audit finding)

- **121 explicit `fuzzable=False` annotations** is the highest in the
  fuzzer registry. The audit flagged this as suspicious because such a
  high count usually indicates either (a) someone disabled mutation
  protocol-wide while debugging, or (b) heavy reliance on `Static` /
  `Bytes` framing where `fuzzable=False` is correct.

  **Verdict from spot-check:** mostly correct. The EncapsulationHeader
  fields (Command, Length, SessionHandle, Status, SenderContext, Options)
  are framing — flipping them yields frames the encap layer rejects
  before any CIP parser is exercised. The `fuzzable=False` annotations
  are appropriate for those.

  However a small subset deserves a second look:

  - `CIP_Path_*` segment fields marked `fuzzable=False` — the *path* is
    the attack surface for CVE-2017-7901-class bugs and should be
    mutated, even if the path *length* byte is held static.
  - `Forward_Open.OT_RPI` / `TO_RPI` (RPI = Requested Packet Interval)
    are timer fields; vendors have crashed on `0` and `0xFFFFFFFF`.
    Worth flipping to default fuzzable.

## Optimization recommendations

1. **Re-audit `fuzzable=False` annotations** in `CIP_Path_*` blocks.
   Anything that's a class/instance/attribute *value* (vs. a path-length
   header byte) should be fuzzable. Estimated ~30 lines flipped.
2. **Add `CIP_Class_Enumeration` request.** `Group("ClassID", values=[0x01,
   0x02, 0x04, 0x06, 0xF4, 0xF5, 0xF6, 0xAC, 0x100..0x110])` — covers
   well-known CIP classes plus vendor-reserved range. The scanner side
   already enumerates these; mirroring in the fuzzer catches parser
   bugs.
3. **Forward_Open parameter fuzzing.** OT_RPI and TO_RPI extreme values
   (0, 1, 0xFFFFFFFF), Connection_Type flags, transport class.

The audit also notes EtherNet/IP cleared the tshark dissector
validation — a good sanity check that the frames are at least
well-formed enough to dissect.
